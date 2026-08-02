//go:build linux
// +build linux

//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package sctp

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"
)

//go:uintptrescapes
func setsockopt(fd int, optname, optval, optlen uintptr) (uintptr, uintptr, error) {
	return rawSetsockopt(fd, SOL_SCTP, optname, optval, optlen)
}

//go:uintptrescapes
func getsockoptRaw(fd int, optname, optval, optlen uintptr) (uintptr, uintptr, error) {
	return rawGetsockopt(fd, SOL_SCTP, optname, optval, optlen)
}

// getsockopt gives the kernel the address of an actual socklen_t. Linux defines
// socklen_t as a 32-bit value on every supported architecture. Using uintptr as
// the backing storage worked accidentally on little-endian 64-bit machines,
// but a big-endian kernel read the leading zero half and rejected every option.
//
//go:uintptrescapes
func getsockopt(fd int, optname, optval uintptr, optlen *uint32) (uintptr, uintptr, error) {
	return getsockoptRaw(fd, optname, optval, uintptr(unsafe.Pointer(optlen)))
}

// setInitOpts sets the association initialisation parameters carried in INIT
// and INIT ACK chunks (RFC 9260 §5.1; RFC 6458 §8.1.2).
func setInitOpts(fd int, options InitMsg) error {
	optlen := uint32(unsafe.Sizeof(options))
	_, _, err := setsockopt(fd, SCTP_INITMSG,
		uintptr(unsafe.Pointer(&options)), uintptr(optlen))
	return err
}

// setsockoptInt sets one of the integer boolean SCTP options defined by the
// sockets API (RFC 6458 §8.1).
func setsockoptInt(fd int, optname uintptr, on bool) error {
	var val int32
	if on {
		val = 1
	}
	_, _, err := setsockopt(fd, optname, uintptr(unsafe.Pointer(&val)),
		unsafe.Sizeof(val))
	return err
}

func setsockoptInt32(fd int, optname uintptr, val int32) error {
	_, _, err := setsockopt(fd, optname, uintptr(unsafe.Pointer(&val)),
		unsafe.Sizeof(val))
	return err
}

func getsockoptInt32(fd int, optname uintptr) (int32, error) {
	var val int32
	optlen := uint32(unsafe.Sizeof(val))
	_, _, err := getsockopt(fd, optname, uintptr(unsafe.Pointer(&val)),
		&optlen)
	if err != nil {
		return 0, err
	}
	return val, nil
}

func setAssocValue(fd int, optname uintptr, val uint32) error {
	av := AssocValue{AssocVal: val}
	_, _, err := setsockopt(fd, optname, uintptr(unsafe.Pointer(&av)),
		unsafe.Sizeof(av))
	return err
}

func setSockoptBool(fd int, optname uintptr, on bool) error {
	return setsockoptInt(fd, optname, on)
}

func getSockoptBool(fd int, optname uintptr) (bool, error) {
	value, err := getsockoptInt32(fd, optname)
	return value != 0, err
}

func setAssocValueBool(fd int, optname uintptr, on bool) error {
	var value uint32
	if on {
		value = 1
	}
	return setAssocValue(fd, optname, value)
}

func getAssocValue(fd int, optname uintptr) (uint32, error) {
	av := AssocValue{}
	optlen := uint32(unsafe.Sizeof(av))
	_, _, err := getsockopt(fd, optname, uintptr(unsafe.Pointer(&av)),
		&optlen)
	if err != nil {
		return 0, err
	}
	return av.AssocVal, nil
}

// connectSettleTimeout bounds the confirmation required after connectx reports
// EALREADY. That result means an association setup is already in progress, not
// that the RFC 9260 four-way handshake has completed.
const connectSettleTimeout = 5 * time.Second

func waitEstablished(fd int, timeout time.Duration) bool {
	const interval = 2 * time.Millisecond
	deadline := time.Now().Add(timeout)
	for {
		if hasEstablishedAssoc(fd) {
			return true
		}
		if !time.Now().Before(deadline) {
			return false
		}
		time.Sleep(interval)
	}
}

// hasEstablishedAssoc uses SCTP_STATUS (RFC 6458 §8.2) to distinguish an
// established one-to-one association from a socket whose handshake is still
// pending. Linux returns EINVAL while there is no association to describe.
func hasEstablishedAssoc(fd int) bool {
	status := &Status{}
	optlen := uint32(unsafe.Sizeof(*status))
	if _, _, err := getsockopt(fd, SCTP_STATUS,
		uintptr(unsafe.Pointer(status)), &optlen); err != nil {
		return false
	}
	return status.State != 0
}

func sctpGetAddrs(fd, id, optname int) (*SCTPAddr, error) {
	type getaddrs struct {
		assocID int32
		addrNum uint32
		addrs   [4096]byte
	}
	param := getaddrs{assocID: int32(id)}
	optlen := uint32(unsafe.Sizeof(param))
	_, _, err := getsockopt(fd, uintptr(optname),
		uintptr(unsafe.Pointer(&param)), &optlen)
	if err != nil {
		return nil, err
	}
	// addrNum comes from the kernel. Bound the walk by the buffer that was
	// actually provided rather than trusting it to describe what fits.
	return resolveFromRawAddrBuf(unsafe.Pointer(&param.addrs),
		int(param.addrNum), unsafe.Sizeof(param.addrs))
}

// closeOnExecUnderForkLock closes the descriptor leak window owned by this
// package. syscall.ForkExec takes ForkLock for writing while it snapshots the
// descriptor table; holding the read lock through F_SETFD ensures that a
// caller-supplied descriptor cannot be inherited after ownership transfers to
// NewSCTPConn.
func closeOnExecUnderForkLock(fd int, closeOnExec func(int)) {
	syscall.ForkLock.RLock()
	closeOnExec(fd)
	syscall.ForkLock.RUnlock()
}

func wrapSocketFile(fd int, name string) (*os.File, syscall.RawConn, error) {
	if fd < 0 {
		return nil, nil, syscall.EBADF
	}
	// NewSCTPConn accepts descriptors supplied by callers, which need not have
	// been created with SOCK_CLOEXEC. Ownership transfers here, so close the
	// exec-leak window before publishing the descriptor through os.File.
	closeOnExecUnderForkLock(fd, syscall.CloseOnExec)
	if err := syscall.SetNonblock(fd, true); err != nil {
		_ = syscall.Close(fd)
		return nil, nil, err
	}
	f := os.NewFile(uintptr(fd), name)
	if f == nil {
		_ = syscall.Close(fd)
		return nil, nil, syscall.EBADF
	}
	raw, err := f.SyscallConn()
	if err != nil {
		_ = f.Close()
		return nil, nil, err
	}
	return f, raw, nil
}

func newSCTPConn(fd int, handler NotificationHandler) (*SCTPConn, error) {
	f, raw, err := wrapSocketFile(fd, "sctp-connection")
	if err != nil {
		return nil, err
	}
	c := &SCTPConn{
		_fd:                 int32(fd),
		notificationHandler: handler,
		file:                f,
		raw:                 raw,
	}
	_ = raw.Control(func(rawfd uintptr) {
		c.localAddr, _ = sctpGetAddrs(int(rawfd), 0, SCTP_GET_LOCAL_ADDRS)
		c.remoteAddr, _ = sctpGetAddrs(int(rawfd), 0, SCTP_GET_PEER_ADDRS)
	})
	return c, nil
}

func newSCTPListener(fd int, handler NotificationHandler) (*SCTPListener, error) {
	f, raw, err := wrapSocketFile(fd, "sctp-listener")
	if err != nil {
		return nil, err
	}
	ln := &SCTPListener{
		_fd:                 int32(fd),
		file:                f,
		raw:                 raw,
		notificationHandler: handler,
	}
	_ = raw.Control(func(rawfd uintptr) {
		ln.localAddr, _ = sctpGetAddrs(int(rawfd), 0, SCTP_GET_LOCAL_ADDRS)
	})
	return ln, nil
}

// bindLocal binds laddr, supplying the wildcard address when the caller named
// only a port.
//
// The wildcard is written into a local copy rather than into the caller's
// SCTPAddr. Appending to laddr.IPAddrs was visible after the call returned and
// was a data race whenever one address value was shared between goroutines,
// which is the ordinary way to run a client and a server against a fixed
// endpoint. It also changed the caller's meaning: a *SCTPAddr that came back
// from a "sctp6" listen carried [::], so reusing it for a "sctp4" dial failed
// with EINVAL.
//
// Only the AF_INET6 arm is load-bearing. ToRawSockAddrBuf already encodes an
// empty address list as IPv4 zero, so the AF_INET arm produces the bytes it
// would have produced anyway; it is kept because relying on that coupling from
// here would be a trap for whoever edits either half next.
func bindLocal(sock int, laddr *SCTPAddr, af int) error {
	if len(laddr.IPAddrs) == 0 {
		local := SCTPAddr{Port: laddr.Port}
		switch af {
		case syscall.AF_INET:
			local.IPAddrs = []net.IPAddr{{IP: net.IPv4zero}}
		case syscall.AF_INET6:
			local.IPAddrs = []net.IPAddr{{IP: net.IPv6zero}}
		}
		laddr = &local
	}
	return SCTPBind(sock, laddr, SCTP_BINDX_ADD_ADDR)
}

// rawConn is the Control-only syscall.RawConn handed to a SocketConfig hook.
// The hook runs synchronously before the socket is published, connected or
// listening, so retaining that descriptor for the duration of the callback is
// safe.
//
// Read and Write report syscall.EINVAL rather than waiting, which is what the
// standard library does for the same case: net/rawconn.go gives a listener's
// RawConn exactly these two methods, and TCPListener.SyscallConn documents it —
// "The returned RawConn only supports calling Control. Read and Write return an
// error." Waiting for accept readiness through a RawConn is not a supported
// idiom anywhere in net, so there is nothing here to implement. What these used
// to do was panic, which is never a defensible answer to a caller using an
// interface exactly as its contract describes.
type rawConn struct {
	sockfd int
}

func (r rawConn) Control(f func(fd uintptr)) error {
	f(uintptr(r.sockfd))
	return nil
}

func (r rawConn) Read(f func(fd uintptr) (done bool)) error {
	return syscall.EINVAL
}

func (r rawConn) Write(f func(fd uintptr) (done bool)) error {
	return syscall.EINVAL
}

// listenerRawConn is the Control-only syscall.RawConn returned by a listener.
// The os.File RawConn underneath pins the descriptor across Control, so Close
// cannot release or recycle it while the callback is running.
type listenerRawConn struct {
	raw      syscall.RawConn
	isClosed func() bool
}

func (r *listenerRawConn) Control(f func(fd uintptr)) error {
	err := r.raw.Control(f)
	if err != nil && r.isClosed() {
		return errClosed("control")
	}
	return normalizePollError("control", err)
}

func (r *listenerRawConn) Read(f func(fd uintptr) (done bool)) error {
	return syscall.EINVAL
}

func (r *listenerRawConn) Write(f func(fd uintptr) (done bool)) error {
	return syscall.EINVAL
}

// connRawConn wraps the os.File RawConn so its errors follow net.Conn's closed
// convention. internal/poll pins the descriptor for Control and serializes
// Read and Write with the package's own RawRead/RawWrite operations. readMu
// additionally keeps raw readers out of the fail-closed interval between a
// partial notification's poller failure and Abort.
type connRawConn struct {
	raw      syscall.RawConn
	isClosed func() bool
	readMu   *sync.Mutex
}

func (r *connRawConn) Control(f func(fd uintptr)) error {
	err := r.raw.Control(f)
	if err != nil && r.isClosed() {
		return errClosed("control")
	}
	return normalizePollError("control", err)
}

func (r *connRawConn) Read(f func(fd uintptr) (done bool)) error {
	r.readMu.Lock()
	defer r.readMu.Unlock()

	err := r.raw.Read(f)
	if err != nil && r.isClosed() {
		return errClosed("read")
	}
	return normalizePollError("read", err)
}

func (r *connRawConn) Write(f func(fd uintptr) (done bool)) error {
	err := r.raw.Write(f)
	if err != nil && r.isClosed() {
		return errClosed("write")
	}
	return normalizePollError("write", err)
}

func (c *SCTPConn) SyscallConn() (syscall.RawConn, error) {
	if c == nil || c.fd() < 0 || c.raw == nil {
		return nil, errClosed("syscallconn")
	}
	return &connRawConn{
		raw:      c.raw,
		isClosed: func() bool { return c.fd() < 0 },
		readMu:   &c.readMu,
	}, nil
}

func (c *SCTPConn) SCTPWrite(b []byte, info *SndRcvInfo) (int, error) {
	if c == nil {
		return 0, errClosed("write")
	}
	return c.writeSndRcv(b, info, c.writeWaitEnabled())
}

func (c *SCTPConn) writeSndRcv(b []byte, info *SndRcvInfo, wait bool) (int, error) {
	var cbuf []byte
	if info != nil {
		cbuf = buildSndRcvCmsg(info)
	}
	return c.sendmsg(b, cbuf, wait)
}

// sendmsg sends one message. When wait is true, it delegates EAGAIN to Go's
// runtime poller so a pending write observes deadline changes and Close.
//
// Sends pass MSG_DONTWAIT, so a full send buffer reports EAGAIN rather than
// blocking. That is deliberate and stays: a blocking sendmsg to a peer that has
// stopped reading does not come back for many minutes — bounded in the limit by
// the retransmission backoff and the shutdown-guard timer, not by anything the
// caller can set — and there is no way to interrupt it. Reporting EAGAIN keeps
// the descriptor under the caller's control.
//
// What it also did was leave SetWriteDeadline with nothing to do. SO_SNDTIMEO
// only bounds a wait the socket never performs, so a deadline in the future
// changed no behaviour whatsoever and only an already-elapsed one was
// observable. A caller asking for what net.Conn.SetWriteDeadline offers — carry
// on until this is accepted or until the deadline — got neither half of it, and
// a burst larger than the send buffer surfaced as a write failure rather than as
// backpressure.
//
// SCTPWrite keeps its historical non-blocking behaviour when no deadline is
// installed. net.Conn.Write always passes wait=true, as its contract requires;
// a concurrent SetWriteDeadline or Close wakes it through the poller.
//
// The whole buffer is retried, never b[n:]. sctp_sendmsg queues a message in
// full or queues nothing, so a refused send leaves nothing behind to resume
// from; resuming at an offset would split one application message into two on
// the wire.
// sendFlags is what both send paths pass to sendmsg.
//
// MSG_NOSIGNAL suppresses the SIGPIPE the kernel otherwise raises when a send
// finds the association gone; the errno is EPIPE either way, which is what a
// caller can actually act on. Both halves were measured: without the flag the
// signal is delivered and the send returns EPIPE, with it the signal is not
// delivered and the send still returns EPIPE.
//
// It matters more since sends grew a retry loop. Go's runtime ignores SIGPIPE
// for descriptors other than 1 and 2, so the default behaviour was survivable,
// but a caller that had asked for it with signal.Notify would see one spurious
// signal per refused send rather than one per write.
const sendFlags = syscall.MSG_DONTWAIT | syscall.MSG_NOSIGNAL

func (c *SCTPConn) writeWaitEnabled() bool {
	c.writeDeadlineMu.Lock()
	wait := c.writeDeadline != 0
	c.writeDeadlineMu.Unlock()
	return wait
}

// sendmsgN is syscall.SendmsgN except at the one boundary where that helper
// changes SCTP's message. On Linux, the syscall package substitutes a one-byte
// iovec when a non-datagram socket sends ancillary data with an empty payload.
// That workaround makes sense for stream-oriented control messages, but SCTP is
// message-oriented: it turns an invalid empty user message into a real one-byte
// DATA chunk while still reporting n == 0 to the caller. A genuine zero-length
// iovec lets the SCTP stack reject the request with EINVAL, consistently with
// an empty send that has no ancillary data.
func sendmsgN(fd int, payload, control []byte, flags int) (int, error) {
	if len(payload) != 0 || len(control) == 0 {
		return syscall.SendmsgN(fd, payload, control, nil, flags)
	}

	var iov syscall.Iovec
	msg := syscall.Msghdr{
		Iov:     &iov,
		Iovlen:  1,
		Control: &control[0],
	}
	msg.SetControllen(len(control))

	n, err := rawSendmsg(fd, &msg, flags)
	runtime.KeepAlive(payload)
	runtime.KeepAlive(control)
	return int(n), err
}

func (c *SCTPConn) sendmsg(b, cbuf []byte, wait bool) (int, error) {
	if c == nil || c.fd() < 0 || c.raw == nil {
		return 0, errClosed("write")
	}
	if c.initErr != nil {
		return 0, c.initErr
	}

	var (
		n       int
		sendErr error
	)
	err := c.raw.Write(func(fd uintptr) bool {
		for {
			n, sendErr = sendmsgN(int(fd), b, cbuf, sendFlags)
			if errors.Is(sendErr, syscall.EINTR) {
				continue
			}
			if wait && (errors.Is(sendErr, syscall.EAGAIN) ||
				errors.Is(sendErr, syscall.EWOULDBLOCK)) {
				return false
			}
			return true
		}
	})
	if err != nil {
		if c.fd() < 0 {
			return 0, errClosed("write")
		}
		return 0, normalizePollError("write", err)
	}
	if sendErr != nil && c.fd() < 0 {
		return 0, errClosed("write")
	}
	return n, sendErr
}

func (c *SCTPConn) write(b []byte) (int, error) {
	return c.sendmsg(b, nil, true)
}

// buildSndRcvCmsg lays out the SCTP_SNDRCV control message for one send.
//
// This replaces two toBuf calls and an append. toBuf goes through
// binary.Write, which reflects over the struct and writes into a bytes.Buffer —
// four allocations per call, so eight per message plus the append's copy. The
// layout is fixed and TestStructLayoutsMatchKernel pins it, so writing the bytes
// directly is equivalent and needs one allocation.
//
// It also fixes a latent data race. The previous version byte-swapped
// info.PPID in place, wrote the struct, then swapped it back:
//
//	oldPPID := info.PPID
//	info.PPID = htonl(info.PPID)
//	cmsgBuf := toBuf(info)
//	info.PPID = oldPPID
//
// Two goroutines sharing one *SndRcvInfo — which callers do, since it is
// otherwise read-only — could observe the swapped value or lose the restore.
// Nothing here mutates the caller's struct.
func buildSndRcvCmsg(info *SndRcvInfo) []byte {
	// Derived from the struct rather than written as a literal, so a field added
	// to SndRcvInfo cannot leave this sending a short message.
	//
	// No test distinguishes this from a hardcoded 32 today, and that was
	// measured rather than assumed: CmsgSpace rounds to a 16-byte boundary, so
	// CmsgSpace(28) and CmsgSpace(32) are both 48 and every plausible wrong
	// constant produces an identical buffer. The derivation is defence against a
	// future change, not a fix for a present bug.
	dataLen := int(unsafe.Sizeof(SndRcvInfo{}))
	// CmsgLen(0) is the header size. CmsgSpace(0) is the same 16 bytes here, so
	// the two are interchangeable on this platform; CmsgLen is used because it is
	// the one that means "header only" rather than "header plus alignment".
	hdrLen := syscall.CmsgLen(0)
	buf := make([]byte, syscall.CmsgSpace(dataLen))

	hdr := (*syscall.Cmsghdr)(unsafe.Pointer(&buf[0]))
	hdr.Level = syscall.IPPROTO_SCTP
	hdr.Type = SCTP_CMSG_SNDRCV
	// The bit width of Len is platform-specific, so SetLen is used rather than
	// assigning it. Note this keeps the original code's CmsgSpace rather than
	// CmsgLen: on this platform the two agree for a 32-byte payload, and
	// changing it would alter the bytes on the wire for every existing caller.
	hdr.SetLen(syscall.CmsgSpace(dataLen))

	// Field offsets from struct sctp_sndrcvinfo. PPID goes to the wire in
	// network byte order; every other field is host order.
	d := buf[hdrLen:]
	nativeEndian.PutUint16(d[0:2], info.Stream)
	nativeEndian.PutUint16(d[2:4], info.SSN)
	nativeEndian.PutUint16(d[4:6], info.Flags)
	// d[6:8] is the pad after Flags.
	nativeEndian.PutUint32(d[8:12], htonl(info.PPID))
	nativeEndian.PutUint32(d[12:16], info.Context)
	nativeEndian.PutUint32(d[16:20], info.TTL)
	nativeEndian.PutUint32(d[20:24], info.TSN)
	nativeEndian.PutUint32(d[24:28], info.CumTSN)
	nativeEndian.PutUint32(d[28:32], uint32(info.AssocID))
	return buf
}

// SCTPWriteInfo sends one message using the non-deprecated ancillary data types,
// optionally attaching a partial reliability policy and an authentication key.
//
// This is the send-side counterpart to the SCTP_RCVINFO support on the read path.
// RFC 6458 §5.3.2 titles the struct sctp_sndrcvinfo that SCTPWrite sends
// "DEPRECATED" and splits it into SCTP_SNDINFO for sending and SCTP_RCVINFO for
// receiving; this emits SCTP_SNDINFO.
//
// SCTPWrite is unchanged and still emits SCTP_SNDRCV, because switching it would
// change the bytes on every existing caller's socket. The kernel accepts either,
// and in fact accepts both in one sendmsg without complaint, so the two can be
// mixed freely on the same association — that was measured.
//
// Any of the three may be nil:
//
//   - info nil sends with the socket defaults from SetDefaultSndInfo.
//   - pr adds SCTP_CMSG_PRINFO, overriding the default policy from
//     SetDefaultPrInfo for this message only. It needs PR-SCTP negotiated;
//     see SetPrSupported.
//   - auth adds SCTP_CMSG_AUTHINFO, naming the shared key to authenticate this
//     message with. It needs net.sctp.auth_enable; see SetAuthActiveKey.
//
// SndInfo.PPID follows the package-wide host-order convention. RFC 6458 §5.3.4
// labels the ancillary field network byte order and says the SCTP stack leaves
// it untouched, so the copy emitted below is converted without mutating the
// caller's structure.
func (c *SCTPConn) SCTPWriteInfo(b []byte, info *SndInfo, pr *PrInfo, auth *AuthInfo) (int, error) {
	if c == nil {
		return 0, errClosed("write")
	}
	var cbuf []byte
	appendCmsg := func(cmsgType int32, data []byte) {
		hdr := &syscall.Cmsghdr{
			Level: syscall.IPPROTO_SCTP,
			Type:  cmsgType,
		}
		// The bit width of hdr.Len is platform-specific, so SetLen is used
		// rather than assigning Len directly.
		hdr.SetLen(syscall.CmsgLen(len(data)))
		cbuf = append(cbuf, toBuf(hdr)...)
		cbuf = append(cbuf, data...)
		// Each control message starts at a platform-aligned offset, so pad up
		// to where the next header has to begin. Without this the kernel reads
		// the second cmsg header from the wrong offset.
		if pad := syscall.CmsgSpace(len(data)) - syscall.CmsgLen(len(data)); pad > 0 {
			cbuf = append(cbuf, make([]byte, pad)...)
		}
	}

	// AUTHINFO goes first deliberately. It is a 2-byte payload, the only one of
	// the three whose CmsgSpace exceeds its CmsgLen, so it is the only cmsg
	// whose alignment padding is observable — and padding is only read when
	// another control message follows. Emitting it last would leave the padding
	// logic untestable, since the bytes after the final cmsg are never
	// inspected. The kernel does not care about the order.
	if auth != nil {
		appendCmsg(SCTP_CMSG_AUTHINFO, toBuf(auth))
	}
	if info != nil {
		param := *info
		param.PPID = htonl(param.PPID)
		appendCmsg(SCTP_CMSG_SNDINFO, toBuf(&param))
	}
	if pr != nil {
		appendCmsg(SCTP_CMSG_PRINFO, toBuf(pr))
	}

	return c.sendmsg(b, cbuf, c.writeWaitEnabled())
}

// parseSndRcvInfo extracts the per-message information from a control message
// buffer, accepting either form the kernel may have sent.
//
// SCTP_SNDRCV is what SubscribeEvents(SCTP_EVENT_DATA_IO) asks for, and RFC 6458
// §5.3.2 titles it "DEPRECATED", directing callers to SCTP_SNDINFO for sending
// and SCTP_RCVINFO (§5.3.5) for receiving. SetRecvRcvInfo enables the latter.
//
// Both are handled here because enabling only the modern option used to lose the
// message's stream and PPID silently: the kernel sent SCTP_RCVINFO, nothing here
// recognised it, and SCTPRead returned a nil SndRcvInfo with no error. That was
// measured, and it is the reason this function does not simply prefer one type.
//
// SCTP_SNDRCV wins when both are present, so a caller that has enabled both
// keeps the exact bytes it had before. The result is always an *SndRcvInfo, which
// keeps the return type of SCTPRead unchanged; RcvInfo carries no TTL, so that
// field stays zero when the information came from SCTP_RCVINFO.
func parseSndRcvInfo(b []byte) (*SndRcvInfo, error) {
	msgs, err := syscall.ParseSocketControlMessage(b)
	if err != nil {
		return nil, err
	}
	var fromRcvInfo *SndRcvInfo
	for _, m := range msgs {
		if m.Header.Level != syscall.IPPROTO_SCTP {
			continue
		}
		switch m.Header.Type {
		case SCTP_CMSG_SNDRCV:
			if len(m.Data) < int(unsafe.Sizeof(SndRcvInfo{})) {
				continue
			}
			// Decode fields explicitly instead of casting m.Data. Control-message
			// payload alignment is an ABI detail, and a caller of SCTPReadMsg may
			// pass these bytes back from a subslice at any alignment.
			//
			// This used to alias the caller's control-message buffer and
			// byte-swap PPID in place, which had two consequences. Parsing the
			// same bytes twice swapped twice, so the second call returned
			// 0x44332211 for an 0x11223344 payload — reachable by any caller
			// driving recvmsg itself through SyscallConn. And it made the oob
			// buffer in SCTPReadFlags impossible to reuse, since the returned
			// value outlived the read.
			info := SndRcvInfo{
				Stream:  nativeEndian.Uint16(m.Data[0:2]),
				SSN:     nativeEndian.Uint16(m.Data[2:4]),
				Flags:   nativeEndian.Uint16(m.Data[4:6]),
				PPID:    ntohl(nativeEndian.Uint32(m.Data[8:12])),
				Context: nativeEndian.Uint32(m.Data[12:16]),
				TTL:     nativeEndian.Uint32(m.Data[16:20]),
				TSN:     nativeEndian.Uint32(m.Data[20:24]),
				CumTSN:  nativeEndian.Uint32(m.Data[24:28]),
				AssocID: int32(nativeEndian.Uint32(m.Data[28:32])),
			}
			return &info, nil
		case SCTP_CMSG_RCVINFO:
			if len(m.Data) < int(unsafe.Sizeof(RcvInfo{})) {
				continue
			}
			fromRcvInfo = &SndRcvInfo{
				Stream:  nativeEndian.Uint16(m.Data[0:2]),
				SSN:     nativeEndian.Uint16(m.Data[2:4]),
				Flags:   nativeEndian.Uint16(m.Data[4:6]),
				PPID:    ntohl(nativeEndian.Uint32(m.Data[8:12])),
				TSN:     nativeEndian.Uint32(m.Data[12:16]),
				CumTSN:  nativeEndian.Uint32(m.Data[16:20]),
				Context: nativeEndian.Uint32(m.Data[20:24]),
				AssocID: int32(nativeEndian.Uint32(m.Data[24:28])),
			}
		}
	}
	return fromRcvInfo, nil
}

// parseNxtInfo extracts SCTP_NXTINFO from a control message buffer, if it is
// there.
//
// It is a separate walk rather than another case in parseSndRcvInfo because
// this describes a different message: SndRcvInfo is about the bytes just read,
// NxtInfo about the one behind them. Folding them together would mean changing
// the return type of every read.
//
// A nil result with a nil error means the kernel sent no such cmsg, which is
// what happens when SetRecvNxtInfo is off or the receive queue is empty. That is
// not a failure, so it is not reported as one.
func parseNxtInfo(b []byte) (*NxtInfo, error) {
	msgs, err := syscall.ParseSocketControlMessage(b)
	if err != nil {
		return nil, err
	}
	for _, m := range msgs {
		if m.Header.Level != SOL_SCTP || m.Header.Type != SCTP_CMSG_NXTINFO {
			continue
		}
		if len(m.Data) < int(unsafe.Sizeof(NxtInfo{})) {
			continue
		}
		// Decode instead of casting so the result neither aliases the pooled
		// buffer nor depends on its address alignment.
		ni := NxtInfo{
			SID:     nativeEndian.Uint16(m.Data[0:2]),
			Flags:   nativeEndian.Uint16(m.Data[2:4]),
			PPID:    ntohl(nativeEndian.Uint32(m.Data[4:8])),
			Length:  nativeEndian.Uint32(m.Data[8:12]),
			AssocID: SCTPAssocID(int32(nativeEndian.Uint32(m.Data[12:16]))),
		}
		return &ni, nil
	}
	return nil, nil
}

// SCTPReadNextInfo is SCTPReadFlags, additionally returning what the kernel
// said about the message queued behind this one.
//
// nxt is nil when SetRecvNxtInfo has not been enabled or when nothing else is
// queued; neither is an error. Its Length is the whole size of the next
// message, so a caller can size the next buffer exactly rather than reading
// into a guess and reassembling.
func (c *SCTPConn) SCTPReadNextInfo(b []byte) (int, *SndRcvInfo, *NxtInfo, int, error) {
	var nxt *NxtInfo
	n, info, flags, err := c.readFlags(b, &nxt)
	return n, info, nxt, flags, err
}

// SCTPRead reads one message, or as much of one message as fits in b.
//
// If the message is larger than b, the remainder is not discarded: it is
// returned by subsequent reads, which makes a truncated message
// indistinguishable from a complete one here. Callers of framed protocols
// should use SCTPReadFlags and test the returned flags for MSG_EOR, or use
// ReadMsg to have the reassembly done for them.
func (c *SCTPConn) SCTPRead(b []byte) (int, *SndRcvInfo, error) {
	n, info, _, err := c.SCTPReadFlags(b)
	return n, info, err
}

// SCTPReadFlags is SCTPRead, additionally returning the flags recvmsg
// reported for the message.
//
// The kernel sets MSG_EOR when b received the end of a message and clears it
// when more of that message remains, so flags&MSG_EOR == 0 means the message
// was truncated and the remainder will arrive on subsequent reads. Without
// checking it, an oversized message is silently split and the remainder is
// delivered as what looks like a fresh message.
func (c *SCTPConn) SCTPReadFlags(b []byte) (int, *SndRcvInfo, int, error) {
	return c.readFlags(b, nil)
}

// SCTPReadMsg performs one recvmsg and returns the payload, ancillary-data
// length, and message flags without interpreting or discarding any of them.
// It is the escape hatch for extensions whose control messages this package
// does not yet decode. In particular, callers must test MSG_CTRUNC before
// trusting oob; use syscall.ParseSocketControlMessage to walk complete data.
//
// Notifications are returned with MSG_NOTIFICATION, and an application record
// that does not fit in b is returned without MSG_EOR. Unlike Read and ReadMsg,
// this method deliberately applies no notification or framing policy.
func (c *SCTPConn) SCTPReadMsg(b, oob []byte) (n, oobn, flags int, err error) {
	if c == nil || c.fd() < 0 || c.raw == nil {
		return 0, 0, 0, errClosed("read")
	}
	if c.initErr != nil {
		return 0, 0, 0, c.initErr
	}
	if len(b) == 0 {
		return 0, 0, 0, nil
	}
	return c.recvmsg(b, oob)
}

// readFlags is SCTPReadFlags, additionally filling *nxt from SCTP_NXTINFO when
// nxt is non-nil.
//
// The two share one body because they share one recvmsg: the next-message
// information arrives as ancillary data on the same call, so parsing it
// afterwards would mean either a second read or stashing the result on the
// connection, and the second is a race as soon as two goroutines read.
// Passing nil keeps the ordinary path from walking the control buffer twice.
func (c *SCTPConn) readFlags(b []byte, nxt **NxtInfo) (int, *SndRcvInfo, int, error) {
	if c == nil || c.fd() < 0 || c.raw == nil {
		return 0, nil, 0, errClosed("read")
	}
	if c.initErr != nil {
		return 0, nil, 0, c.initErr
	}

	// An empty buffer must not touch the stream. recvmsg substitutes a
	// one-byte scratch iovec when the data buffer is empty and the control
	// buffer is not — correct for a genuine control-only receive, and the
	// control buffer here is never empty. So without this the kernel dequeued a
	// payload byte into a package-local variable and reported n=1: Read
	// returned more than len(b), which io.Reader forbids, and the byte was
	// gone. Measured with eight bytes queued, Read(nil) returned 1 and the next
	// read returned "BCDEFGH".
	//
	// It is not only Read(nil) that gets here. The ordinary framing loop reads
	// into b[total:], which is empty the moment the buffer fills, so the next
	// line — b[:total] — panicked on a slice grown past its own capacity.
	if len(b) == 0 {
		return 0, nil, 0, nil
	}

	// The control buffer is pooled rather than allocated per call. This is only
	// safe because parseSndRcvInfo copies: it used to return a pointer into
	// this buffer and byte-swap PPID in place, so reusing the buffer would have
	// been a use-after-free. See TestParseSndRcvInfoDoesNotAliasInput.
	oobp := oobPool.Get().(*[]byte)
	oob := *oobp
	defer oobPool.Put(oobp)

	for {
		n, oobn, recvflags, notification, err := c.recvmsgWithNotification(b, oob)
		if err != nil {
			return n, nil, recvflags, err
		}

		if notification != nil {
			if err := c.notificationHandler(notification); err != nil {
				return 0, nil, recvflags, err
			}
			continue
		}

		if n == 0 && oobn == 0 {
			return 0, nil, recvflags, io.EOF
		}

		if recvflags&syscall.MSG_CTRUNC != 0 {
			return n, nil, recvflags, ErrControlTruncated
		}
		var info *SndRcvInfo
		if oobn > 0 {
			info, err = parseSndRcvInfo(oob[:oobn])
			if nxt != nil && err == nil {
				// A malformed SCTP_NXTINFO is not worth failing the read
				// for: the message itself is fine, and the caller's
				// fallback is to size the next buffer as they did before.
				*nxt, _ = parseNxtInfo(oob[:oobn])
			}
		}
		return n, info, recvflags, err
	}
}

// recvmsgWithNotification performs one application-data recvmsg, or consumes
// one complete notification when a NotificationHandler is installed. Linux
// fragments a notification when the caller's data buffer is too small and
// clears MSG_EOR until the final fragment. Holding one RawConn.Read operation
// across those fragments prevents another concurrent reader from stealing the
// tail; the caller invokes user code only after this method releases the
// runtime poller's read lock.
//
// With no handler this intentionally delegates to recvmsg unchanged, preserving
// SCTPReadFlags and SCTPEndpoint.Receive's raw fragment/MSG_EOR contract.
func (c *SCTPConn) recvmsgWithNotification(b, oob []byte) (
	n, oobn, recvflags int, notification []byte, err error,
) {
	return c.recvmsgWithNotificationUsing(b, oob, recvmsg)
}

type recvmsgFunc func(fd int, b, oob []byte, flags int) (
	n, oobn, recvflags int, err error,
)

func (c *SCTPConn) recvmsgWithNotificationUsing(
	b, oob []byte, receive recvmsgFunc,
) (n, oobn, recvflags int, notification []byte, err error) {
	if c == nil || c.fd() < 0 || c.raw == nil {
		return 0, 0, 0, nil, errClosed("read")
	}
	if c.notificationHandler == nil {
		n, oobn, recvflags, err = c.recvmsg(b, oob)
		return n, oobn, recvflags, nil, err
	}

	const continuationSize = 2048
	var continuation [continuationSize]byte
	accumulator := notificationAccumulator{retain: true}
	notificationStarted := false
	notificationComplete := false
	var recvErr error
	c.readMu.Lock()
	defer c.readMu.Unlock()
	pollErr := c.raw.Read(func(fd uintptr) bool {
		for {
			dst := b
			if notificationStarted {
				dst = continuation[:]
			}
			n, oobn, recvflags, recvErr = receive(
				int(fd), dst, oob, syscall.MSG_DONTWAIT)
			if errors.Is(recvErr, syscall.EINTR) {
				continue
			}
			if errors.Is(recvErr, syscall.EAGAIN) ||
				errors.Is(recvErr, syscall.EWOULDBLOCK) {
				return false
			}
			if recvErr != nil {
				return true
			}
			if n == 0 && oobn == 0 {
				if notificationStarted {
					recvErr = io.EOF
				}
				return true
			}
			if recvflags&MSG_NOTIFICATION == 0 {
				if notificationStarted {
					recvErr = syscall.EPROTO
				}
				return true
			}

			notificationStarted = true
			accumulator.add(dst[:n])
			if recvflags&syscall.MSG_EOR != 0 {
				notification, recvErr = accumulator.finish()
				notificationComplete = true
				n = 0
				oobn = 0
				return true
			}
		}
	})
	if pollErr != nil {
		if c.fd() < 0 {
			return 0, 0, 0, nil, errClosed("read")
		}
		if notificationStarted {
			return 0, 0, recvflags, nil,
				c.abortInterruptedNotification(&accumulator, pollErr)
		}
		return 0, 0, 0, nil, normalizePollError("read", pollErr)
	}
	// A complete event has already been consumed from the socket. Preserve it
	// if Close races after RawConn.Read releases its poller lock; otherwise the
	// close check below would replace the event with net.ErrClosed because
	// notification delivery intentionally returns n == 0.
	if notificationComplete {
		return 0, 0, recvflags, notification, recvErr
	}
	if notificationStarted {
		return 0, 0, recvflags, nil,
			c.abortInterruptedNotification(&accumulator, recvErr)
	}
	if c.fd() < 0 && (recvErr != nil || n == 0) {
		return 0, 0, recvflags, nil, errClosed("read")
	}
	return n, oobn, recvflags, notification, recvErr
}

// abortInterruptedNotification handles every automatic-reassembly exit that
// cannot preserve a record boundary: recvmsg consumed a notification prefix
// but no call observed MSG_EOR. Returning while leaving the socket open would
// let the next read mistake the queued tail for a new event. Notification
// records are enqueued atomically by Linux in normal operation, so this is a
// defensive kernel/error path; fail the association closed rather than
// silently corrupting the receive stream.
func (c *SCTPConn) abortInterruptedNotification(
	accumulator *notificationAccumulator, pollErr error,
) error {
	err := errors.Join(accumulator.interrupted(), normalizePollError("read", pollErr))
	if abortErr := c.Abort(); abortErr != nil && !errors.Is(abortErr, net.ErrClosed) {
		err = errors.Join(err, abortErr)
	}
	return err
}

func (c *SCTPConn) abortInterruptedMessage(cause error) error {
	err := errors.Join(ErrMessageInterrupted, normalizePollError("read", cause))
	if abortErr := c.Abort(); abortErr != nil && !errors.Is(abortErr, net.ErrClosed) {
		err = errors.Join(err, abortErr)
	}
	return err
}

// recvmsg runs one non-blocking receive under the descriptor ownership and
// readiness guarantees of the runtime poller. Returning false on EAGAIN lets
// internal/poll wait without tying up a thread, and lets a later deadline or
// Close interrupt a receive that was already pending.
func (c *SCTPConn) recvmsg(b, oob []byte) (n, oobn, recvflags int, err error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()

	var recvErr error
	pollErr := c.raw.Read(func(fd uintptr) bool {
		for {
			n, oobn, recvflags, recvErr = recvmsg(int(fd), b, oob, syscall.MSG_DONTWAIT)
			if errors.Is(recvErr, syscall.EINTR) {
				continue
			}
			if errors.Is(recvErr, syscall.EAGAIN) ||
				errors.Is(recvErr, syscall.EWOULDBLOCK) {
				return false
			}
			return true
		}
	})
	if pollErr != nil {
		if c.fd() < 0 {
			return 0, 0, 0, errClosed("read")
		}
		return 0, 0, 0, normalizePollError("read", pollErr)
	}
	if c.fd() < 0 && (recvErr != nil || n == 0) {
		return 0, 0, recvflags, errClosed("read")
	}
	return n, oobn, recvflags, recvErr
}

// errClosed is the error for an operation on a connection or listener whose
// descriptor this package has already released.
//
// net documents errors.Is(err, net.ErrClosed) as the way to recognise this, and
// the ordinary shutdown loop is written around it. Returning the kernel's bare
// EBADF meant that test was always false, so the loop never matched and logged
// the errno as an unexpected failure instead of exiting.
//
// It is reported from the descriptor being -1, which only this package's own
// Close does. A descriptor closed by someone else between the check and the
// syscall still surfaces as EBADF, which is the truthful answer for a socket
// this package did not close.
func (c *SCTPConn) control(op string, f func(fd int) error) error {
	if c == nil {
		return errClosed(op)
	}
	if c.initErr != nil {
		return c.initErr
	}
	if c.fd() < 0 || c.raw == nil {
		return errClosed(op)
	}
	var callErr error
	err := c.raw.Control(func(fd uintptr) {
		callErr = f(int(fd))
	})
	if err != nil {
		return normalizePollError(op, err)
	}
	return callErr
}

func (c *SCTPConn) setsockopt(optname, optval, optlen uintptr) (uintptr, uintptr, error) {
	var r0, r1 uintptr
	err := c.control("setsockopt", func(fd int) error {
		var err error
		r0, r1, err = setsockopt(fd, optname, optval, optlen)
		return err
	})
	return r0, r1, err
}

func (c *SCTPConn) getsockopt(optname, optval uintptr, optlen *uint32) (uintptr, uintptr, error) {
	var r0, r1 uintptr
	err := c.control("getsockopt", func(fd int) error {
		var err error
		r0, r1, err = getsockopt(fd, optname, optval, optlen)
		return err
	})
	return r0, r1, err
}

func (c *SCTPConn) getsockoptRaw(optname, optval, optlen uintptr) (uintptr, uintptr, error) {
	var r0, r1 uintptr
	err := c.control("getsockopt", func(fd int) error {
		var err error
		r0, r1, err = getsockoptRaw(fd, optname, optval, optlen)
		return err
	})
	return r0, r1, err
}

func (c *SCTPConn) setInitOpts(options InitMsg) error {
	return c.control("setsockopt", func(fd int) error {
		return setInitOpts(fd, options)
	})
}

func (c *SCTPConn) setsockoptInt(optname uintptr, on bool) error {
	return c.control("setsockopt", func(fd int) error {
		return setsockoptInt(fd, optname, on)
	})
}

func (c *SCTPConn) setsockoptInt32(optname uintptr, value int32) error {
	return c.control("setsockopt", func(fd int) error {
		return setsockoptInt32(fd, optname, value)
	})
}

func (c *SCTPConn) getsockoptInt32(optname uintptr) (int32, error) {
	var value int32
	err := c.control("getsockopt", func(fd int) error {
		var err error
		value, err = getsockoptInt32(fd, optname)
		return err
	})
	return value, err
}

func (c *SCTPConn) setSockoptBool(optname uintptr, on bool) error {
	return c.control("setsockopt", func(fd int) error {
		return setSockoptBool(fd, optname, on)
	})
}

func (c *SCTPConn) getSockoptBool(optname uintptr) (bool, error) {
	var value bool
	err := c.control("getsockopt", func(fd int) error {
		var err error
		value, err = getSockoptBool(fd, optname)
		return err
	})
	return value, err
}

func (c *SCTPConn) setAssocValue(optname uintptr, value uint32) error {
	return c.control("setsockopt", func(fd int) error {
		return setAssocValue(fd, optname, value)
	})
}

func (c *SCTPConn) getAssocValue(optname uintptr) (uint32, error) {
	var value uint32
	err := c.control("getsockopt", func(fd int) error {
		var err error
		value, err = getAssocValue(fd, optname)
		return err
	})
	return value, err
}

func (c *SCTPConn) setAssocValueBool(optname uintptr, on bool) error {
	return c.control("setsockopt", func(fd int) error {
		return setAssocValueBool(fd, optname, on)
	})
}

func (c *SCTPConn) getAddrs(id, optname int) (*SCTPAddr, error) {
	var addr *SCTPAddr
	err := c.control("getsockopt", func(fd int) error {
		var err error
		addr, err = sctpGetAddrs(fd, id, optname)
		return err
	})
	return addr, err
}

// oobPool holds the per-read control-message buffers.
//
// 254 bytes is what the read path has always asked for. It is enough, but not
// for the reason it looks like: the cmsgs are not delivered one at a time. With
// every info option this package can enable turned on and a message queued
// behind the one being read, one recvmsg carries three, measured on 6.12 as
// SCTP_NXTINFO (CMSG_SPACE 32), SCTP_RCVINFO (48) and SCTP_SNDRCV (48) — 128
// bytes in that order.
//
// The order is what makes an undersized buffer dangerous. SCTP_SNDRCV is
// written last, so truncation can leave the prediction for the next message
// while losing the description of the message just read. High-level reads
// therefore return ErrControlTruncated on MSG_CTRUNC; SCTPReadMsg exposes the
// raw flag. The full-sized pool avoids that error for every supported metadata
// combination under normal operation.
//
// Pointers to slices are pooled rather than slices, so putting one back does
// not allocate a header on the heap to hold it.
func newOOBPool(size int) *sync.Pool {
	return &sync.Pool{
		New: func() interface{} {
			b := make([]byte, size)
			return &b
		},
	}
}

var oobPool = newOOBPool(254)

// recvmsg receives one message into b with its control data into oob.
//
// It exists because syscall.Recvmsg allocates twice per call for a peer address
// this package discards: it fills a RawSockaddrAny, which escapes to the heap,
// and then converts it with anyToSockaddr, which allocates the Sockaddr. A
// memory profile of the read path attributed two thirds of its allocations to
// that conversion alone.
//
// Passing a nil msg.Name asks the kernel not to report the source address at
// all, which is what SCTP wants: the socket is connected, so the peer is not in
// question, and SCTPReadFlags never looked at the value.
//
// The Msghdr and Iovec stay on the stack.
func recvmsg(fd int, b, oob []byte, flags int) (n, oobn, recvflags int, err error) {
	var msg syscall.Msghdr
	var iov syscall.Iovec

	if len(b) > 0 {
		iov.Base = &b[0]
		iov.SetLen(len(b))
	}
	// A control-only receive still needs somewhere for the kernel to put the
	// single byte a SOCK_STREAM read must return, mirroring what
	// syscall.recvmsgRaw does for the same case.
	var dummy byte
	if len(oob) > 0 {
		if len(b) == 0 {
			iov.Base = &dummy
			iov.SetLen(1)
		}
		msg.Control = &oob[0]
		msg.SetControllen(len(oob))
	}
	msg.Iov = &iov
	msg.Iovlen = 1

	r0, err := rawRecvmsg(fd, &msg, flags)
	if err != nil {
		return 0, 0, 0, err
	}
	return int(r0), int(msg.Controllen), int(msg.Flags), nil
}

// ReadMsg reads one whole message, reassembling it across as many recvmsg
// calls as the kernel needs to deliver it. Once the first application-data
// fragment arrives, one runtime-poller read lock covers the complete record so
// another concurrent reader cannot steal a fragment. Notifications preceding
// that record are delivered outside the poller's lock.
//
// At most max bytes are retained. If the message is larger, ReadMsg drains its
// remainder before returning ErrMsgTooLong; this preserves the record boundary
// and guarantees the next read cannot mistake the rejected tail for a new
// message. Notifications are likewise header-validated and bounded by
// NotificationReassemblyLimit before being consumed or passed to a handler.
// The returned SndRcvInfo is from the first application-data fragment.
func (c *SCTPConn) ReadMsg(max int) ([]byte, *SndRcvInfo, error) {
	return c.readMsgUsing(max, recvmsg)
}

func (c *SCTPConn) readMsgUsing(max int, receive recvmsgFunc) ([]byte, *SndRcvInfo, error) {
	if max <= 0 {
		return nil, nil, syscall.EINVAL
	}
	if c == nil || c.fd() < 0 || c.raw == nil {
		return nil, nil, errClosed("read")
	}
	if c.initErr != nil {
		return nil, nil, c.initErr
	}

	// Start well under max so a small message costs a small allocation.
	const chunk = 2048
	size := chunk
	if max < size {
		size = max
	}
	buf := make([]byte, size)
	drainBuf := make([]byte, chunk)
	var (
		total                   int
		first                   *SndRcvInfo
		haveFirstFragment       bool
		applicationComplete     bool
		tooLong                 bool
		resultErr               error
		queuedNotifications     [][]byte
		queuedNotificationBytes int
		noteAccumulator         notificationAccumulator
		notificationStarted     bool
		notificationQueueFull   bool
	)
	addResultErr := func(err error) {
		if err == nil {
			return
		}
		if resultErr == nil {
			resultErr = err
			return
		}
		resultErr = errors.Join(resultErr, err)
	}

	oobp := oobPool.Get().(*[]byte)
	oob := *oobp
	defer oobPool.Put(oobp)

	for {
		var immediateNotification []byte
		completedReceive := false
		var partialNotificationErr error
		var partialApplicationErr error
		c.readMu.Lock()
		pollErr := c.raw.Read(func(fd uintptr) bool {
			for {
				if !tooLong && total == len(buf) && total < max {
					grow := len(buf)
					if room := max - total; room < grow {
						grow = room
					}
					buf = append(buf, make([]byte, grow)...)
				}

				dst := drainBuf
				if !tooLong && !notificationStarted {
					dst = buf[total:]
				}

				n, oobn, flags, recvErr := receive(int(fd), dst, oob, syscall.MSG_DONTWAIT)
				if errors.Is(recvErr, syscall.EINTR) {
					continue
				}
				if errors.Is(recvErr, syscall.EAGAIN) ||
					errors.Is(recvErr, syscall.EWOULDBLOCK) {
					return false
				}
				if recvErr != nil {
					if notificationStarted {
						partialNotificationErr = recvErr
					} else if haveFirstFragment && !applicationComplete {
						partialApplicationErr = recvErr
					} else {
						addResultErr(recvErr)
					}
					return true
				}
				if n == 0 && oobn == 0 {
					if notificationStarted {
						partialNotificationErr = io.EOF
					} else if haveFirstFragment && !applicationComplete {
						partialApplicationErr = io.EOF
					} else {
						addResultErr(io.EOF)
					}
					return true
				}

				if flags&MSG_NOTIFICATION != 0 {
					if !notificationStarted {
						notificationStarted = true
						noteAccumulator = notificationAccumulator{
							retain: c.notificationHandler != nil &&
								(!haveFirstFragment || !notificationQueueFull),
						}
					}
					noteAccumulator.add(dst[:n])
					if flags&syscall.MSG_EOR == 0 {
						continue
					}

					completedReceive = true
					note, notificationErr := noteAccumulator.finish()
					notificationStarted = false
					if notificationErr != nil {
						addResultErr(notificationErr)
						if errors.Is(notificationErr, ErrNotificationTooLong) {
							notificationQueueFull = true
						}
						if !haveFirstFragment {
							return true
						}
						continue
					}
					if c.notificationHandler != nil {
						if !haveFirstFragment {
							immediateNotification = note
							return true
						}
						if notificationQueueFull {
							continue
						}
						if len(note) > NotificationReassemblyLimit-queuedNotificationBytes {
							addResultErr(ErrNotificationTooLong)
							notificationQueueFull = true
							continue
						}
						queuedNotifications = append(queuedNotifications, note)
						queuedNotificationBytes += len(note)
					}
					// ReadMsg is an application-message API. Notifications are
					// consumed, whether or not a handler was installed.
					continue
				}
				if notificationStarted {
					partialNotificationErr = syscall.EPROTO
					return true
				}

				if !tooLong {
					total += n
					if !haveFirstFragment {
						haveFirstFragment = true
						if flags&syscall.MSG_CTRUNC != 0 {
							addResultErr(ErrControlTruncated)
						} else if oobn > 0 {
							var err error
							first, err = parseSndRcvInfo(oob[:oobn])
							if err != nil {
								addResultErr(err)
							}
						}
					} else if flags&syscall.MSG_CTRUNC != 0 {
						addResultErr(ErrControlTruncated)
					}
					if total == max && flags&syscall.MSG_EOR == 0 {
						tooLong = true
					}
				}

				if flags&syscall.MSG_EOR != 0 {
					completedReceive = true
					applicationComplete = true
					if tooLong {
						addResultErr(ErrMsgTooLong)
					}
					return true
				}
			}
		})

		// syscall.RawConn.Read holds internal/poll's per-descriptor read lock
		// while its callback runs. User code must run after that callback has
		// returned: a NotificationHandler is allowed to read from the same
		// connection, and invoking it under the lock deadlocks that nested read.
		// Before an application record starts, release the lock for each
		// notification and then resume. Notifications encountered between
		// partial-delivery fragments are queued until the complete record has
		// been consumed, preserving ReadMsg's no-fragment-stealing guarantee.
		// If the poller failed with a notification still partial, abort before
		// invoking any queued handler: handlers may re-enter a read, and must not
		// get a chance to consume the orphaned tail as a fresh event.
		recordInterrupted := haveFirstFragment && !applicationComplete
		if notificationStarted {
			cause := partialNotificationErr
			if pollErr != nil {
				cause = pollErr
			}
			if c.fd() < 0 {
				addResultErr(noteAccumulator.interrupted())
				addResultErr(errClosed("read"))
			} else {
				addResultErr(c.abortInterruptedNotification(&noteAccumulator, cause))
			}
			if recordInterrupted {
				addResultErr(ErrMessageInterrupted)
			}
		} else if recordInterrupted {
			cause := partialApplicationErr
			if pollErr != nil {
				cause = pollErr
			}
			if c.fd() < 0 {
				addResultErr(ErrMessageInterrupted)
				addResultErr(errClosed("read"))
			} else {
				addResultErr(c.abortInterruptedMessage(cause))
			}
		} else if pollErr != nil {
			if c.fd() < 0 {
				addResultErr(errClosed("read"))
			} else {
				addResultErr(normalizePollError("read", pollErr))
			}
		}
		c.readMu.Unlock()

		if immediateNotification != nil {
			if err := c.notificationHandler(immediateNotification); err != nil {
				addResultErr(err)
				return buf[:total], first, resultErr
			}
			if pollErr != nil {
				return buf[:total], first, resultErr
			}
			continue
		}

		for _, note := range queuedNotifications {
			if err := c.notificationHandler(note); err != nil {
				addResultErr(err)
				break
			}
		}
		queuedNotifications = nil
		queuedNotificationBytes = 0

		if pollErr != nil {
			return buf[:total], first, resultErr
		}
		if c.fd() < 0 && !completedReceive && total == 0 {
			if resultErr != nil {
				return buf[:total], first, resultErr
			}
			return buf[:total], first, errClosed("read")
		}
		return buf[:total], first, resultErr
	}
}

// Close closes the SCTP connection gracefully with a timeout fallback.
//
// It initiates a graceful shutdown by sending a SHUTDOWN chunk to the peer
// and waits up to 3 seconds for the peer to acknowledge (SHUTDOWN-ACK).
// If the peer responds, the connection closes gracefully and resources are
// released immediately. If the peer does not respond within the timeout
// (e.g., network failure or unreachable peer), an ABORT chunk is sent to
// forcefully terminate the association and release resources.
//
// This ensures that Close always returns promptly and releases resources,
// avoiding the EADDRINUSE "Address already in use" error that can occur when the kernel
// still occupies the resource.
//
// For immediate termination without waiting, use Abort() instead.
func (c *SCTPConn) Close() error {
	return c.CloseWithTimeout(closeTimeout)
}

// closeTimeout is how long Close waits for the peer to acknowledge a
// shutdown before falling back to an ABORT. It is a compromise: long enough
// that a peer on a congested link can still complete the handshake, short
// enough that a server tearing down many associations is not held up by a
// peer that will never answer. Use CloseWithTimeout to choose another value.
const closeTimeout = 3 * time.Second

// establishTimeout bounds the same wait on the error paths of dial and
// listen. Those sockets have no established association to shut down
// gracefully, so the wait exists only to let the kernel release the address.
const establishTimeout = 1 * time.Second

// CloseWithTimeout is Close with a caller-chosen grace period.
//
// A zero or negative timeout skips the wait entirely and terminates the
// association immediately, which is equivalent to Abort.
func (c *SCTPConn) CloseWithTimeout(timeout time.Duration) error {
	// A zero-value SCTPConn has _fd == 0 but no ownership objects; descriptor
	// zero is stdin in that case and must never be closed. Every connection
	// created by newSCTPConn has both file and raw, including a genuine socket
	// allocated as fd 0.
	if c == nil || (c.file == nil && c.raw == nil) {
		return errClosed("close")
	}
	fd := atomic.SwapInt32(&c._fd, -1)
	// Zero is a valid descriptor: a process that has closed stdin can be
	// handed fd 0 for a socket. Guarding with "fd > 0" leaked it.
	if fd < 0 {
		return errClosed("close")
	}
	if c.file == nil || c.raw == nil {
		return closeSctpSocket(int(fd), timeout)
	}

	var prepareErr error
	controlErr := c.raw.Control(func(rawfd uintptr) {
		prepareErr = prepareSctpClose(int(rawfd), timeout)
	})
	closeErr := c.file.Close()
	if closeErr != nil {
		return normalizePollError("close", closeErr)
	}
	if controlErr != nil {
		return normalizePollError("close", controlErr)
	}
	return prepareErr
}

// shutdownViaEOF asks for a graceful shutdown through the send path, which is
// how it is done on the sockets where shutdown(2) does nothing.
//
// The two mechanisms are complementary in the kernel, and neither covers both
// socket styles. sctp_shutdown opens with "if (!sctp_style(sk, TCP)) return", so
// shutdown(2) is a no-op on a one-to-many socket or one peeled off it. The send
// path is the mirror image: sctp_sendmsg rejects SCTP_EOF with EINVAL when
// sctp_style(sk, TCP), and otherwise calls sctp_primitive_SHUTDOWN.
//
// Measured on a peeled socket, which is the case this package can produce
// through PeelOff. After shutdown(SHUT_RDWR) returns 0 the association is still
// established; the SCTP_EOF send returns 0 and it is gone 50ms later, with
// SHUTDOWN, SHUTDOWN_ACK and SHUTDOWN_COMPLETE on the wire and no ABORT. Before
// this, closeSctpSocket waited out its whole grace period and then aborted.
//
// EINVAL is the expected answer on the one-to-one sockets this package usually
// holds, where shutdown(2) has already done the work. A peeled descriptor is
// nonblocking, however, so EAGAIN must be retried within the caller's grace
// period: otherwise a temporarily full send buffer silently turns a requested
// graceful close into an abort.
func shutdownViaEOF(fd int, deadline time.Time) error {
	cbuf := buildSndRcvCmsg(&SndRcvInfo{Flags: SCTP_EOF})

	var msg syscall.Msghdr
	msg.Control = &cbuf[0]
	msg.SetControllen(len(cbuf))

	// No iovec at all, deliberately. sctp_sendmsg rejects an SCTP_EOF send
	// carrying any payload — "(sflags & SCTP_EOF) && msg_len > 0" is EINVAL —
	// and syscall.SendmsgN substitutes a one-byte scratch iovec whenever the
	// payload is empty and the control buffer is not, on anything that is not
	// SOCK_DGRAM. A peeled socket is SOCK_SEQPACKET, so going through it would
	// send that byte and be refused. This is the same scratch-iovec behaviour
	// recvmsg documents on the read path, in the other direction.
	return shutdownViaEOFUsing(deadline, func() error {
		_, err := rawSendmsg(fd, &msg, 0)
		runtime.KeepAlive(cbuf)
		return err
	}, func(deadline time.Time) (bool, error) {
		return waitWritableUntil(fd, deadline)
	})
}

func shutdownViaEOFUsing(
	deadline time.Time,
	send func() error,
	waitWritable func(time.Time) (bool, error),
) error {
	for {
		err := send()
		switch {
		case err == nil:
			return nil
		case errors.Is(err, syscall.EINTR):
			continue
		case !errors.Is(err, syscall.EAGAIN) && !errors.Is(err, syscall.EWOULDBLOCK):
			return err
		}

		ready, waitErr := waitWritable(deadline)
		if waitErr != nil {
			return waitErr
		}
		if !ready {
			return os.ErrDeadlineExceeded
		}
	}
}

type sctpPollFD struct {
	fd      int32
	events  int16
	revents int16
}

const (
	sctpPollOut  = 0x004
	sctpPollErr  = 0x008
	sctpPollHup  = 0x010
	sctpPollNval = 0x020
)

// waitWritableUntil waits for a nonblocking send to make progress. ppoll is
// used directly because prepareSctpClose runs inside RawConn.Control and cannot
// recursively enter the runtime poller for the same descriptor.
func waitWritableUntil(fd int, deadline time.Time) (bool, error) {
	for {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return false, nil
		}

		fds := [1]sctpPollFD{{fd: int32(fd), events: sctpPollOut}}
		timeout := syscall.NsecToTimespec(remaining.Nanoseconds())
		n, _, errno := syscall.Syscall6(syscall.SYS_PPOLL,
			uintptr(unsafe.Pointer(&fds[0])), 1,
			uintptr(unsafe.Pointer(&timeout)), 0, 0, 0)
		runtime.KeepAlive(&fds)
		runtime.KeepAlive(&timeout)
		if errors.Is(errno, syscall.EINTR) {
			continue
		}
		if errno != 0 {
			return false, errno
		}
		if n == 0 {
			return false, nil
		}
		if fds[0].revents&sctpPollNval != 0 {
			return false, syscall.EBADF
		}
		// POLLERR and POLLHUP are reported as writable conditions too. Retry the
		// send so its errno, which is more specific than a readiness bit, wins.
		if fds[0].revents&(sctpPollOut|sctpPollErr|sctpPollHup) != 0 {
			return true, nil
		}
	}
}

func closeSctpSocket(fd int, timeout time.Duration) error {
	prepareErr := prepareSctpClose(fd, timeout)
	if closeErr := syscall.Close(fd); closeErr != nil {
		return closeErr
	}
	return prepareErr
}

// prepareSctpClose initiates and, when requested, waits for graceful SCTP
// shutdown without releasing the descriptor. Object-owned sockets call it
// while os.File's RawConn pins the descriptor, then let os.File.Close perform
// the one and only close. Raw construction error paths use closeSctpSocket.
func prepareSctpClose(fd int, timeout time.Duration) error {
	if timeout <= 0 {
		return prepareSctpAbort(fd)
	}
	deadline := time.Now().Add(timeout)

	// Take a control reading before shutdown. A missing association is already
	// complete. An unknown query failure is not evidence of completion: abort and
	// propagate it rather than failing open and leaving a live association behind.
	gone, queryErr := assocGone(fd)
	if queryErr != nil {
		return errors.Join(queryErr, prepareSctpAbort(fd))
	}
	if gone {
		return nil
	}

	// Send SHUTDOWN to initiate graceful shutdown. A failure here means no
	// graceful shutdown is possible, so skip the wait and abort instead of
	// blocking for a SHUTDOWN-ACK that cannot arrive.
	if err := syscall.Shutdown(fd, syscall.SHUT_RDWR); err != nil {
		return prepareSctpAbort(fd)
	}

	// shutdown(2) reports success without doing anything on a socket that is
	// not one-to-one style, so ask again through the send path, which is the
	// route that works there. See shutdownViaEOF: the two mechanisms are
	// complementary in the kernel and neither covers both socket styles, so
	// both are issued and whichever does not apply fails harmlessly.
	eofErr := shutdownViaEOF(fd, deadline)
	switch {
	case eofErr == nil, errors.Is(eofErr, syscall.EINVAL):
		// The EOF path either started shutdown or is inapplicable to this
		// one-to-one socket, where shutdown(2) above already started it.
	case errors.Is(eofErr, os.ErrDeadlineExceeded):
		return prepareSctpAbort(fd)
	default:
		gone, statusErr := assocGone(fd)
		if statusErr == nil && gone {
			return nil
		}
		return errors.Join(eofErr, statusErr, prepareSctpAbort(fd))
	}

	// Wait for the shutdown handshake to finish, by watching the association
	// itself rather than by reading from the socket.
	//
	// A read cannot answer this question. shutdown(SHUT_RDWR) sets RCV_SHUTDOWN
	// on the socket before the SCTP layer sees it, and sctp_skb_recv_datagram
	// tests RCV_SHUTDOWN — returning end of stream — before both the EAGAIN path
	// and the SO_RCVTIMEO wait. So the read that used to be here returned
	// (0, nil) the instant the receive queue was empty, whatever the peer had
	// done. Three consequences, all measured:
	//
	//   - "the peer completed the handshake" was true for every peer that had
	//     simply gone silent, which is the one case the wait exists for.
	//   - the EAGAIN outcome the old comment documented was unreachable.
	//   - SO_RCVTIMEO never bound anything, so timeout was inert:
	//     CloseWithTimeout(1ms) and CloseWithTimeout(1h) were the same call.
	//
	// The visible cost was a silent one. Against a peer that had vanished, Close
	// decided the handshake had completed, skipped the ABORT, and left the
	// association and its bound port in the kernel until the retransmissions
	// gave up — up to 5 x RTO.max, 300s at defaults. That is precisely the
	// EADDRINUSE window this function's own doc claims to prevent.
	//
	// SCTP_STATUS is the query that survives the shutdown: sctp_id2assoc admits
	// SCTP_SS_CLOSING as well as SCTP_SS_ESTABLISHED, so it keeps resolving the
	// association across the handshake and only fails once the association is
	// freed. Measured: still answering SHUTDOWN_PENDING 3s after the shutdown
	// for a stalled peer; EINVAL 1.9us after it for one that answers.
	//
	// This is a real wait where the old one was not, so a graceful close now
	// costs about a round trip instead of returning immediately with the wrong
	// answer. It is bounded by the caller's timeout, which now means what it
	// says.
	//
	remaining := time.Until(deadline)
	if remaining <= 0 {
		return prepareSctpAbort(fd)
	}
	completed, waitErr := waitAssocGone(fd, remaining)
	if waitErr != nil {
		return errors.Join(waitErr, prepareSctpAbort(fd))
	}

	if completed {
		// The association is already shut down, so there is nothing for
		// linger to bound. Setting linger=0 here makes close() emit an ABORT
		// on an association that ended cleanly, and a peer still in a read
		// sees ECONNRESET instead of the end of the stream.
		return nil
	}

	// No handshake: linger=0 makes close() send ABORT rather than leave the
	// association half-open, so the address is released promptly instead of
	// being held by a peer that is not answering.
	if err := syscall.SetsockoptLinger(fd, syscall.SOL_SOCKET, syscall.SO_LINGER,
		&syscall.Linger{Onoff: 1, Linger: 0}); err != nil {
		return err
	}
	return nil
}

const (
	// shutdownPollMin and shutdownPollMax bound the backoff waitAssocGone uses.
	// It starts short because the common case — a peer on the same host that
	// answers at once — completes in microseconds, and grows so that waiting out
	// a peer that never answers costs a handful of syscalls rather than
	// thousands.
	shutdownPollMin = 200 * time.Microsecond
	shutdownPollMax = 20 * time.Millisecond
)

// assocGone reports whether the association behind fd has been freed. Only the
// kernel's no-association errors mean gone; every other failure is returned so
// close can abort rather than misreport a graceful shutdown.
//
// The zero AssocID is correct for a one-to-one socket: sctp_id2assoc resolves
// the socket's single association and ignores the identifier.
func assocGone(fd int) (bool, error) {
	status := &Status{}
	optlen := uint32(unsafe.Sizeof(*status))
	for {
		_, _, err := getsockopt(fd, SCTP_STATUS,
			uintptr(unsafe.Pointer(status)), &optlen)
		if errors.Is(err, syscall.EINTR) {
			continue
		}
		switch {
		case err == nil:
			return false, nil
		case errors.Is(err, syscall.EINVAL), errors.Is(err, syscall.ENOTCONN):
			return true, nil
		default:
			return false, err
		}
	}
}

// waitAssocGone waits up to timeout for the shutdown handshake to finish,
// reporting whether it did.
//
// False means the association was still there when the budget ran out, which is
// what tells closeSctpSocket to abort rather than leave it lingering.
func waitAssocGone(fd int, timeout time.Duration) (bool, error) {
	return waitAssocGoneUsing(timeout, func() (bool, error) { return assocGone(fd) })
}

func waitAssocGoneUsing(timeout time.Duration, probe func() (bool, error)) (bool, error) {
	deadline := time.Now().Add(timeout)
	for delay := shutdownPollMin; ; {
		gone, err := probe()
		if err != nil || gone {
			return gone, err
		}
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return false, nil
		}
		if delay > remaining {
			delay = remaining
		}
		time.Sleep(delay)
		if delay < shutdownPollMax {
			delay *= 2
		}
	}
}

// prepareSctpAbort configures immediate termination and wakes blocked readers
// without releasing fd. The caller must close the descriptor exactly once.
func prepareSctpAbort(fd int) error {
	// Setting SO_LINGER with l_onoff=1 and l_linger=0 causes the kernel to
	// send an ABORT chunk instead of SHUTDOWN when closing.
	lerr := syscall.SetsockoptLinger(fd, syscall.SOL_SOCKET, syscall.SO_LINGER,
		&syscall.Linger{Onoff: 1, Linger: 0})

	// Closing the descriptor is not enough to end the association while another
	// goroutine is parked in recvmsg. The blocked call holds a reference to the
	// struct file, so close only unhooks the descriptor number and defers the
	// final release; sctp_close never runs, the SO_LINGER ABORT is never put on
	// the wire, and the association stays up — with Abort having returned nil
	// in tens of microseconds. Measured: no ABORT chunk in seven seconds of
	// capture, both ends still listed in /proc/net/sctp/assocs, and the parked
	// reader still blocked. The graceful path never had this problem because it
	// calls shutdown first.
	//
	// SHUT_RD rather than SHUT_RDWR: it sets RCV_SHUTDOWN and wakes the waiter
	// without asking for a graceful teardown, so the ABORT is still what
	// reaches the peer. sctp_shutdown only emits a SHUTDOWN chunk for
	// SEND_SHUTDOWN.
	//
	// The error is deliberately dropped. A descriptor with no association —
	// which is every socket this is called on that never connected — answers
	// ENOTCONN, and that is not a reason to skip the close.
	_ = syscall.Shutdown(fd, syscall.SHUT_RD)

	return lerr
}

// abortSctpSocket terminates an unwrapped socket and releases its descriptor.
func abortSctpSocket(fd int) error {
	prepareErr := prepareSctpAbort(fd)
	if closeErr := syscall.Close(fd); closeErr != nil {
		return closeErr
	}
	return prepareErr
}

func abandonDialSocket(fd int, policy DialAbandonPolicy) error {
	return abandonDialSocketUsing(fd, policy, abortSctpSocket, syscall.Close)
}

// Abort terminates the SCTP association immediately by sending an ABORT chunk.
// Unlike Close(), this does not perform a graceful shutdown handshake.
// Use this when you need immediate resource release without waiting for
// the peer to acknowledge the shutdown (e.g., when the peer is unreachable).
func (c *SCTPConn) Abort() error {
	if c == nil || (c.file == nil && c.raw == nil) {
		return errClosed("close")
	}
	fd := atomic.SwapInt32(&c._fd, -1)
	// See CloseWithTimeout: fd 0 is valid and must not be skipped.
	if fd < 0 {
		return errClosed("close")
	}
	if c.file == nil || c.raw == nil {
		return abortSctpSocket(int(fd))
	}

	var prepareErr error
	controlErr := c.raw.Control(func(rawfd uintptr) {
		prepareErr = prepareSctpAbort(int(rawfd))
	})
	closeErr := c.file.Close()
	if closeErr != nil {
		return normalizePollError("close", closeErr)
	}
	if controlErr != nil {
		return normalizePollError("close", controlErr)
	}
	return prepareErr
}

func (c *SCTPConn) SetWriteBuffer(bytes int) error {
	return c.control("setsockopt", func(fd int) error {
		return syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_SNDBUF, bytes)
	})
}

func (c *SCTPConn) GetWriteBuffer() (int, error) {
	var value int
	err := c.control("getsockopt", func(fd int) error {
		var err error
		value, err = syscall.GetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_SNDBUF)
		return err
	})
	return value, err
}

func (c *SCTPConn) SetReadBuffer(bytes int) error {
	return c.control("setsockopt", func(fd int) error {
		return syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_RCVBUF, bytes)
	})
}

func (c *SCTPConn) GetReadBuffer() (int, error) {
	var value int
	err := c.control("getsockopt", func(fd int) error {
		var err error
		value, err = syscall.GetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_RCVBUF)
		return err
	})
	return value, err
}

// ListenSCTP - start listener on specified address/port
func ListenSCTP(net string, laddr *SCTPAddr) (*SCTPListener, error) {
	return ListenSCTPExt(net, laddr, InitMsg{NumOstreams: SCTP_MAX_STREAM})
}

// ListenSCTPExt - start listener on specified address/port with given SCTP options
func ListenSCTPExt(network string, laddr *SCTPAddr, options InitMsg) (*SCTPListener, error) {
	return listenSCTPExtConfig(network, laddr, options, nil, nil, PreAssociationConfig{})
}

// listenSCTPExtConfig - start listener on specified address/port with given SCTP options and socket configuration
func listenSCTPExtConfig(network string, laddr *SCTPAddr, options InitMsg, control func(network, address string, c syscall.RawConn) error, notificationHandler NotificationHandler, preAssociation PreAssociationConfig) (*SCTPListener, error) {
	network, _, err := canonicalNetwork(network)
	if err != nil {
		return nil, err
	}
	if laddr != nil {
		if err := laddr.validateNetworkFamily(network); err != nil {
			return nil, err
		}
	}
	prepared, err := preparePreAssociationConfig(preAssociation, preAssociationOneToOne)
	if err != nil {
		return nil, err
	}

	af, ipv6only := favoriteAddrFamily(network, laddr, nil, "listen")
	sock, err := syscall.Socket(
		af,
		syscall.SOCK_STREAM|syscall.SOCK_CLOEXEC,
		syscall.IPPROTO_SCTP,
	)
	if err != nil {
		return nil, err
	}

	// close socket on error
	defer func() {
		if err != nil && sock >= 0 {
			_ = closeSctpSocket(sock, establishTimeout)
		}
	}()
	if err = setDefaultSockopts(sock, af, ipv6only); err != nil {
		return nil, err
	}
	if control != nil {
		rc := rawConn{sockfd: sock}
		var localAddressString string
		if laddr != nil {
			localAddressString = laddr.String()
		}
		if err = control(network, localAddressString, rc); err != nil {
			return nil, err
		}
	}
	err = setInitOpts(sock, options)
	if err != nil {
		return nil, err
	}
	if err = applyPreparedPreAssociationConfig(sock, prepared); err != nil {
		return nil, err
	}

	if laddr != nil {
		if err = bindLocal(sock, laddr, af); err != nil {
			return nil, err
		}
	}
	// syscall.SOMAXCONN is a compile-time constant of 128 in Go, not the
	// running kernel's net.core.somaxconn, which has defaulted to 4096 since
	// Linux 5.4. Passing 128 caps the accept backlog an order of magnitude
	// below what the system allows, and a listener that is handed more
	// simultaneous INITs than that answers the excess with ABORT: the peer
	// sees ECONNREFUSED even though the listener is healthy and accepting.
	//
	// The kernel clamps whatever is passed to its own somaxconn, so asking
	// for more than it permits is safe and gets the configured maximum.
	backlog := syscall.SOMAXCONN
	if n, err := readSomaxconn(); err == nil && n > backlog {
		backlog = n
	}
	err = syscall.Listen(sock, backlog)
	if err != nil {
		return nil, err
	}
	ln, wrapErr := newSCTPListener(sock, notificationHandler)
	sock = -1 // newSCTPListener owns the descriptor on both success and error.
	if wrapErr != nil {
		err = wrapErr
		return nil, err
	}
	return ln, nil
}

// FileListener takes a file, dup's the underlying file descriptor, and returns
// a SCTPListener created from the dup'd fd.
func FileListener(file *os.File) (*SCTPListener, error) {
	if file == nil {
		return nil, syscall.EINVAL
	}
	r1, _, err := syscall.Syscall(syscall.SYS_FCNTL, file.Fd(), syscall.F_DUPFD_CLOEXEC, 0)
	if err != 0 {
		return nil, os.NewSyscallError("fcntl", err)
	}

	return newSCTPListener(int(r1), nil)
}

// AcceptSCTP waits for and returns the next SCTP connection to the listener.
func (ln *SCTPListener) AcceptSCTP() (*SCTPConn, error) {
	if ln == nil || ln.fd() < 0 || ln.raw == nil {
		return nil, errClosed("accept")
	}

	acceptedFD := -1
	var acceptErr error
	err := ln.raw.Read(func(fd uintptr) bool {
		for {
			acceptedFD, _, acceptErr = syscall.Accept4(int(fd),
				syscall.SOCK_NONBLOCK|syscall.SOCK_CLOEXEC)
			if errors.Is(acceptErr, syscall.EINTR) {
				continue
			}
			if errors.Is(acceptErr, syscall.EAGAIN) ||
				errors.Is(acceptErr, syscall.EWOULDBLOCK) {
				return false
			}
			return true
		}
	})
	if err != nil {
		if ln.fd() < 0 {
			return nil, errClosed("accept")
		}
		return nil, normalizePollError("accept", err)
	}
	if acceptErr != nil {
		if ln.fd() < 0 {
			return nil, errClosed("accept")
		}
		return nil, acceptErr
	}
	conn, err := newSCTPConn(acceptedFD, ln.notificationHandler)
	if err != nil {
		// newSCTPConn owns acceptedFD on both success and error.
		return nil, err
	}
	return conn, nil
}

// Accept waits for and returns the next connection to the listener.
func (ln *SCTPListener) Accept() (net.Conn, error) {
	// Converted explicitly rather than returned straight through. A nil
	// *SCTPConn assigned to a net.Conn keeps its type word, so the result
	// compares unequal to nil and the idiomatic `if conn != nil` on an accept
	// failure is true — after which any use of it panics in (*SCTPConn).fd.
	// net.TCPListener.Accept does the same for the same reason, and an accept
	// deadline expiring is enough to reach it.
	c, err := ln.AcceptSCTP()
	if err != nil {
		return nil, err
	}
	return c, nil
}

// Close releases the listening socket.
//
// The descriptor is swapped out atomically, so concurrent or repeated calls
// report EBADF rather than closing the number a second time. That matters
// because the kernel reuses descriptor numbers: without it, a second Close
// could release a socket that had since been opened elsewhere in the process.
func (ln *SCTPListener) Close() error {
	if ln == nil {
		return errClosed("close")
	}
	if fd := atomic.SwapInt32(&ln._fd, -1); fd < 0 {
		return errClosed("close")
	}
	if ln.file == nil {
		return errClosed("close")
	}
	return normalizePollError("close", ln.file.Close())
}

func (ln *SCTPListener) SyscallConn() (syscall.RawConn, error) {
	if ln == nil || ln.fd() < 0 || ln.raw == nil {
		return nil, errClosed("syscallconn")
	}
	return &listenerRawConn{
		raw:      ln.raw,
		isClosed: func() bool { return ln.fd() < 0 },
	}, nil
}

// DialSCTP - bind socket to laddr (if given) and connect to raddr
func DialSCTP(net string, laddr, raddr *SCTPAddr) (*SCTPConn, error) {
	return DialSCTPExt(net, laddr, raddr, InitMsg{NumOstreams: SCTP_MAX_STREAM})
}

// DialSCTPExt - same as DialSCTP but with given SCTP options
func DialSCTPExt(network string, laddr, raddr *SCTPAddr, options InitMsg) (*SCTPConn, error) {
	return dialSCTPExtConfig(network, laddr, raddr, options, nil, nil, PreAssociationConfig{})
}

// dialSCTPExtConfig - same as DialSCTP but with given SCTP options and socket configuration
func dialSCTPExtConfig(network string, laddr, raddr *SCTPAddr, options InitMsg, control func(network, address string, c syscall.RawConn) error, notificationHandler NotificationHandler, preAssociation PreAssociationConfig) (*SCTPConn, error) {
	network, _, err := canonicalNetwork(network)
	if err != nil {
		return nil, err
	}
	if raddr == nil {
		return nil, &net.AddrError{Err: "missing remote SCTP address", Addr: "<nil>"}
	}
	for _, addr := range []*SCTPAddr{laddr, raddr} {
		if addr != nil {
			if err := addr.validateNetworkFamily(network); err != nil {
				return nil, err
			}
		}
	}
	prepared, err := preparePreAssociationConfig(preAssociation, preAssociationOneToOne)
	if err != nil {
		return nil, err
	}

	af, ipv6only := favoriteAddrFamily(network, laddr, raddr, "dial")
	sock, err := syscall.Socket(
		af,
		syscall.SOCK_STREAM|syscall.SOCK_CLOEXEC,
		syscall.IPPROTO_SCTP,
	)
	if err != nil {
		return nil, err
	}

	// close socket on error
	defer func() {
		if err != nil && sock >= 0 {
			_ = closeSctpSocket(sock, establishTimeout)
		}
	}()
	if err = setDefaultSockopts(sock, af, ipv6only); err != nil {
		return nil, err
	}
	if control != nil {
		rc := rawConn{sockfd: sock}
		if err = control(network, raddr.String(), rc); err != nil {
			return nil, err
		}
	}
	err = setInitOpts(sock, options)
	if err != nil {
		return nil, err
	}
	if err = applyPreparedPreAssociationConfig(sock, prepared); err != nil {
		return nil, err
	}
	if laddr != nil {
		// EADDRINUSE here means the source address and port are already taken.
		if err = bindLocal(sock, laddr, af); err != nil {
			return nil, err
		}
	}
	var viaEALREADY bool
	_, viaEALREADY, err = sctpConnect(sock, raddr)
	if err != nil {
		return nil, err
	}
	// A connect that completed normally needs nothing further: the kernel
	// waited for the handshake before returning, so the association is there.
	//
	// EALREADY is the exception. It is an early return that skips the kernel's
	// own wait, so it says the endpoint holds the association but not that the
	// handshake finished — and measured under signal load, one such dial in two
	// never established. This function owns the socket and returns a *SCTPConn,
	// so handing back one with nothing behind it would surface as a dial that
	// reported success and a first write that failed with EPIPE. Only this
	// branch is confirmed, and only it can pay the wait.
	if viaEALREADY && !waitEstablished(sock, connectSettleTimeout) {
		err = syscall.ETIMEDOUT
		return nil, err
	}
	conn, wrapErr := newSCTPConn(sock, notificationHandler)
	sock = -1 // newSCTPConn owns the descriptor on both success and error.
	if wrapErr != nil {
		err = wrapErr
		return nil, err
	}
	return conn, nil
}

// dialSCTPExtConfigContext is dialSCTPExtConfig with the wait under this
// function's control instead of the kernel's.
//
// The difference is SOCK_NONBLOCK. A blocking connect does not return until the
// kernel either completes the handshake or exhausts its own retransmission
// budget, so a caller that gives up at its own deadline can stop waiting but
// cannot stop the attempt: the association stays in COOKIE-WAIT, the scheduled
// INIT retransmission still goes out, and the descriptor is held until the
// kernel abandons it. A dial abandoned after one second was measured still
// emitting an INIT thirty seconds later.
//
// SCTP_INITMSG cannot express "send one INIT" either. MaxAttempts counts
// retransmissions rather than attempts and zero selects the kernel default, so
// the smallest usable value still puts a second INIT on the wire at
// net.sctp.rto_initial; MaxInitTimeout caps each RTO without bounding the total.
// So the bound has to come from here.
func dialSCTPExtConfigContext(ctx context.Context, network string, laddr, raddr *SCTPAddr, options InitMsg, control func(network, address string, c syscall.RawConn) error, notificationHandler NotificationHandler, preAssociation PreAssociationConfig, abandonPolicy DialAbandonPolicy) (*SCTPConn, error) {
	if ctx == nil {
		return nil, errNilContext
	}
	network, _, err := canonicalNetwork(network)
	if err != nil {
		return nil, err
	}
	if raddr == nil {
		return nil, &net.AddrError{Err: "missing remote SCTP address", Addr: "<nil>"}
	}
	for _, addr := range []*SCTPAddr{laddr, raddr} {
		if addr != nil {
			if err := addr.validateNetworkFamily(network); err != nil {
				return nil, err
			}
		}
	}

	// A context that is already done must not open a socket at all.
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := validateDialAbandonPolicy(abandonPolicy); err != nil {
		return nil, err
	}
	prepared, err := preparePreAssociationConfig(preAssociation, preAssociationOneToOne)
	if err != nil {
		return nil, err
	}

	af, ipv6only := favoriteAddrFamily(network, laddr, raddr, "dial")
	sock, err := syscall.Socket(
		af,
		syscall.SOCK_STREAM|syscall.SOCK_CLOEXEC|syscall.SOCK_NONBLOCK,
		syscall.IPPROTO_SCTP,
	)
	if err != nil {
		return nil, err
	}

	// The default is abort rather than close on every failure path. Nothing is
	// established, so there is no shutdown to negotiate, and an abort releases
	// the association at once instead of leaving the kernel retransmitting an
	// INIT on a socket the caller has already given up on. Some protocols still
	// require the caller's timeout to be a quiet local abandon, so the explicit
	// policy can select a plain close for the same non-established socket.
	established := false
	defer func() {
		if !established {
			_ = abandonDialSocket(sock, abandonPolicy)
		}
	}()

	if err = setDefaultSockopts(sock, af, ipv6only); err != nil {
		return nil, err
	}
	if control != nil {
		rc := rawConn{sockfd: sock}
		if err = control(network, raddr.String(), rc); err != nil {
			return nil, err
		}
	}
	if err = setInitOpts(sock, options); err != nil {
		return nil, err
	}
	if err = applyPreparedPreAssociationConfig(sock, prepared); err != nil {
		return nil, err
	}
	if laddr != nil {
		if err = bindLocal(sock, laddr, af); err != nil {
			return nil, err
		}
	}

	// On a non-blocking socket the handshake is started and EINPROGRESS comes
	// straight back; EALREADY would mean one is already under way. Neither is a
	// failure. The EALREADY settle the blocking path needs does not apply here,
	// because the wait below confirms establishment in every case rather than
	// trusting what connect returned.
	//
	// Tolerating EALREADY is defensive rather than load-bearing. This is the
	// first connect on a socket this function created, so the kernel has no
	// earlier attempt to find: 200 of 200 measured attempts against a
	// silent address returned EINPROGRESS and none returned EALREADY. What
	// keeps it here is the control hook above, which is handed the descriptor
	// and could have connected it. A mutation dropping the tolerance survives
	// the suite for the same reason the branch is unreachable.
	if _, _, err = sctpConnect(sock, raddr); err != nil &&
		!errors.Is(err, syscall.EINPROGRESS) && !errors.Is(err, syscall.EALREADY) {
		return nil, err
	}

	if err = awaitEstablished(ctx, sock); err != nil {
		return nil, err
	}

	established = true
	conn, err := newSCTPConn(sock, notificationHandler)
	if err != nil {
		// newSCTPConn owns and closes sock on failure.
		return nil, err
	}
	return conn, nil
}

// awaitEstablished waits for the handshake to finish or for ctx to be done,
// whichever comes first. It is waitEstablished with a context in place of a
// fixed timeout, and polls at the same interval.
func awaitEstablished(ctx context.Context, fd int) error {
	const interval = 2 * time.Millisecond

	tick := time.NewTicker(interval)
	defer tick.Stop()

	for {
		// A refused or aborted association surfaces through SO_ERROR rather
		// than through the connect, which returned before the peer answered.
		if errno, err := syscall.GetsockoptInt(fd, syscall.SOL_SOCKET,
			syscall.SO_ERROR); err == nil && errno != 0 {
			return syscall.Errno(errno)
		}
		// Checked before ctx so that a handshake which completed in the same
		// instant the deadline expired is not thrown away.
		if hasEstablishedAssoc(fd) {
			return nil
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-tick.C:
		}
	}
}

// DialSCTPContext is DialSCTPExt with a context. A nil context is rejected
// with an error wrapping syscall.EINVAL.
//
// The attempt is abandoned as soon as ctx is done: by default the association
// setup is aborted and the socket released before this returns, so no
// descriptor is left behind. Use DialSCTPContextWithAbandonPolicy with
// DialAbandonQuiet when the caller needs cancellation or timeout to release the
// local attempt without intentionally emitting a local ABORT for an association
// that never reached ESTABLISHED.
//
// DialSCTP, DialSCTPExt and SocketConfig.Dial are unchanged and still block for
// as long as the kernel's own retransmission budget.
func DialSCTPContext(ctx context.Context, network string, laddr, raddr *SCTPAddr, options InitMsg) (*SCTPConn, error) {
	return DialSCTPContextWithAbandonPolicy(ctx, network, laddr, raddr, options,
		DialAbandonAbort)
}

// DialSCTPContextWithAbandonPolicy is DialSCTPContext with explicit control
// over how a non-established attempt is released when the context expires or
// another pre-establishment error path returns.
func DialSCTPContextWithAbandonPolicy(
	ctx context.Context,
	network string,
	laddr, raddr *SCTPAddr,
	options InitMsg,
	policy DialAbandonPolicy,
) (*SCTPConn, error) {
	return dialSCTPExtConfigContext(ctx, network, laddr, raddr, options, nil, nil,
		PreAssociationConfig{}, policy)
}

// readSomaxconn reports the kernel's net.core.somaxconn, which bounds the
// accept backlog a listener may request. It is read rather than assumed
// because syscall.SOMAXCONN is a Go constant of 128 and has not tracked the
// kernel default since Linux 5.4 raised it to 4096.
func readSomaxconn() (int, error) {
	b, err := os.ReadFile("/proc/sys/net/core/somaxconn")
	if err != nil {
		return 0, err
	}
	n, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil {
		return 0, err
	}
	return n, nil
}

// peeloffArg mirrors sctp_peeloff_arg_t.
//
// Both members are 32 bits in the kernel — sctp_assoc_t is __s32 and sd is an
// int — so the struct is 8 bytes with sd at offset 4. The Go version used to
// declare sd as int, which is 64 bits on every target anyone runs this on. That
// made the struct 16 bytes with sd at offset 8, so the kernel wrote the new
// descriptor at offset 4 and PeelOff read offset 8, which nothing had written:
// it returned an SCTPConn wrapping descriptor 0, and leaked the real one.
//
// It went unnoticed because it is right on 32-bit, where Go's int is 32 bits,
// and because nothing tested it.
type peeloffArg struct {
	assocID int32
	sd      int32
}

// legacyPeelOffFD runs the descriptor-returning legacy peel-off operation
// under ForkLock and marks the result close-on-exec before releasing the read
// lock. Unlike SCTP_SOCKOPT_PEELOFF_FLAGS, SCTP_SOCKOPT_PEELOFF cannot request
// SOCK_CLOEXEC atomically. Without this lock, a concurrent fork/exec can run in
// the interval between getsockopt returning the new descriptor and
// CloseOnExec, leaking the association into the child process.
func legacyPeelOffFD(peelOff func() (int, error)) (int, error) {
	// See syscall.ForkLock: descriptor-creating operations without a CLOEXEC
	// variant take the read lock across creation and CloseOnExec. forkExec takes
	// the write lock while it snapshots the descriptor table.
	syscall.ForkLock.RLock()
	fd, err := peelOff()
	if err == nil && fd >= 0 {
		syscall.CloseOnExec(fd)
	}
	syscall.ForkLock.RUnlock()

	if err != nil {
		return -1, err
	}
	if fd < 0 {
		return -1, syscall.EINVAL
	}
	return fd, nil
}

// PeelOff detaches association id onto its own socket (RFC 6458 §9.2).
//
// This only works on a one-to-many (SOCK_SEQPACKET) socket, which is what
// peeling off is for: it turns one association out of many into a socket of its
// own. SCTPEndpoint.PeelOff is the package-owned typed path. Calling this method
// on a connection returned by Dial or Accept still returns EINVAL from the
// kernel — sctp_do_peeloff rejects their one-to-one style. NewSCTPConn remains
// the lower-level escape for a caller-owned one-to-many descriptor.
//
// A peeled socket looks one-to-one from userspace but is not one internally:
// sctp_do_peeloff builds it with sctp_clone_sock(..., SCTP_SOCKET_UDP_HIGH_BANDWIDTH).
// That matters at teardown, because sctp_shutdown opens with
// "if (!sctp_style(sk, TCP)) return" and so does nothing on this style. Close
// asks through the send path as well, which is the route that works here; see
// shutdownViaEOF.
//
// Without that second route Close was measurably wrong on these connections,
// with a capture on both sides:
//
//	                    ordinary conn   peeled, before   peeled, now
//	Close returned in   21.7us          3.005s           260us
//	SHUTDOWN on wire    1               0                1
//	ABORT on wire       0               1                0
//
// It ran the whole grace period out, because SCTP_STATUS kept reporting
// SCTP_ESTABLISHED and nothing told it the handshake had finished, and then fell
// back to the abort. So a caller asking for a graceful close got the opposite of
// one, three seconds later.
func (c *SCTPConn) PeelOff(id int) (*SCTPConn, error) {
	if c == nil || c.fd() < 0 || c.raw == nil {
		return nil, errClosed("getsockopt")
	}
	if c.initErr != nil {
		return nil, c.initErr
	}
	assocID, err := associationIDFromInt(id)
	if err != nil || !validEndpointAssociationID(assocID) {
		return nil, syscall.EINVAL
	}
	// SCTP_SOCKOPT_PEELOFF gives no way to ask for close-on-exec, so the
	// peeled descriptor would leak into any child forked afterwards — the same
	// defect accept4 had here. SCTP_SOCKOPT_PEELOFF_FLAGS exists for exactly
	// this and takes the same struct with a flags word appended. It is the
	// newer of the two, so an older kernel answering ENOPROTOOPT falls back
	// rather than failing the call.
	flagged := struct {
		arg   peeloffArg
		flags uint32
	}{arg: peeloffArg{assocID: int32(assocID)}, flags: syscall.SOCK_CLOEXEC}
	optlen := uint32(unsafe.Sizeof(flagged))
	_, _, err = c.getsockopt(SCTP_SOCKOPT_PEELOFF_FLAGS,
		uintptr(unsafe.Pointer(&flagged)), &optlen)
	if err == nil {
		if flagged.arg.sd < 0 {
			return nil, syscall.EINVAL
		}
		return newSCTPConn(int(flagged.arg.sd), c.notificationHandler)
	}
	if !errors.Is(err, syscall.ENOPROTOOPT) {
		return nil, err
	}

	fd, err := legacyPeelOffFD(func() (int, error) {
		param := peeloffArg{assocID: int32(assocID)}
		optlen := uint32(unsafe.Sizeof(param))
		_, _, err := c.getsockopt(SCTP_SOCKOPT_PEELOFF,
			uintptr(unsafe.Pointer(&param)), &optlen)
		return int(param.sd), err
	})
	if err != nil {
		return nil, err
	}
	return newSCTPConn(fd, c.notificationHandler)
}
