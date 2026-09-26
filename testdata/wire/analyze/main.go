// Copyright 2026 gomaja. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Command analyze proves the package's SCTP wire behaviour from the capture
// testdata/wire/run.sh takes on the client host, claim by claim, against
// the facts the two test processes recorded: the ports each case used, the
// times of the API calls it made, and the counts it saw.
//
// It fails closed. A missing, unreadable or empty capture, a tshark that
// lacks a field it reads, a malformed or inconsistent field, a frame from
// an unknown host or larger than the path MTU allows, a claim with no facts
// or with no packet on its port: each fails the run, and none is ever
// reported as a skip.
//
// Usage:
//
//	analyze -capture sender.pcapng -facts facts.client.txt -facts facts.server.txt \
//		-mtu 1500 [-run REGEX] [-summary FILE]
//
// The capture is proven complete up to the sentinel the last case sends:
// an INIT to a port the server does not listen on, on each network. A
// capture holds each interface's packets in the order they crossed it, so
// every packet before a sentinel is in it. A claim that rests on the
// absence of a packet is checked only up to the earlier sentinel.
//
// Times are compared on one clock: both containers read the Docker host's
// kernel clock, the test processes through time.Now and the capture
// through the kernel's packet timestamps.
package main

import (
	"bufio"
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/netip"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Chunk types, RFC 9260 §3.2 and RFC 3758 §3.2.
const (
	chunkDATA             = 0
	chunkINIT             = 1
	chunkINITACK          = 2
	chunkSACK             = 3
	chunkHEARTBEAT        = 4
	chunkHEARTBEATACK     = 5
	chunkABORT            = 6
	chunkSHUTDOWN         = 7
	chunkSHUTDOWNACK      = 8
	chunkERROR            = 9
	chunkCOOKIEECHO       = 10
	chunkCOOKIEACK        = 11
	chunkSHUTDOWNCOMPLETE = 14
	chunkFORWARDTSN       = 192
)

var chunkNames = map[int]string{
	chunkDATA:             "DATA",
	chunkINIT:             "INIT",
	chunkINITACK:          "INIT ACK",
	chunkSACK:             "SACK",
	chunkHEARTBEAT:        "HEARTBEAT",
	chunkHEARTBEATACK:     "HEARTBEAT ACK",
	chunkABORT:            "ABORT",
	chunkSHUTDOWN:         "SHUTDOWN",
	chunkSHUTDOWNACK:      "SHUTDOWN ACK",
	chunkERROR:            "ERROR",
	chunkCOOKIEECHO:       "COOKIE ECHO",
	chunkCOOKIEACK:        "COOKIE ACK",
	chunkSHUTDOWNCOMPLETE: "SHUTDOWN COMPLETE",
	chunkFORWARDTSN:       "FORWARD TSN",
}

// tolerance absorbs the capture's microsecond timestamps and the instant
// between reading the clock and making the call.
const tolerance = time.Millisecond

// fields are the tshark fields read for every SCTP frame, in column order.
// The DATA fields have one occurrence per DATA chunk, the SACK and FORWARD
// TSN fields one per chunk of their type, and every chunk has one
// chunk_type occurrence, which is how they line up.
var fields = []string{
	"frame.number",
	"frame.time_epoch",
	"frame.len",
	"ip.src",
	"ip.dst",
	"sctp.srcport",
	"sctp.dstport",
	"sctp.chunk_type",
	"sctp.data_tsn_raw",
	"sctp.data_sid",
	"sctp.data_payload_proto_id",
	"sctp.data_u_bit",
	"sctp.data_i_bit",
	"sctp.sack_cumulative_tsn_ack_raw",
	"sctp.forward_tsn_tsn",
	"sctp.cause_code",
}

type dataChunk struct {
	tsn  uint32
	sid  uint16
	ppid uint32
	u, i bool
}

type frame struct {
	number       int
	at           time.Time
	length       int
	src, dst     netip.Addr
	sport, dport uint16
	chunks       []int
	data         []dataChunk
	sackCum      []uint32
	fwdTSN       []uint32
	causes       []uint16 // the error causes of every chunk, in order
}

func (f frame) count(chunk int) int {
	n := 0
	for _, c := range f.chunks {
		if c == chunk {
			n++
		}
	}
	return n
}

func (f frame) has(chunk int) bool { return f.count(chunk) != 0 }

// facts is every fact of every case: case, then key, then value.
type facts map[string]map[string]string

// env is everything the claims are checked against.
type env struct {
	frames     []frame
	facts      facts
	names      map[netip.Addr]string // client-a, client-b, server-a, server-b
	server     map[netip.Addr]bool
	captureEnd time.Time // the earlier sentinel: the capture is complete up to it
	sentinel   []frame
}

// claim is one proven property: its case's name, the number of consecutive
// server ports the case uses, and the check.
type claim struct {
	name  string
	ports int
	check func(r *claimRun)
}

type result struct {
	name  string
	err   error
	notes []string
}

func main() {
	var factFiles []string
	capture := flag.String("capture", "", "the client host's capture (pcapng)")
	flag.Func("facts", "a facts file from one test process (repeatable)", func(s string) error {
		factFiles = append(factFiles, s)
		return nil
	})
	mtu := flag.Int("mtu", 0, "the MTU of the captured interfaces")
	run := flag.String("run", "", "check only the claims matching this regular expression")
	summary := flag.String("summary", "", "also write the report to this file")
	flag.Parse()

	if err := mainErr(*capture, factFiles, *mtu, *run, *summary, os.Stdout); err != nil {
		fmt.Fprintf(os.Stderr, "analyze: %v\n", err)
		os.Exit(1)
	}
}

func mainErr(capture string, factFiles []string, mtu int, run, summary string, stdout io.Writer) error {
	if capture == "" || len(factFiles) == 0 || mtu <= 0 {
		return errors.New("-capture, -facts and -mtu are required")
	}
	filter, err := regexp.Compile(run)
	if err != nil {
		return fmt.Errorf("-run: %v", err)
	}
	if err := checkFields(); err != nil {
		return err
	}
	out, err := tsharkFields(capture)
	if err != nil {
		return err
	}
	frames, err := parseFrames(out)
	if err != nil {
		return err
	}
	fs, err := readFacts(factFiles)
	if err != nil {
		return err
	}
	e, err := newEnv(frames, fs, mtu)
	if err != nil {
		return err
	}
	results, err := analyze(e, claims, filter)
	if err != nil {
		return err
	}
	var report bytes.Buffer
	failed := writeReport(&report, e, results)
	if _, err := stdout.Write(report.Bytes()); err != nil {
		return err
	}
	if summary != "" {
		if err := os.WriteFile(summary, report.Bytes(), 0o644); err != nil {
			return err
		}
	}
	if failed != 0 {
		return fmt.Errorf("%d of %d claims failed", failed, len(results))
	}
	return nil
}

// checkFields fails unless this tshark knows every field read.
func checkFields() error {
	out, err := exec.Command("tshark", "-G", "fields").Output()
	if err != nil {
		return fmt.Errorf("tshark -G fields: %v", err)
	}
	known := map[string]bool{}
	for _, line := range strings.Split(string(out), "\n") {
		if cols := strings.Split(line, "\t"); len(cols) >= 3 {
			known[cols[2]] = true
		}
	}
	var missing []string
	for _, f := range fields {
		if !known[f] {
			missing = append(missing, f)
		}
	}
	if len(missing) != 0 {
		return fmt.Errorf("this tshark lacks the fields %s", strings.Join(missing, ", "))
	}
	return nil
}

// tsharkFields reads the capture's SCTP frames as tab-separated fields,
// with absolute TSNs.
func tsharkFields(capture string) (string, error) {
	if fi, err := os.Stat(capture); err != nil {
		return "", fmt.Errorf("capture: %v", err)
	} else if fi.Size() == 0 {
		return "", fmt.Errorf("capture %s is empty", capture)
	}
	args := []string{
		"-n", "-r", capture,
		"-o", "sctp.relative_tsns:FALSE",
		"-Y", "sctp",
		"-T", "fields",
		"-E", "separator=/t",
		"-E", "occurrence=a",
		"-E", "aggregator=,",
	}
	for _, f := range fields {
		args = append(args, "-e", f)
	}
	cmd := exec.Command("tshark", args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("tshark: %v: %s", err, strings.TrimSpace(stderr.String()))
	}
	return string(out), nil
}

// parseFrames parses tsharkFields' output. Every column must be present
// and well formed, and the per-chunk columns must agree with the chunk
// types.
func parseFrames(out string) ([]frame, error) {
	var frames []frame
	for n, line := range strings.Split(out, "\n") {
		if line == "" {
			continue
		}
		cols := strings.Split(line, "\t")
		if len(cols) != len(fields) {
			return nil, fmt.Errorf("line %d has %d columns, want %d", n+1, len(cols), len(fields))
		}
		f, err := parseFrame(cols)
		if err != nil {
			return nil, fmt.Errorf("line %d: %v", n+1, err)
		}
		frames = append(frames, f)
	}
	if len(frames) == 0 {
		return nil, errors.New("the capture holds no SCTP frame")
	}
	sort.SliceStable(frames, func(i, j int) bool { return frames[i].at.Before(frames[j].at) })
	return frames, nil
}

func parseFrame(c []string) (frame, error) {
	var f frame
	var err error
	if f.number, err = strconv.Atoi(c[0]); err != nil {
		return f, fmt.Errorf("frame.number %q", c[0])
	}
	if f.at, err = parseEpoch(c[1]); err != nil {
		return f, fmt.Errorf("frame %d: frame.time_epoch %q: %v", f.number, c[1], err)
	}
	if f.length, err = strconv.Atoi(c[2]); err != nil {
		return f, fmt.Errorf("frame %d: frame.len %q", f.number, c[2])
	}
	if f.src, err = netip.ParseAddr(c[3]); err != nil {
		return f, fmt.Errorf("frame %d: ip.src %q", f.number, c[3])
	}
	if f.dst, err = netip.ParseAddr(c[4]); err != nil {
		return f, fmt.Errorf("frame %d: ip.dst %q", f.number, c[4])
	}
	ports, err := uints(c[5]+","+c[6], 16)
	if err != nil || len(ports) != 2 {
		return f, fmt.Errorf("frame %d: ports %q %q", f.number, c[5], c[6])
	}
	f.sport, f.dport = uint16(ports[0]), uint16(ports[1])
	types, err := uints(c[7], 8)
	if err != nil || len(types) == 0 {
		return f, fmt.Errorf("frame %d: sctp.chunk_type %q", f.number, c[7])
	}
	for _, t := range types {
		f.chunks = append(f.chunks, int(t))
	}
	tsn, err1 := uints(c[8], 32)
	sid, err2 := uints(c[9], 16)
	ppid, err3 := uints(c[10], 32)
	u, err4 := bools(c[11])
	i, err5 := bools(c[12])
	if err := errors.Join(err1, err2, err3, err4, err5); err != nil {
		return f, fmt.Errorf("frame %d: DATA fields: %v", f.number, err)
	}
	n := f.count(chunkDATA)
	if len(tsn) != n || len(sid) != n || len(ppid) != n || len(u) != n || len(i) != n {
		return f, fmt.Errorf("frame %d: %d DATA chunks but %d TSNs, %d stream ids, %d PPIDs, %d U bits, %d I bits",
			f.number, n, len(tsn), len(sid), len(ppid), len(u), len(i))
	}
	for k := range n {
		f.data = append(f.data, dataChunk{tsn: uint32(tsn[k]), sid: uint16(sid[k]), ppid: uint32(ppid[k]), u: u[k], i: i[k]})
	}
	sack, err := uints(c[13], 32)
	if err != nil || len(sack) != f.count(chunkSACK) {
		return f, fmt.Errorf("frame %d: %d SACK chunks, cumulative TSN acks %q", f.number, f.count(chunkSACK), c[13])
	}
	for _, v := range sack {
		f.sackCum = append(f.sackCum, uint32(v))
	}
	fwd, err := uints(c[14], 32)
	if err != nil || len(fwd) != f.count(chunkFORWARDTSN) {
		return f, fmt.Errorf("frame %d: %d FORWARD TSN chunks, new cumulative TSNs %q", f.number, f.count(chunkFORWARDTSN), c[14])
	}
	for _, v := range fwd {
		f.fwdTSN = append(f.fwdTSN, uint32(v))
	}
	causes, err := uints(c[15], 16)
	if err != nil {
		return f, fmt.Errorf("frame %d: sctp.cause_code %q", f.number, c[15])
	}
	for _, v := range causes {
		f.causes = append(f.causes, uint16(v))
	}
	return f, nil
}

func splitValues(s string) []string {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	return strings.Split(s, ",")
}

func uints(s string, bits int) ([]uint64, error) {
	var out []uint64
	for _, v := range splitValues(s) {
		n, err := strconv.ParseUint(strings.TrimSpace(v), 0, bits)
		if err != nil {
			return nil, fmt.Errorf("%q: %v", v, err)
		}
		out = append(out, n)
	}
	return out, nil
}

func bools(s string) ([]bool, error) {
	var out []bool
	for _, v := range splitValues(s) {
		switch strings.ToLower(strings.TrimSpace(v)) {
		case "1", "true":
			out = append(out, true)
		case "0", "false":
			out = append(out, false)
		default:
			return nil, fmt.Errorf("boolean %q", v)
		}
	}
	return out, nil
}

// parseEpoch parses frame.time_epoch, seconds with a fraction, without
// going through a float.
func parseEpoch(s string) (time.Time, error) {
	whole, frac, _ := strings.Cut(s, ".")
	sec, err := strconv.ParseInt(whole, 10, 64)
	if err != nil {
		return time.Time{}, err
	}
	if len(frac) > 9 {
		frac = frac[:9]
	}
	frac += strings.Repeat("0", 9-len(frac))
	nsec, err := strconv.ParseInt(frac, 10, 64)
	if err != nil {
		return time.Time{}, err
	}
	return time.Unix(sec, nsec), nil
}

// readFacts reads "case key value" lines. A key recorded twice for one
// case is an error: each fact has one author.
func readFacts(paths []string) (facts, error) {
	fs := facts{}
	for _, p := range paths {
		f, err := os.Open(p)
		if err != nil {
			return nil, fmt.Errorf("facts: %v", err)
		}
		err = parseFacts(f, p, fs)
		_ = f.Close() // read only
		if err != nil {
			return nil, err
		}
	}
	return fs, nil
}

func parseFacts(r io.Reader, name string, fs facts) error {
	sc := bufio.NewScanner(r)
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		f := strings.Fields(line)
		if len(f) != 3 {
			return fmt.Errorf("%s:%d: %q is not \"case key value\"", name, n, line)
		}
		if fs[f[0]] == nil {
			fs[f[0]] = map[string]string{}
		}
		if _, dup := fs[f[0]][f[1]]; dup {
			return fmt.Errorf("%s:%d: %s %s recorded twice", name, n, f[0], f[1])
		}
		fs[f[0]][f[1]] = f[2]
	}
	return sc.Err()
}

// newEnv checks the frames against the hosts the setup facts name and
// the path MTU: a frame from any other host, or one longer than an
// Ethernet frame of that MTU (which segmentation offload would make), makes
// the capture unfit to prove anything. It then finds the sentinels.
func newEnv(frames []frame, fs facts, mtu int) (*env, error) {
	e := &env{frames: frames, facts: fs, names: map[netip.Addr]string{}, server: map[netip.Addr]bool{}}
	setup := fs["setup"]
	for _, key := range []string{"client_a", "client_b", "server_a", "server_b"} {
		a, err := netip.ParseAddr(setup[key])
		if err != nil {
			return nil, fmt.Errorf("setup fact %s = %q: %v", key, setup[key], err)
		}
		if _, dup := e.names[a]; dup {
			return nil, fmt.Errorf("setup: %v is named twice", a)
		}
		e.names[a] = strings.ReplaceAll(key, "_", "-")
		e.server[a] = strings.HasPrefix(key, "server")
	}
	const ethernetHeader = 14
	for _, f := range frames {
		if _, ok := e.names[f.src]; !ok {
			return nil, fmt.Errorf("frame %d comes from %v, which is neither host", f.number, f.src)
		}
		if _, ok := e.names[f.dst]; !ok {
			return nil, fmt.Errorf("frame %d goes to %v, which is neither host", f.number, f.dst)
		}
		if e.server[f.src] == e.server[f.dst] {
			return nil, fmt.Errorf("frame %d goes from %v to %v, the same host", f.number, f.src, f.dst)
		}
		if f.length > mtu+ethernetHeader {
			return nil, fmt.Errorf("frame %d is %d bytes, more than an MTU of %d allows: the capture saw an offloaded super-packet, not the packets on the wire", f.number, f.length, mtu)
		}
	}
	end, err := e.sentinels()
	if err != nil {
		return nil, err
	}
	e.captureEnd = end
	return e, nil
}

// sentinelCase is the last case of TestWire, which sends the sentinels.
const sentinelCase = "capture-sentinel"

// sentinels finds the sentinel INITs, one to each server address on the
// port the sentinel case names, and returns the earlier one's time: the
// capture is complete up to it.
func (e *env) sentinels() (time.Time, error) {
	port, err := strconv.ParseUint(e.facts[sentinelCase]["port"], 10, 16)
	if err != nil {
		return time.Time{}, fmt.Errorf("the sentinel case recorded no port: the capture is not proven complete")
	}
	var end time.Time
	for _, key := range []string{"server_a", "server_b"} {
		dst, _ := netip.ParseAddr(e.facts["setup"][key])
		var found *frame
		for i, f := range e.frames {
			if f.dst == dst && f.dport == uint16(port) && f.has(chunkINIT) {
				found = &e.frames[i]
				break
			}
		}
		if found == nil {
			return time.Time{}, fmt.Errorf("no sentinel INIT to %s: the capture is not proven complete", strings.ReplaceAll(key, "_", "-"))
		}
		if end.IsZero() || found.at.Before(end) {
			end = found.at
		}
		e.sentinel = append(e.sentinel, *found)
	}
	return end, nil
}

// analyze runs every claim that filter matches. A filter that matches no
// claim is an error, as is a case with facts that no claim checks.
func analyze(e *env, all []claim, filter *regexp.Regexp) ([]result, error) {
	known := map[string]bool{"setup": true, sentinelCase: true}
	var results []result
	for _, c := range all {
		known[c.name] = true
		if !filter.MatchString(c.name) {
			continue
		}
		results = append(results, runClaim(e, c))
	}
	if len(results) == 0 {
		return nil, fmt.Errorf("no claim matches %q", filter)
	}
	for name := range e.facts {
		if !known[name] {
			return nil, fmt.Errorf("facts for %q, which no claim checks", name)
		}
	}
	return results, nil
}

// claimFailure is what failf panics with; runClaim turns it into the
// claim's failure and lets every other panic through.
type claimFailure struct{ err error }

func runClaim(e *env, c claim) (res result) {
	r := &claimRun{env: e, name: c.name}
	res.name = c.name
	defer func() {
		res.notes = r.notes
		if p := recover(); p != nil {
			f, ok := p.(claimFailure)
			if !ok {
				panic(p)
			}
			res.err = f.err
		}
	}()
	r.facts = e.facts[c.name]
	if len(r.facts) == 0 {
		r.failf("no facts: the case did not run")
	}
	port := r.int("port")
	if port <= 0 || port > 0xffff-int64(c.ports) {
		r.failf("port %d", port)
	}
	for i := range c.ports {
		p := uint16(port) + uint16(i)
		r.ports = append(r.ports, p)
		if len(r.all(p)) == 0 {
			r.failf("no frame on port %d", p)
		}
	}
	c.check(r)
	return res
}

// claimRun is one claim being checked.
type claimRun struct {
	env   *env
	name  string
	facts map[string]string
	ports []uint16
	notes []string
}

func (r *claimRun) failf(format string, args ...any) {
	panic(claimFailure{fmt.Errorf(format, args...)})
}

func (r *claimRun) note(format string, args ...any) {
	r.notes = append(r.notes, fmt.Sprintf(format, args...))
}

func (r *claimRun) str(key string) string {
	v, ok := r.facts[key]
	if !ok {
		r.failf("no fact %s", key)
	}
	return v
}

func (r *claimRun) int(key string) int64 {
	n, err := strconv.ParseInt(r.str(key), 0, 64)
	if err != nil {
		r.failf("fact %s: %v", key, err)
	}
	return n
}

func (r *claimRun) uint32(key string) uint32 {
	n, err := strconv.ParseUint(r.str(key), 0, 32)
	if err != nil {
		r.failf("fact %s: %v", key, err)
	}
	return uint32(n)
}

func (r *claimRun) time(key string) time.Time { return time.Unix(0, r.int(key)) }

func (r *claimRun) duration(key string) time.Duration { return time.Duration(r.int(key)) }

// setupAddr is the address the setup facts give key ("server_b", say).
func (r *claimRun) setupAddr(key string) netip.Addr {
	a, err := netip.ParseAddr(r.env.facts["setup"][key])
	if err != nil {
		r.failf("setup fact %s: %v", key, err)
	}
	return a
}

// all is every frame of the case's association on port, either way: the
// client's frames to the server's port and the server's frames from it.
// Matching the port alone would also take in another association whose
// client-side ephemeral port happens to equal port.
func (r *claimRun) all(port uint16) []frame {
	var out []frame
	for _, f := range r.env.frames {
		if r.toServer(f, port) || r.fromServer(f, port) {
			out = append(out, f)
		}
	}
	return out
}

// out is every frame the client sent to the server's port; in, every frame
// the server sent from it.
func (r *claimRun) out(port uint16) []frame {
	var out []frame
	for _, f := range r.env.frames {
		if r.toServer(f, port) {
			out = append(out, f)
		}
	}
	return out
}

func (r *claimRun) in(port uint16) []frame {
	var out []frame
	for _, f := range r.env.frames {
		if r.fromServer(f, port) {
			out = append(out, f)
		}
	}
	return out
}

func (r *claimRun) toServer(f frame, port uint16) bool {
	return f.dport == port && r.env.server[f.dst]
}

func (r *claimRun) fromServer(f frame, port uint16) bool {
	return f.sport == port && r.env.server[f.src]
}

// with keeps the frames holding a chunk of type chunk.
func with(frames []frame, chunk int) []frame {
	var out []frame
	for _, f := range frames {
		if f.has(chunk) {
			out = append(out, f)
		}
	}
	return out
}

// after keeps the frames later than t.
func after(frames []frame, t time.Time) []frame {
	var out []frame
	for _, f := range frames {
		if f.at.After(t) {
			out = append(out, f)
		}
	}
	return out
}

// first is the first frame of frames holding chunk, failing when there
// is none.
func (r *claimRun) first(frames []frame, chunk int, what string) frame {
	for _, f := range frames {
		if f.has(chunk) {
			return f
		}
	}
	r.failf("no %s: %s", chunkNames[chunk], what)
	return frame{}
}

// dataWith is every DATA chunk with ppid in frames, with its frame.
type sentData struct {
	f frame
	d dataChunk
}

func dataWith(frames []frame, ppid uint32) []sentData {
	var out []sentData
	for _, f := range frames {
		for _, d := range f.data {
			if d.ppid == ppid {
				out = append(out, sentData{f, d})
			}
		}
	}
	return out
}

// distinctTSNs is the TSNs of sent, each once, in the order first sent.
func distinctTSNs(sent []sentData) []uint32 {
	seen := map[uint32]bool{}
	var out []uint32
	for _, s := range sent {
		if !seen[s.d.tsn] {
			seen[s.d.tsn] = true
			out = append(out, s.d.tsn)
		}
	}
	return out
}

// tsnAtLeast compares TSNs in serial number arithmetic (RFC 9260 §1.6).
func tsnAtLeast(a, b uint32) bool { return int32(a-b) >= 0 }

// maxTSN is the latest of tsns in serial number arithmetic.
func maxTSN(tsns []uint32) uint32 {
	m := tsns[0]
	for _, t := range tsns[1:] {
		if !tsnAtLeast(m, t) {
			m = t
		}
	}
	return m
}

// describe names a frame for the report: its number, direction and
// chunks, and its time relative to ref.
func (r *claimRun) describe(f frame, ref time.Time, refName string) string {
	var names []string
	for _, c := range f.chunks {
		n, ok := chunkNames[c]
		if !ok {
			n = fmt.Sprintf("chunk %d", c)
		}
		names = append(names, n)
	}
	return fmt.Sprintf("frame %d %s -> %s [%s] at %s%s", f.number, r.env.names[f.src], r.env.names[f.dst],
		strings.Join(names, ", "), refName, signed(f.at.Sub(ref)))
}

// signed renders d as a signed offset in milliseconds.
func signed(d time.Duration) string {
	ms := float64(d) / float64(time.Millisecond)
	if ms >= 0 {
		return fmt.Sprintf(" +%.3f ms", ms)
	}
	return fmt.Sprintf(" %.3f ms", ms)
}

// noABORT fails if frames holds an ABORT.
func (r *claimRun) noABORT(frames []frame) {
	if a := with(frames, chunkABORT); len(a) != 0 {
		r.failf("frame %d %s -> %s holds an ABORT", a[0].number, r.env.names[a[0].src], r.env.names[a[0].dst])
	}
}

// causeUserAbort is the User-Initiated Abort error cause (RFC 9260
// §3.3.10.12), which Linux puts in the ABORT a close with SO_LINGER and no
// linger time sends (net/sctp/socket.c: sctp_close, with
// sctp_make_abort_user in net/sctp/sm_make_chunk.c).
const causeUserAbort = 12

// userAbort fails unless f is a lone ABORT chunk carrying exactly the
// User-Initiated Abort cause.
func (r *claimRun) userAbort(f frame) {
	if len(f.chunks) != 1 || len(f.causes) != 1 || f.causes[0] != causeUserAbort {
		r.failf("frame %d: chunks %v with causes %v, want one ABORT carrying the User-Initiated Abort cause (%d)", f.number, f.chunks, f.causes, causeUserAbort)
	}
}

// covered fails unless the capture was still running at t: the absence of
// a packet before t proves nothing otherwise.
func (r *claimRun) covered(t time.Time, what string) {
	if r.env.captureEnd.Before(t) {
		r.failf("the capture is proven complete only up to %v before %s", t.Sub(r.env.captureEnd), what)
	}
}

// writeReport prints every result and a summary line, and returns how many
// claims failed.
func writeReport(w *bytes.Buffer, e *env, results []result) int {
	// Writes to a bytes.Buffer never fail.
	printf := func(format string, args ...any) { _, _ = fmt.Fprintf(w, format, args...) }
	for _, f := range e.sentinel {
		printf("sentinel: frame %d %s -> %s [INIT] to closed port %d; the capture is complete up to it\n", f.number, e.names[f.src], e.names[f.dst], f.dport)
	}
	failed := 0
	for _, res := range results {
		if res.err != nil {
			failed++
			printf("FAIL %s: %v\n", res.name, res.err)
		} else {
			printf("PASS %s\n", res.name)
		}
		for _, n := range res.notes {
			printf("     %s\n", n)
		}
	}
	printf("WIRE_SUMMARY claims=%d passed=%d failed=%d\n", len(results), len(results)-failed, failed)
	return failed
}
