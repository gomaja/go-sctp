//go:build linux
// +build linux

package sctp

import (
	"errors"
	"net"
	"os"
	"os/exec"
	"syscall"
	"testing"
)

func TestFileListenerRejectsNilFile(t *testing.T) {
	if listener, err := FileListener(nil); listener != nil || err == nil {
		t.Fatalf("FileListener(nil) = (%v, %v), want (nil, error)", listener, err)
	}
}

func TestZeroValueConnectionNeverOwnsDescriptorZero(t *testing.T) {
	if mode := os.Getenv("GO_SCTP_FD0_MODE"); mode != "" {
		var conn SCTPConn
		var err error
		switch mode {
		case "close":
			err = conn.Close()
		case "abort":
			err = conn.Abort()
		case "owned":
			owned := NewSCTPConn(0, nil)
			if owned.initErr != nil {
				t.Fatalf("NewSCTPConn(0): %v", owned.initErr)
			}
			_ = owned.Abort()
			if _, _, errno := syscall.Syscall(syscall.SYS_FCNTL, 0, syscall.F_GETFD, 0); errno != syscall.EBADF {
				t.Fatalf("owned descriptor 0 remains open: fcntl = %v", errno)
			}
			return
		default:
			t.Fatalf("unknown helper mode %q", mode)
		}
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("zero-value %s = %v, want net.ErrClosed", mode, err)
		}
		if _, _, errno := syscall.Syscall(syscall.SYS_FCNTL, 0, syscall.F_GETFD, 0); errno != 0 {
			t.Fatalf("zero-value %s changed descriptor 0: fcntl = %v", mode, errno)
		}
		return
	}

	for _, mode := range []string{"close", "abort", "owned"} {
		t.Run(mode, func(t *testing.T) {
			reader, writer, err := os.Pipe()
			if err != nil {
				t.Fatalf("pipe: %v", err)
			}
			defer func() { _ = reader.Close() }()
			defer func() { _ = writer.Close() }()

			cmd := exec.Command(os.Args[0], "-test.run=^TestZeroValueConnectionNeverOwnsDescriptorZero$")
			cmd.Env = append(os.Environ(), "GO_SCTP_FD0_MODE="+mode)
			cmd.Stdin = reader
			output, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("helper %s: %v\n%s", mode, err, output)
			}
		})
	}
}

func TestNewSCTPConnSetsCloseOnExec(t *testing.T) {
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		t.Fatalf("socketpair: %v", err)
	}
	defer func() { _ = syscall.Close(fds[1]) }()

	conn := NewSCTPConn(fds[0], nil)
	if conn.initErr != nil {
		t.Fatalf("NewSCTPConn: %v", conn.initErr)
	}
	defer func() { _ = conn.file.Close() }()

	flags, _, errno := syscall.Syscall(syscall.SYS_FCNTL,
		uintptr(conn.fd()), syscall.F_GETFD, 0)
	if errno != 0 {
		t.Fatalf("fcntl(F_GETFD): %v", errno)
	}
	if flags&syscall.FD_CLOEXEC == 0 {
		t.Fatal("NewSCTPConn left its owned descriptor open across exec")
	}
}

func TestCloseOnExecRunsUnderForkLock(t *testing.T) {
	called := false
	closeOnExecUnderForkLock(42, func(fd int) {
		called = true
		if fd != 42 {
			t.Errorf("close-on-exec callback fd = %d, want 42", fd)
		}
		if syscall.ForkLock.TryLock() {
			syscall.ForkLock.Unlock()
			t.Error("close-on-exec callback ran outside ForkLock")
		}
	})
	if !called {
		t.Fatal("close-on-exec callback was not called")
	}
	if !syscall.ForkLock.TryLock() {
		t.Fatal("closeOnExecUnderForkLock left ForkLock held")
	}
	syscall.ForkLock.Unlock()
}
