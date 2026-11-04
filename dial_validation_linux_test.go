// Copyright 2026 gomaja. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package sctp

import (
	"encoding/binary"
	"errors"
	"math"
	"os"
	"strconv"
	"syscall"
	"testing"
)

func TestSetupFailedNotification(t *testing.T) {
	record := func(typ EventType, state AssocChangeState) []byte {
		b := make([]byte, sizeAssocChange)
		binary.NativeEndian.PutUint16(b[assocChangeTypeOff:], uint16(typ))
		binary.NativeEndian.PutUint32(b[assocChangeLengthOff:], uint32(len(b)))
		binary.NativeEndian.PutUint16(b[assocChangeStateOff:], uint16(state))
		return b
	}
	failed := record(EventAssocChange, AssocCantStart)
	for n := 0; n <= len(failed); n++ {
		t.Run("length/"+strconv.Itoa(n), func(t *testing.T) {
			if got := setupFailedNotification(failed[:n], msgNotification); got != (n >= 12) {
				t.Errorf("classification = %v, want %v", got, n >= 12)
			}
		})
	}
	for _, tc := range []struct {
		name  string
		b     []byte
		flags int
		want  bool
	}{
		{"data", failed, 0, false},
		{"unrelated flag", failed, syscall.MSG_EOR, false},
		{"notification with EOR", failed, msgNotification | syscall.MSG_EOR, true},
		{"notification with truncation", failed, msgNotification | syscall.MSG_TRUNC, true},
		{"preceding type", record(EventAssocChange-1, AssocCantStart), msgNotification, false},
		{"next type", record(EventAssocChange+1, AssocCantStart), msgNotification, false},
		{"COMM_UP", record(EventAssocChange, AssocCommUp), msgNotification, false},
		{"COMM_LOST", record(EventAssocChange, AssocCommLost), msgNotification, false},
		{"RESTART", record(EventAssocChange, AssocRestart), msgNotification, false},
		{"SHUTDOWN_COMP", record(EventAssocChange, AssocShutdownComplete), msgNotification, false},
		{"CANT_STR_ASSOC", failed, msgNotification, true},
		{"next state", record(EventAssocChange, AssocCantStart+1), msgNotification, false},
		{"unknown state", record(EventAssocChange, AssocChangeState(math.MaxUint16)), msgNotification, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := setupFailedNotification(tc.b, tc.flags); got != tc.want {
				t.Fatalf("classification = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestConnectxLength(t *testing.T) {
	for _, n := range []int{-1, 0, 1, 16, 28, math.MaxInt32 - 1, math.MaxInt32} {
		t.Run(strconv.Itoa(n), func(t *testing.T) {
			got, err := connectxLength(n)
			if n <= 0 {
				if !errors.Is(err, syscall.EINVAL) {
					t.Fatalf("connectxLength(%d) = %d, %v, want EINVAL", n, got, err)
				}
			} else if err != nil || got != int32(n) {
				t.Fatalf("connectxLength(%d) = %d, %v", n, got, err)
			}
		})
	}
	if strconv.IntSize == 64 {
		for _, n := range []int64{math.MaxInt32 + 1, math.MaxInt32 + 2, math.MaxInt64} {
			got, err := connectxLength(int(n))
			if !errors.Is(err, syscall.EINVAL) {
				t.Errorf("connectxLength(%d) = %d, %v, want EINVAL", n, got, err)
			}
		}
	}
}

func TestConnectxRejectsEmptyAddresses(t *testing.T) {
	var s socket
	for _, b := range [][]byte{nil, {}} {
		id, err := s.connectxID(b)
		if id != 0 || !errors.Is(err, syscall.EINVAL) {
			t.Fatalf("connectxID(empty) = %d, %v", id, err)
		}
	}
}

func TestFailedSetupErrorFailsClosed(t *testing.T) {
	err := failedSetupError(-1)
	var se *os.SyscallError
	if !errors.Is(err, syscall.EBADF) || !errors.As(err, &se) || se.Syscall != "getsockopt" {
		t.Fatalf("failedSetupError(-1) = %v, want getsockopt EBADF", err)
	}
	s, err := newSocket(afInet, "sctp4")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.file.Close() }()
	if err := s.control(func(fd int) error {
		err := failedSetupError(fd)
		if !errors.Is(err, syscall.ECONNREFUSED) || !errors.As(err, &se) || se.Syscall != "sctp_connectx" {
			t.Errorf("cleared SO_ERROR = %v, want sctp_connectx ECONNREFUSED", err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
