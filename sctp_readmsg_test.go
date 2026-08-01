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
	"bytes"
	"errors"
	"syscall"
	"testing"
	"time"
)

// fill builds a message with position-dependent bytes, so a reassembly that
// splices fragments in the wrong order is detected rather than passing on a
// uniform payload.
func fill(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i*31 + i/251)
	}
	return b
}

// TestReadMsgSizeMaxMatrix walks message sizes against ReadMsg limits, with
// particular attention to the points where the internal buffer growth
// switches behaviour: the initial 2048-byte chunk, and max itself.
func TestReadMsgSizeMaxMatrix(t *testing.T) {
	client, server := eorPair(t)

	// These straddle ReadMsg's initial 2048-byte allocation and its doubling
	// points, where the growth arithmetic changes behaviour.
	sizes := []int{
		1, 2047, 2048, 2049,
		4095, 4096, 4097,
		8192, 20000,
	}
	maxes := []int{2048, 4096, 65536}

	for _, max := range maxes {
		for _, size := range sizes {
			msg := fill(size)
			if _, err := client.SCTPWrite(msg, nil); err != nil {
				t.Fatalf("write size=%d: %v", size, err)
			}

			got, _, err := server.ReadMsg(max)

			if size <= max {
				if err != nil {
					t.Errorf("size=%d max=%d: unexpected error %v", size, max, err)
					continue
				}
				if !bytes.Equal(got, msg) {
					t.Errorf("size=%d max=%d: payload mismatch (got %d bytes)",
						size, max, len(got))
				}
				continue
			}

			// size > max: must report ErrMsgTooLong with a correct prefix.
			if !errors.Is(err, ErrMsgTooLong) {
				t.Errorf("size=%d max=%d: err = %v, want ErrMsgTooLong", size, max, err)
			}
			if len(got) > max {
				t.Errorf("size=%d max=%d: returned %d bytes, over the limit",
					size, max, len(got))
			}
			if !bytes.HasPrefix(msg, got) {
				t.Errorf("size=%d max=%d: returned prefix does not match the message",
					size, max)
			}
		}
	}
}

// TestReadMsgExactMaxIsComplete pins the boundary case: a message whose
// length is exactly max is a complete message and must be reported as such,
// not as ErrMsgTooLong. The remainder-detection must not depend on whether
// the final fragment happened to fill the buffer.
func TestReadMsgExactMaxIsComplete(t *testing.T) {
	client, server := eorPair(t)

	for _, size := range []int{64, 2048, 4096, 9000} {
		msg := fill(size)
		if _, err := client.SCTPWrite(msg, nil); err != nil {
			t.Fatalf("write %d: %v", size, err)
		}

		got, _, err := server.ReadMsg(size) // max == len(msg)
		if err != nil {
			t.Errorf("size=%d max=%d: err = %v, want nil (message fits exactly)",
				size, size, err)
			continue
		}
		if !bytes.Equal(got, msg) {
			t.Errorf("size=%d: payload mismatch", size)
		}
	}
}

// TestReadMsgOneOverMax checks the other side of the boundary.
func TestReadMsgOneOverMax(t *testing.T) {
	client, server := eorPair(t)

	for _, max := range []int{64, 2048, 4096} {
		msg := fill(max + 1)
		if _, err := client.SCTPWrite(msg, nil); err != nil {
			t.Fatalf("write: %v", err)
		}

		got, _, err := server.ReadMsg(max)
		if !errors.Is(err, ErrMsgTooLong) {
			t.Errorf("max=%d: err = %v, want ErrMsgTooLong", max, err)
		}
		if len(got) != max {
			t.Errorf("max=%d: got %d bytes, want %d", max, len(got), max)
		}
	}
}

// TestReadMsgTooLongDrainsRemainder proves that an over-limit record cannot
// poison the framing of the next one. Returning at max without consuming to
// MSG_EOR makes the oversized tail look like a distinct application message.
func TestReadMsgTooLongDrainsRemainder(t *testing.T) {
	client, server := eorPair(t)

	oversized := fill(32 * 1024)
	next := []byte("message-after-oversized-record")
	if _, err := client.SCTPWrite(oversized, nil); err != nil {
		t.Fatalf("write oversized message: %v", err)
	}
	if _, err := client.SCTPWrite(next, nil); err != nil {
		t.Fatalf("write next message: %v", err)
	}

	got, _, err := server.ReadMsg(1024)
	if !errors.Is(err, ErrMsgTooLong) {
		t.Fatalf("oversized ReadMsg error = %v, want ErrMsgTooLong", err)
	}
	if !bytes.Equal(got, oversized[:1024]) {
		t.Fatal("oversized ReadMsg returned the wrong prefix")
	}

	got, _, err = server.ReadMsg(1024)
	if err != nil {
		t.Fatalf("ReadMsg after oversized record: %v", err)
	}
	if !bytes.Equal(got, next) {
		t.Fatalf("next message = %q, want %q", got, next)
	}
}

// TestZeroLengthSendIsRefusedByTheKernel pins what actually happens when a
// caller asks to send an empty message.
//
// This used to be TestReadMsgZeroLengthMessage, which set out to check that an
// empty message is delivered as one rather than mistaken for EOF — and opened
// with a guard that skipped when the write was refused. The write is always
// refused: sctp_sendmsg rejects a zero-length message with EINVAL, so the body
// had never run on Linux in the normal suite. Unlike
// the two AUTH skips, no second pass reached it either. A test that cannot run
// is not coverage, so it now asserts the contract that exists.
//
// SCTPWrite and SCTPWriteInfo pass the kernel's answer through: a caller asking
// for a zero-length SCTP message asked for something specific and is entitled to
// be told it is not available. Conn.Write is the one held to the net.Conn
// contract instead — see TestWriteWithZeroLengthBufferIsANoOp.
func TestZeroLengthSendIsRefusedByTheKernel(t *testing.T) {
	client, server := eorPair(t)

	pr := func(policy uint16, value uint32) *PrInfo {
		return &PrInfo{Policy: policy, Value: value}
	}
	tests := []struct {
		name string
		send func([]byte) (int, error)
	}{
		{"SCTPWrite defaults", func(b []byte) (int, error) {
			return client.SCTPWrite(b, nil)
		}},
		{"SCTPWrite SndRcvInfo", func(b []byte) (int, error) {
			return client.SCTPWrite(b, &SndRcvInfo{Stream: 0, PPID: 0x11223344})
		}},
		{"SCTPWriteInfo defaults", func(b []byte) (int, error) {
			return client.SCTPWriteInfo(b, nil, nil, nil)
		}},
		{"SCTPWriteInfo SndInfo", func(b []byte) (int, error) {
			return client.SCTPWriteInfo(b, &SndInfo{SID: 0, PPID: 0x55667788}, nil, nil)
		}},
		{"SCTPWriteInfo reliable PrInfo", func(b []byte) (int, error) {
			return client.SCTPWriteInfo(b, nil, pr(SCTPPrPolicyNone, 0), nil)
		}},
		{"SCTPWriteInfo TTL PrInfo", func(b []byte) (int, error) {
			return client.SCTPWriteInfo(b, nil, pr(SCTPPrPolicyTTL, 1000), nil)
		}},
		{"SCTPWriteInfo retransmit PrInfo", func(b []byte) (int, error) {
			return client.SCTPWriteInfo(b, nil, pr(SCTPPrPolicyRtx, 2), nil)
		}},
		{"SCTPWriteInfo priority PrInfo", func(b []byte) (int, error) {
			return client.SCTPWriteInfo(b, nil, pr(SCTPPrPolicyPrio, 7), nil)
		}},
		{"SCTPWriteInfo AuthInfo", func(b []byte) (int, error) {
			return client.SCTPWriteInfo(b, nil, nil, &AuthInfo{KeyNumber: 0})
		}},
		{"SCTPWriteInfo SndInfo and PrInfo", func(b []byte) (int, error) {
			return client.SCTPWriteInfo(b, &SndInfo{SID: 0},
				pr(SCTPPrPolicyTTL, 1000), nil)
		}},
		{"SCTPWriteInfo SndInfo and AuthInfo", func(b []byte) (int, error) {
			return client.SCTPWriteInfo(b, &SndInfo{SID: 0}, nil,
				&AuthInfo{KeyNumber: 0})
		}},
		{"SCTPWriteInfo PrInfo and AuthInfo", func(b []byte) (int, error) {
			return client.SCTPWriteInfo(b, nil, pr(SCTPPrPolicyTTL, 1000),
				&AuthInfo{KeyNumber: 0})
		}},
		{"SCTPWriteInfo all ancillary types", func(b []byte) (int, error) {
			return client.SCTPWriteInfo(b, &SndInfo{SID: 0},
				pr(SCTPPrPolicyTTL, 1000), &AuthInfo{KeyNumber: 0})
		}},
	}
	for _, tc := range tests {
		for _, payload := range []struct {
			name string
			data []byte
		}{
			{"nil", nil},
			{"empty", []byte{}},
		} {
			t.Run(tc.name+"/"+payload.name, func(t *testing.T) {
				n, err := tc.send(payload.data)
				if !errors.Is(err, syscall.EINVAL) {
					t.Errorf("send = (%d, %v), want EINVAL: the kernel refuses a "+
						"zero-length message", n, err)
				}
				if n != 0 {
					t.Errorf("send reported %d bytes", n)
				}
			})
		}
	}

	// And the refusal must leave the association usable — a rejected send that
	// disturbed the socket would be worse than the refusal. This peer read also
	// proves that no hidden dummy-byte messages were queued by an ancillary send:
	// any such record would arrive before want and fail the payload comparison.
	want := []byte("after-empty")
	if _, err := client.SCTPWrite(want, nil); err != nil {
		t.Fatalf("write after the refused sends: %v", err)
	}
	if err := server.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	got, _, err := server.ReadMsg(4096)
	if err != nil {
		t.Fatalf("ReadMsg: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("got %q, want %q", got, want)
	}
}

// FuzzReadMsg drives real messages through a real association, varying the
// message length and the ReadMsg limit. The invariant is total: either the
// full message comes back, or ErrMsgTooLong with a correct, bounded prefix.
func FuzzReadMsg(f *testing.F) {
	f.Add(1, 4096)
	f.Add(2048, 2048)
	f.Add(2049, 2048)
	f.Add(4096, 4096)
	f.Add(8192, 2048)
	f.Add(65535, 65536)

	client, server := eorPair(f)

	f.Fuzz(func(t *testing.T, size, max int) {
		// Keep the association usable: bound the inputs rather than
		// rejecting them, so more of the space is actually exercised.
		// Convert through uint before reducing so MinInt cannot overflow when
		// normalized. Every input maps to a bounded, deterministic case.
		size = int(uint(size) % 70000)
		max = int(uint(max) % 70000)
		if max == 0 {
			max = 1
		}

		msg := fill(size)
		if _, err := client.SCTPWrite(msg, nil); err != nil {
			t.Skipf("write %d: %v", size, err)
		}

		got, _, err := server.ReadMsg(max)

		switch {
		case size <= max:
			if err != nil {
				t.Fatalf("size=%d max=%d: unexpected err %v", size, max, err)
			}
			if !bytes.Equal(got, msg) {
				t.Fatalf("size=%d max=%d: payload mismatch, got %d bytes",
					size, max, len(got))
			}
		default:
			if !errors.Is(err, ErrMsgTooLong) {
				t.Fatalf("size=%d max=%d: err = %v, want ErrMsgTooLong",
					size, max, err)
			}
			if len(got) > max {
				t.Fatalf("size=%d max=%d: returned %d bytes, over limit",
					size, max, len(got))
			}
			if !bytes.HasPrefix(msg, got) {
				t.Fatalf("size=%d max=%d: prefix mismatch", size, max)
			}
		}
	})
}
