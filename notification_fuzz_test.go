// Copyright 2019 Wataru Ishida. All rights reserved.
// Copyright 2026 gomaja. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
// This file includes modifications by gomaja.

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
	"encoding/binary"
	"testing"
)

// FuzzParseNotification asserts the parser never panics and never returns a
// result aliasing its input. It is reachable directly from bytes off the
// wire, so a panic here is a remote crash.
//
// The fuzzer drives the notification type through a separate uint16
// argument rather than leaving it only in the byte slice: left there, the
// mutator almost never lands on an input that is both a recognised type and
// short enough to overflow, so a parser missing its length checks can
// survive a long fuzzing run. Splitting the type out makes every length of
// every known type reachable.
func FuzzParseNotification(f *testing.F) {
	types := []EventType{
		EventAssocChange, EventPeerAddrChange, EventRemoteError,
		EventShutdown, EventPartialDelivery, EventAdaptationIndication,
		EventAuthentication, EventSenderDry, EventStreamReset,
		EventAssocReset, EventStreamChange, EventSendFailed,
	}
	sizes := []int{0, 8, 11, 12, 13, 15, 16, 20, 24, 28, 32, 48, 148, 152}
	for _, typ := range types {
		for _, size := range sizes {
			f.Add(uint16(typ), notif(typ, size))
		}
	}
	f.Add(uint16(0), []byte{})
	f.Add(uint16(0xFFFF), []byte{0x01})
	f.Add(uint16(EventAssocChange), notifSized(EventAssocChange, NotificationReassemblyLimit+1, sizeAssocChange, 0))

	f.Fuzz(func(t *testing.T, typ uint16, body []byte) {
		// Stamp the type over the header so the fuzzer reaches every branch
		// instead of bouncing off the unknown-type case.
		b := body
		if len(b) >= notificationTypeOff+2 {
			b = append([]byte(nil), body...)
			binary.NativeEndian.PutUint16(b[notificationTypeOff:], typ)
		}
		orig := append([]byte(nil), b...)

		n, err := ParseNotification(b)
		if err != nil && n != nil {
			t.Fatalf("returned both a notification (%T) and an error (%v)", n, err)
		}
		if len(b) >= notificationHeaderSize {
			declared := binary.NativeEndian.Uint32(b[notificationLengthOff:])
			if declared < notificationHeaderSize && err == nil {
				t.Fatalf("accepted header declaring only %d bytes", declared)
			}
			if EventType(typ) == EventStreamReset &&
				declared >= sizeStreamResetEvent && declared <= uint32(len(b)) &&
				(declared-sizeStreamResetEvent)%2 != 0 && err == nil {
				t.Fatalf("accepted odd %d-byte stream-reset notification", declared)
			}
		}

		// The input must never be mutated by the parse itself, independent
		// of whatever the caller does with it afterward (TestParseNotification
		// Copies already covers the result's independence once b is reused).
		if !bytes.Equal(b, orig) {
			t.Fatalf("ParseNotification mutated its input: got % x, want % x", b, orig)
		}

		if n == nil {
			return
		}
		// A notification must never be returned from a buffer too short to
		// hold it: that is the read-past-the-end this parser exists to avoid.
		if len(b) < notificationHeaderSize {
			t.Fatalf("parsed %T from %d bytes, shorter than the header", n, len(b))
		}
		// The accessor must not panic either.
		_ = n.Type()

		// The result must never alias b: mutate b and check every byte
		// field the concrete type carries is unaffected. Flipping every bit
		// (rather than overwriting with a fixed value such as 0xFF)
		// guarantees each byte actually changes, even one the fuzzer
		// happened to set to that fixed value already.
		fields := notificationByteFields(n)
		saved := make([][]byte, len(fields))
		for i, fld := range fields {
			saved[i] = append([]byte(nil), fld...)
		}
		for i := range b {
			b[i] ^= 0xFF
		}
		fields = notificationByteFields(n)
		for i, fld := range fields {
			if !bytes.Equal(fld, saved[i]) {
				t.Fatalf("%T field %d aliased the input buffer", n, i)
			}
		}
	})
}

// notificationByteFields returns every []byte field a decoded Notification
// carries, so the fuzz target can check none of them alias the input buffer
// without a type switch at every call site.
func notificationByteFields(n Notification) [][]byte {
	switch v := n.(type) {
	case *AssocChange:
		return [][]byte{v.Info}
	case *RemoteError:
		return [][]byte{v.Data}
	case *SendFailed:
		return [][]byte{v.Data}
	case *UnknownNotification:
		return [][]byte{v.Data}
	default:
		return nil
	}
}
