package main

import (
	"errors"
	"testing"
)

type fakeBufferSizer struct {
	writeSize int
	readSize  int
	calls     []string
	errors    map[string]error
}

func (f *fakeBufferSizer) record(call string) error {
	f.calls = append(f.calls, call)
	return f.errors[call]
}

func (f *fakeBufferSizer) SetWriteBuffer(size int) error {
	if err := f.record("set-write"); err != nil {
		return err
	}
	f.writeSize = size
	return nil
}

func (f *fakeBufferSizer) SetReadBuffer(size int) error {
	if err := f.record("set-read"); err != nil {
		return err
	}
	f.readSize = size
	return nil
}

func (f *fakeBufferSizer) GetWriteBuffer() (int, error) {
	return f.writeSize, f.record("get-write")
}

func (f *fakeBufferSizer) GetReadBuffer() (int, error) {
	return f.readSize, f.record("get-read")
}

func TestConfigureBuffersReadsEachConfiguredBuffer(t *testing.T) {
	conn := &fakeBufferSizer{writeSize: 111, readSize: 222}

	gotWrite, gotRead, err := configureBuffers(conn, 333, 444)
	if err != nil {
		t.Fatalf("configureBuffers: %v", err)
	}
	if gotWrite != 333 {
		t.Errorf("write buffer = %d, want 333", gotWrite)
	}
	if gotRead != 444 {
		t.Errorf("read buffer = %d, want 444", gotRead)
	}
	if got, want := conn.calls, []string{"set-write", "set-read", "get-write", "get-read"}; !equalStrings(got, want) {
		t.Errorf("calls = %v, want %v", got, want)
	}
}

func TestConfigureBuffersLeavesZeroRequestsUnchanged(t *testing.T) {
	conn := &fakeBufferSizer{writeSize: 111, readSize: 222}

	gotWrite, gotRead, err := configureBuffers(conn, 0, 0)
	if err != nil {
		t.Fatalf("configureBuffers: %v", err)
	}
	if gotWrite != 111 || gotRead != 222 {
		t.Errorf("buffers = (%d, %d), want (111, 222)", gotWrite, gotRead)
	}
	if got, want := conn.calls, []string{"get-write", "get-read"}; !equalStrings(got, want) {
		t.Errorf("calls = %v, want %v", got, want)
	}
}

func TestConfigureBuffersStopsAtEachError(t *testing.T) {
	wantErr := errors.New("boom")
	tests := []struct {
		name      string
		fail      string
		wantCalls []string
	}{
		{name: "set write", fail: "set-write", wantCalls: []string{"set-write"}},
		{name: "set read", fail: "set-read", wantCalls: []string{"set-write", "set-read"}},
		{name: "get write", fail: "get-write", wantCalls: []string{"set-write", "set-read", "get-write"}},
		{name: "get read", fail: "get-read", wantCalls: []string{"set-write", "set-read", "get-write", "get-read"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conn := &fakeBufferSizer{errors: map[string]error{tt.fail: wantErr}}
			_, _, err := configureBuffers(conn, 1, 1)
			if !errors.Is(err, wantErr) {
				t.Fatalf("error = %v, want wrapped %v", err, wantErr)
			}
			if !equalStrings(conn.calls, tt.wantCalls) {
				t.Errorf("calls = %v, want %v", conn.calls, tt.wantCalls)
			}
		})
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
