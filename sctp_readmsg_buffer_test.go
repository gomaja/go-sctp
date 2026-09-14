//go:build linux
// +build linux

package sctp

import (
	"bytes"
	"runtime"
	"sync"
	"testing"
)

// Cache exhaustion must allocate independent storage, not wait for an active
// read (which may itself be waiting for a re-entrant notification handler).
func TestReadMsgBufferCacheExclusiveAndBounded(t *testing.T) {
	for _, size := range []int{2048, 8192, 32768, 65536} {
		p := readMsgBufferCache{size: size}
		borrowed := make([][]byte, 12)
		for i := range borrowed {
			borrowed[i] = p.get()
			for j := range borrowed[i] {
				borrowed[i][j] = byte(i + 1)
			}
		}
		for i, b := range borrowed {
			if len(b) != size || cap(b) != size || !bytes.Equal(b, bytes.Repeat([]byte{byte(i + 1)}, size)) {
				t.Fatalf("size %d: borrowed buffer %d was aliased or incorrectly sized", size, i)
			}
			// ReadMsg may limit the visible length to the caller's maximum.
			p.put(b[:17])
		}
		if p.count != 4 {
			t.Fatalf("size %d: retained %d buffers, want 4", size, p.count)
		}
		for i := 0; i < 4; i++ {
			b := p.get()
			if len(b) != size || cap(b) != size {
				t.Fatalf("size %d: reused length %d capacity %d", size, len(b), cap(b))
			}
			for j := range b {
				b[j] = 0
			}
		}
		if p.count != 0 {
			t.Fatalf("borrowed buffers are still counted: %d", p.count)
		}
		for _, b := range p.buffers {
			if b != nil {
				t.Fatal("cache retained a reference to a borrowed buffer")
			}
		}
		// Reuse must avoid a payload allocation, even following collection.
		p.put(borrowed[0])
		runtime.GC()
		if allocs := testing.AllocsPerRun(100, func() { p.put(p.get()) }); allocs != 0 {
			t.Fatalf("warm cache allocates %g times", allocs)
		}
	}
}

func TestReadMsgBufferCacheConcurrent(t *testing.T) {
	p := readMsgBufferCache{size: 8192}
	var wg sync.WaitGroup
	for i := 1; i <= 32; i++ {
		wg.Add(1)
		go func(value byte) {
			defer wg.Done()
			for round := 0; round < 100; round++ {
				b := p.get()
				for j := range b {
					b[j] = value
				}
				runtime.Gosched()
				for _, got := range b {
					if got != value {
						t.Errorf("active buffer aliased: got %d want %d", got, value)
						return
					}
				}
				p.put(b)
			}
		}(byte(i))
	}
	wg.Wait()
	if p.count > 4 {
		t.Fatalf("concurrent returns exceeded cache bound: %d", p.count)
	}
}
