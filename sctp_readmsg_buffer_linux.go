//go:build linux
// +build linux

package sctp

import (
	"errors"
	"sync"
)

// Cache only intermediate assembly storage, never caller-owned results. Four
// buffers per class bound idle payload storage to 424 KiB across all connections.
// Active reads borrow exclusively; neither cache misses nor returns wait for a
// buffer to become available. Larger records use uncached storage, so this is
// not a limit on the accepted message size.
var readMsgBuffers = [...]readMsgBufferCache{
	{size: 2048},
	{size: 8192},
	{size: 32768},
	{size: 65536},
}

type readMsgBufferCache struct {
	mu      sync.Mutex
	size    int
	buffers [4][]byte
	count   int
}

func (p *readMsgBufferCache) get() []byte {
	p.mu.Lock()
	if p.count > 0 {
		p.count--
		b := p.buffers[p.count]
		p.buffers[p.count] = nil
		p.mu.Unlock()
		return b
	}
	p.mu.Unlock()
	return make([]byte, p.size)
}

func (p *readMsgBufferCache) put(b []byte) {
	p.mu.Lock()
	if p.count < len(p.buffers) {
		p.buffers[p.count] = b[:cap(b)]
		p.count++
	}
	p.mu.Unlock()
}

func getReadMsgBuffer(size int) ([]byte, int) {
	for i := range readMsgBuffers {
		if size <= readMsgBuffers[i].size {
			return readMsgBuffers[i].get(), i
		}
	}
	return make([]byte, size), -1
}

// The poller callback can escape. A single call-owned state keeps its captures
// together, including during notification-handler re-entry. No connection or
// receive state is cached with the assembly storage.
type readMsgState struct {
	buf                     []byte
	drainBuf                []byte
	bufferClass             int
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
	immediateNotification   []byte
	completedReceive        bool
	partialNotificationErr  error
	partialApplicationErr   error
}

func (s *readMsgState) addError(err error) {
	if err == nil {
		return
	}
	if s.resultErr == nil {
		s.resultErr = err
		return
	}
	s.resultErr = errors.Join(s.resultErr, err)
}
