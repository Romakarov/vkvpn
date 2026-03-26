// Package packetpipe provides a simple async packet pipe (replaces connutil).
package packetpipe

import (
	"net"
	"sync"
	"time"
)

type packet struct {
	data []byte
	addr net.Addr
}

type pipeConn struct {
	ch     chan packet
	peer   *pipeConn
	mu     sync.Mutex
	closed bool
	local  net.Addr

	// Deadline support: a channel that is closed when the deadline fires
	readDone chan struct{}
	readMu   sync.Mutex
	readTimer *time.Timer
}

type dummyAddr struct{}

func (dummyAddr) Network() string { return "pipe" }
func (dummyAddr) String() string  { return "pipe" }

func AsyncPacketPipe() (net.PacketConn, net.PacketConn) {
	c1 := &pipeConn{ch: make(chan packet, 256), local: dummyAddr{}}
	c2 := &pipeConn{ch: make(chan packet, 256), local: dummyAddr{}}
	c1.peer = c2
	c2.peer = c1
	return c1, c2
}

func (c *pipeConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	c.readMu.Lock()
	done := c.readDone
	c.readMu.Unlock()

	if done != nil {
		select {
		case pkt, ok := <-c.ch:
			if !ok {
				return 0, nil, net.ErrClosed
			}
			return copy(p, pkt.data), pkt.addr, nil
		case <-done:
			return 0, nil, &net.OpError{Op: "read", Err: deadlineErr{}}
		}
	}

	pkt, ok := <-c.ch
	if !ok {
		return 0, nil, net.ErrClosed
	}
	return copy(p, pkt.data), pkt.addr, nil
}

func (c *pipeConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return 0, net.ErrClosed
	}
	c.mu.Unlock()

	// Check if peer is closed
	c.peer.mu.Lock()
	if c.peer.closed {
		c.peer.mu.Unlock()
		return 0, net.ErrClosed
	}
	c.peer.mu.Unlock()

	buf := make([]byte, len(p))
	copy(buf, p)
	defer func() {
		if r := recover(); r != nil {
			err = net.ErrClosed
		}
	}()
	c.peer.ch <- packet{data: buf, addr: addr}
	return len(p), nil
}

func (c *pipeConn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.closed {
		c.closed = true
		close(c.ch)
	}
	return nil
}

func (c *pipeConn) LocalAddr() net.Addr { return c.local }

func (c *pipeConn) SetDeadline(t time.Time) error {
	c.SetReadDeadline(t)
	return nil
}

func (c *pipeConn) SetReadDeadline(t time.Time) error {
	c.readMu.Lock()
	defer c.readMu.Unlock()

	// Cancel previous timer
	if c.readTimer != nil {
		c.readTimer.Stop()
		c.readTimer = nil
	}

	if t.IsZero() {
		c.readDone = nil
		return nil
	}

	d := time.Until(t)
	if d <= 0 {
		// Already past: signal immediately
		ch := make(chan struct{})
		close(ch)
		c.readDone = ch
		return nil
	}

	ch := make(chan struct{})
	c.readDone = ch
	c.readTimer = time.AfterFunc(d, func() { close(ch) })
	return nil
}

func (c *pipeConn) SetWriteDeadline(_ time.Time) error { return nil }

// deadlineErr implements net.Error for deadline exceeded
type deadlineErr struct{}

func (deadlineErr) Error() string   { return "i/o timeout" }
func (deadlineErr) Timeout() bool   { return true }
func (deadlineErr) Temporary() bool { return true }
