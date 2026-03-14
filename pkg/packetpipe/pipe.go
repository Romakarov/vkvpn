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
	pkt, ok := <-c.ch
	if !ok {
		return 0, nil, net.ErrClosed
	}
	n = copy(p, pkt.data)
	return n, pkt.addr, nil
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
	select {
	case c.peer.ch <- packet{data: buf, addr: addr}:
		return len(p), nil
	default:
		return len(p), nil
	}
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

func (c *pipeConn) LocalAddr() net.Addr                         { return c.local }
func (c *pipeConn) SetDeadline(_ time.Time) error               { return nil }
func (c *pipeConn) SetReadDeadline(_ time.Time) error           { return nil }
func (c *pipeConn) SetWriteDeadline(_ time.Time) error          { return nil }
