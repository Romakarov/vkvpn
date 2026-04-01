package vp8tunnel

import (
	"net"
	"time"
)

// dummyAddr implements net.Addr for the VP8 tunnel endpoint.
type dummyAddr struct{}

func (dummyAddr) Network() string { return "vp8" }
func (dummyAddr) String() string  { return "vp8-tunnel" }

// PacketConn wraps a VP8 Tunnel as a net.PacketConn.
// This allows WireGuard UDP packets to flow through the VP8 tunnel
// using the same interface as DTLS/TURN connections.
type PacketConn struct {
	tunnel   *Tunnel
	peer     net.Addr
	deadline time.Time
}

// NewPacketConn creates a net.PacketConn backed by a VP8 tunnel.
func NewPacketConn(tunnel *Tunnel) *PacketConn {
	return &PacketConn{
		tunnel: tunnel,
		peer:   dummyAddr{},
	}
}

// ReadFrom reads the next data packet from the VP8 tunnel.
// Returns the decoded payload as if it came from the peer address.
func (c *PacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	data, err := c.tunnel.Recv()
	if err != nil {
		return 0, nil, err
	}
	n = copy(p, data)
	return n, c.peer, nil
}

// WriteTo sends data through the VP8 tunnel.
// Packets must fit within MaxPayloadSize — fragmentation is not supported
// because the receiver has no reassembly and WireGuard requires intact packets.
// Oversized packets are silently dropped (not an error) to avoid killing the bridge.
// This should not happen in practice if the WG TUN MTU is set correctly (≤1000).
func (c *PacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	if len(p) > MaxPayloadSize {
		// Drop oversized packet — WireGuard MTU should be set low enough to prevent this.
		// Returning success avoids killing the bridge on a single oversized packet.
		return len(p), nil
	}
	if err := c.tunnel.Send(p); err != nil {
		return 0, err
	}
	return len(p), nil
}

// Close closes the underlying tunnel.
func (c *PacketConn) Close() error {
	c.tunnel.Close()
	return nil
}

// LocalAddr returns a dummy local address.
func (c *PacketConn) LocalAddr() net.Addr {
	return dummyAddr{}
}

// SetDeadline sets read and write deadlines (best-effort, tunnel is channel-based).
func (c *PacketConn) SetDeadline(t time.Time) error {
	c.deadline = t
	return nil
}

// SetReadDeadline sets the read deadline.
func (c *PacketConn) SetReadDeadline(t time.Time) error {
	c.deadline = t
	return nil
}

// SetWriteDeadline sets the write deadline (no-op for channel-based writes).
func (c *PacketConn) SetWriteDeadline(t time.Time) error {
	return nil
}
