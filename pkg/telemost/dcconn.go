package telemost

import (
	"fmt"
	"net"
	"time"

	"github.com/pion/webrtc/v4"
)

// dummyAddr implements net.Addr for the DataChannel tunnel endpoint.
type dummyAddr struct{}

func (dummyAddr) Network() string { return "dc" }
func (dummyAddr) String() string  { return "dc-tunnel" }

// DCPacketConn wraps a WebRTC DataChannel as a net.PacketConn.
// This allows WireGuard UDP packets to flow through the DataChannel
// using the same interface as the VP8 tunnel.
type DCPacketConn struct {
	dc   *webrtc.DataChannel
	recv chan []byte
	done chan struct{}
	peer net.Addr
}

// NewDCPacketConn creates a net.PacketConn backed by a DataChannel.
func NewDCPacketConn(dc *webrtc.DataChannel, recv chan []byte, done chan struct{}) *DCPacketConn {
	return &DCPacketConn{
		dc:   dc,
		recv: recv,
		done: done,
		peer: dummyAddr{},
	}
}

// ReadFrom reads the next data packet from the DataChannel.
func (c *DCPacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	select {
	case data, ok := <-c.recv:
		if !ok {
			return 0, nil, fmt.Errorf("datachannel closed")
		}
		n = copy(p, data)
		return n, c.peer, nil
	case <-c.done:
		return 0, nil, fmt.Errorf("datachannel closed")
	}
}

// WriteTo sends data through the DataChannel.
func (c *DCPacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	select {
	case <-c.done:
		return 0, fmt.Errorf("datachannel closed")
	default:
	}
	if err := c.dc.Send(p); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *DCPacketConn) Close() error {
	return c.dc.Close()
}

func (c *DCPacketConn) LocalAddr() net.Addr {
	return dummyAddr{}
}

func (c *DCPacketConn) SetDeadline(t time.Time) error      { return nil }
func (c *DCPacketConn) SetReadDeadline(t time.Time) error   { return nil }
func (c *DCPacketConn) SetWriteDeadline(t time.Time) error  { return nil }
