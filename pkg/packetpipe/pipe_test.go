package packetpipe

import (
	"net"
	"testing"
)

func TestAsyncPacketPipe(t *testing.T) {
	c1, c2 := AsyncPacketPipe()
	defer c1.Close()
	defer c2.Close()

	msg := []byte("hello wireguard")
	addr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 9000}

	n, err := c1.WriteTo(msg, addr)
	if err != nil {
		t.Fatal(err)
	}
	if n != len(msg) {
		t.Fatalf("wrote %d, want %d", n, len(msg))
	}

	buf := make([]byte, 1600)
	n, raddr, err := c2.ReadFrom(buf)
	if err != nil {
		t.Fatal(err)
	}
	if n != len(msg) {
		t.Fatalf("read %d, want %d", n, len(msg))
	}
	if string(buf[:n]) != string(msg) {
		t.Fatalf("got %q, want %q", buf[:n], msg)
	}
	if raddr.String() != addr.String() {
		t.Fatalf("addr %s, want %s", raddr, addr)
	}
}

func TestPipeBidirectional(t *testing.T) {
	c1, c2 := AsyncPacketPipe()
	defer c1.Close()
	defer c2.Close()

	addr := &net.UDPAddr{IP: net.ParseIP("10.0.0.1"), Port: 51820}

	// c1 -> c2
	c1.WriteTo([]byte("ping"), addr)
	buf := make([]byte, 1600)
	n, _, _ := c2.ReadFrom(buf)
	if string(buf[:n]) != "ping" {
		t.Fatal("c1->c2 failed")
	}

	// c2 -> c1
	c2.WriteTo([]byte("pong"), addr)
	n, _, _ = c1.ReadFrom(buf)
	if string(buf[:n]) != "pong" {
		t.Fatal("c2->c1 failed")
	}
}

func TestPipeClose(t *testing.T) {
	c1, c2 := AsyncPacketPipe()
	c1.Close()

	_, _, err := c1.ReadFrom(make([]byte, 100))
	if err != net.ErrClosed {
		t.Fatalf("expected ErrClosed, got %v", err)
	}

	_, err = c2.WriteTo([]byte("x"), &net.UDPAddr{})
	// Writing to peer of closed conn should not panic
	_ = err
}
