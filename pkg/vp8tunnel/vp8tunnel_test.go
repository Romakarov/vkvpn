package vp8tunnel

import (
	"testing"
	"time"
)

func TestEncodeDecodeDataFrame(t *testing.T) {
	payload := []byte("hello wireguard packet")
	frame := EncodeDataFrame(payload)

	if frame[0] != DataFrameMarker {
		t.Errorf("expected marker 0xFF, got 0x%02x", frame[0])
	}
	if len(frame) != DataHeaderLen+len(payload) {
		t.Errorf("expected frame len %d, got %d", DataHeaderLen+len(payload), len(frame))
	}

	decoded := DecodeDataFrame(frame)
	if decoded == nil {
		t.Fatal("decoded is nil")
	}
	if string(decoded) != string(payload) {
		t.Errorf("expected %q, got %q", payload, decoded)
	}
}

func TestDecodeKeepaliveFrame(t *testing.T) {
	// Real VP8 keyframe should return nil (it's a keepalive)
	data := DecodeDataFrame(vp8Keyframe)
	if data != nil {
		t.Errorf("expected nil for VP8 keyframe, got %v", data)
	}

	// Real VP8 interframe should return nil
	data = DecodeDataFrame(vp8Interframe)
	if data != nil {
		t.Errorf("expected nil for VP8 interframe, got %v", data)
	}
}

func TestDecodeTooShort(t *testing.T) {
	data := DecodeDataFrame([]byte{0xFF, 0x00})
	if data != nil {
		t.Error("expected nil for too-short frame")
	}
}

func TestDecodeZeroLength(t *testing.T) {
	frame := []byte{DataFrameMarker, 0, 0, 0, 0}
	data := DecodeDataFrame(frame)
	if data != nil {
		t.Error("expected nil for zero-length data frame")
	}
}

func TestDecodeBadLength(t *testing.T) {
	// Length says 100 but only 5 bytes of payload
	frame := []byte{DataFrameMarker, 0, 0, 0, 100, 1, 2, 3, 4, 5}
	data := DecodeDataFrame(frame)
	if data != nil {
		t.Error("expected nil for bad-length frame")
	}
}

func TestTunnelSendRecv(t *testing.T) {
	tunnel := New()
	defer tunnel.Close()

	// Use a channel to capture frames (thread-safe)
	frameCh := make(chan []byte, 100)
	tunnel.SendFrame = func(data []byte, _ time.Duration) error {
		cp := make([]byte, len(data))
		copy(cp, data)
		frameCh <- cp
		return nil
	}
	tunnel.Start(25)

	// Send data
	payload := []byte("test packet 12345")
	if err := tunnel.Send(payload); err != nil {
		t.Fatal(err)
	}

	// Wait for frame to be sent and collect
	time.Sleep(100 * time.Millisecond)

	// Drain channel
	var sentFrames [][]byte
	for {
		select {
		case f := <-frameCh:
			sentFrames = append(sentFrames, f)
		default:
			goto done
		}
	}
done:

	if len(sentFrames) == 0 {
		t.Fatal("no frames sent")
	}

	// Decode the sent frame
	found := false
	for _, frame := range sentFrames {
		data := DecodeDataFrame(frame)
		if data != nil && string(data) == string(payload) {
			found = true
			// Simulate receiving back
			tunnel.HandleIncomingFrame(frame)
			break
		}
	}
	if !found {
		t.Error("payload not found in sent frames")
	}

	// Should be able to Recv
	select {
	case data := <-tunnel.recvQueue:
		if string(data) != string(payload) {
			t.Errorf("expected %q, got %q", payload, data)
		}
	case <-time.After(200 * time.Millisecond):
		t.Error("timeout waiting for recv")
	}
}

func TestTunnelSendTooLarge(t *testing.T) {
	tunnel := New()
	defer tunnel.Close()

	big := make([]byte, MaxPayloadSize+1)
	err := tunnel.Send(big)
	if err == nil {
		t.Error("expected error for oversized payload")
	}
}

func TestTunnelClose(t *testing.T) {
	tunnel := New()
	tunnel.Close()

	err := tunnel.Send([]byte("test"))
	if err == nil {
		t.Error("expected error after close")
	}

	_, err = tunnel.Recv()
	if err == nil {
		t.Error("expected error after close")
	}
}

func TestKeepaliveFramesAreValid(t *testing.T) {
	// VP8 keyframe: first byte bit 0 should be 0 (keyframe)
	if vp8Keyframe[0]&0x01 != 0 {
		t.Error("VP8 keyframe should have bit 0 = 0")
	}

	// VP8 interframe: first byte bit 0 should be 1
	if vp8Interframe[0]&0x01 != 1 {
		t.Error("VP8 interframe should have bit 0 = 1")
	}

	// Neither should have 0xFF as first byte
	if vp8Keyframe[0] == DataFrameMarker {
		t.Error("VP8 keyframe should not start with 0xFF")
	}
	if vp8Interframe[0] == DataFrameMarker {
		t.Error("VP8 interframe should not start with 0xFF")
	}
}

func TestPacketConnReadWrite(t *testing.T) {
	tunnel := New()
	defer tunnel.Close()

	// Capture sent frames
	tunnel.SendFrame = func(data []byte, _ time.Duration) error {
		// Feed back to recv (loopback)
		tunnel.HandleIncomingFrame(data)
		return nil
	}
	tunnel.Start(25)

	pconn := NewPacketConn(tunnel)
	defer pconn.Close()

	// Write a packet
	payload := []byte("wireguard udp packet")
	n, err := pconn.WriteTo(payload, nil)
	if err != nil {
		t.Fatal(err)
	}
	if n != len(payload) {
		t.Errorf("expected %d bytes written, got %d", len(payload), n)
	}

	// Read it back (loopback)
	buf := make([]byte, 1600)
	n, addr, err := pconn.ReadFrom(buf)
	if err != nil {
		t.Fatal(err)
	}
	if string(buf[:n]) != string(payload) {
		t.Errorf("expected %q, got %q", payload, string(buf[:n]))
	}
	if addr == nil {
		t.Error("expected non-nil addr")
	}
}

func TestPacketConnLocalAddr(t *testing.T) {
	tunnel := New()
	pconn := NewPacketConn(tunnel)
	defer pconn.Close()

	addr := pconn.LocalAddr()
	if addr.Network() != "vp8" {
		t.Errorf("expected network 'vp8', got %q", addr.Network())
	}
}
