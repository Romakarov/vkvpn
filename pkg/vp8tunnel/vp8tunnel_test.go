package vp8tunnel

import (
	"testing"
	"time"

	"github.com/pion/rtp"
	"github.com/pion/rtp/codecs"
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
	// VP8 keyframe: should have start code at bytes 3-5
	if vp8Keyframe[3] != 0x9d || vp8Keyframe[4] != 0x01 || vp8Keyframe[5] != 0x2a {
		t.Error("VP8 keyframe should have start code 0x9d012a at bytes 3-5")
	}

	// VP8 interframe: first byte bit 0 should be 1
	if vp8Interframe[0]&0x01 != 1 {
		t.Error("VP8 interframe should have bit 0 = 1")
	}

	// Neither should have 0xFF as first byte (would conflict with our data marker)
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

// TestRTPRoundtrip verifies that data survives encode → VP8 RTP packetize → depacketize → decode.
// This simulates the real WebRTC pipeline where pion adds VP8 payload descriptors.
func TestRTPRoundtrip(t *testing.T) {
	payload := []byte("wireguard handshake initiation packet data")
	frame := EncodeDataFrame(payload)

	// Simulate VP8 RTP packetization (what pion/webrtc does in WriteSample):
	// VP8 packetizer adds a VP8 payload descriptor before the frame.
	payloadDescriptor := codecs.VP8Packet{
		S:   1,  // start of partition
		PID: 0,  // partition 0
	}
	// Build RTP payload: [VP8 descriptor][frame data]
	rtpPayload := make([]byte, 0, 1+len(frame))
	// Minimal VP8 payload descriptor: 1 byte with S=1
	// S=1, PID=0 → 0x10
	rtpPayload = append(rtpPayload, 0x10)
	rtpPayload = append(rtpPayload, frame...)
	_ = payloadDescriptor // used only for documentation

	// Build full RTP packet
	pkt := &rtp.Packet{
		Header: rtp.Header{
			Version:        2,
			Marker:         true, // end of frame
			PayloadType:    96,
			SequenceNumber: 1,
			Timestamp:      3000,
			SSRC:           12345,
		},
		Payload: rtpPayload,
	}
	rtpBytes, err := pkt.Marshal()
	if err != nil {
		t.Fatalf("RTP marshal: %v", err)
	}

	// Now depacketize (what readIncomingTrack should do):
	// 1. Unmarshal RTP
	rxPkt := &rtp.Packet{}
	if err := rxPkt.Unmarshal(rtpBytes); err != nil {
		t.Fatalf("RTP unmarshal: %v", err)
	}

	// 2. Strip VP8 payload descriptor
	vp8Pkt := &codecs.VP8Packet{}
	vp8Payload, err := vp8Pkt.Unmarshal(rxPkt.Payload)
	if err != nil {
		t.Fatalf("VP8 unmarshal: %v", err)
	}
	if vp8Pkt.S != 1 {
		t.Errorf("expected S=1, got S=%d", vp8Pkt.S)
	}

	// 3. Decode data frame
	decoded := DecodeDataFrame(vp8Payload)
	if decoded == nil {
		t.Fatal("decoded is nil — data frame not recognized after RTP depacketization")
	}
	if string(decoded) != string(payload) {
		t.Errorf("expected %q, got %q", payload, decoded)
	}
}

// TestFrameReassembly verifies that a VP8 frame split across multiple RTP packets
// can be correctly reassembled before decoding.
func TestFrameReassembly(t *testing.T) {
	// Create a larger payload that would be split across 2 RTP packets
	payload := make([]byte, 800)
	for i := range payload {
		payload[i] = byte(i % 256)
	}
	frame := EncodeDataFrame(payload)

	// Split frame into two parts (simulating RTP fragmentation)
	mid := len(frame) / 2
	part1 := frame[:mid]
	part2 := frame[mid:]

	// RTP packet 1: S=1, Marker=false (start of frame, not end)
	rtpPayload1 := append([]byte{0x10}, part1...) // S=1, PID=0
	pkt1 := &rtp.Packet{
		Header: rtp.Header{
			Version: 2, Marker: false, PayloadType: 96,
			SequenceNumber: 1, Timestamp: 3000, SSRC: 12345,
		},
		Payload: rtpPayload1,
	}

	// RTP packet 2: S=0, Marker=true (continuation, end of frame)
	rtpPayload2 := append([]byte{0x00}, part2...) // S=0, PID=0
	pkt2 := &rtp.Packet{
		Header: rtp.Header{
			Version: 2, Marker: true, PayloadType: 96,
			SequenceNumber: 2, Timestamp: 3000, SSRC: 12345,
		},
		Payload: rtpPayload2,
	}

	// Reassemble (same logic as readIncomingTrack)
	var frameBuf []byte

	for _, pkt := range []*rtp.Packet{pkt1, pkt2} {
		raw, _ := pkt.Marshal()
		rxPkt := &rtp.Packet{}
		rxPkt.Unmarshal(raw)

		vp8Pkt := &codecs.VP8Packet{}
		vp8Payload, err := vp8Pkt.Unmarshal(rxPkt.Payload)
		if err != nil {
			t.Fatalf("VP8 unmarshal: %v", err)
		}

		if vp8Pkt.S == 1 {
			frameBuf = make([]byte, 0, 2048)
		}
		if frameBuf != nil {
			frameBuf = append(frameBuf, vp8Payload...)
		}

		if rxPkt.Marker && frameBuf != nil {
			decoded := DecodeDataFrame(frameBuf)
			if decoded == nil {
				t.Fatal("decoded is nil after frame reassembly")
			}
			if len(decoded) != len(payload) {
				t.Errorf("expected payload len %d, got %d", len(payload), len(decoded))
			}
			for i := 0; i < len(payload); i++ {
				if decoded[i] != payload[i] {
					t.Errorf("payload mismatch at byte %d: expected 0x%02x, got 0x%02x", i, payload[i], decoded[i])
					break
				}
			}
			frameBuf = nil
		}
	}
}

// TestKeepaliveFramesThroughRTP verifies that VP8 keepalive frames
// are correctly identified as non-data after RTP round-trip.
func TestKeepaliveFramesThroughRTP(t *testing.T) {
	for _, tc := range []struct {
		name  string
		frame []byte
	}{
		{"keyframe", vp8Keyframe},
		{"interframe", vp8Interframe},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rtpPayload := append([]byte{0x10}, tc.frame...)
			pkt := &rtp.Packet{
				Header: rtp.Header{
					Version: 2, Marker: true, PayloadType: 96,
					SequenceNumber: 1, Timestamp: 3000, SSRC: 12345,
				},
				Payload: rtpPayload,
			}
			raw, _ := pkt.Marshal()

			rxPkt := &rtp.Packet{}
			rxPkt.Unmarshal(raw)

			vp8Pkt := &codecs.VP8Packet{}
			vp8Payload, err := vp8Pkt.Unmarshal(rxPkt.Payload)
			if err != nil {
				t.Fatalf("VP8 unmarshal: %v", err)
			}

			decoded := DecodeDataFrame(vp8Payload)
			if decoded != nil {
				t.Errorf("expected nil for %s keepalive, got %d bytes", tc.name, len(decoded))
			}
		})
	}
}

// TestMinSendInterval verifies that the MinSendInterval constant is set.
func TestMinSendInterval(t *testing.T) {
	if MinSendInterval != 5*time.Millisecond {
		t.Errorf("expected MinSendInterval=5ms, got %v", MinSendInterval)
	}
}
