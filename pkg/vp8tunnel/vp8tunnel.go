// Package vp8tunnel encodes and decodes arbitrary data inside VP8 video frames.
//
// This allows tunneling data through WebRTC SFU servers (like Yandex Telemost)
// that don't inspect video content. The SFU simply forwards "video" between
// call participants — it can't block this without breaking all video calls.
//
// Protocol:
//   - Data frame:     [0xFF][4B length big-endian][payload]
//   - VP8 keyframe:   17-byte valid VP8 keyframe (keepalive, every 60 frames)
//   - VP8 interframe: 2-byte valid VP8 interframe (keepalive, between data)
//
// The 0xFF marker byte never appears in valid VP8:
//   - VP8 keyframes start with partition size (bit 0 = 0, so first byte is even)
//   - VP8 interframes start with partition size (bit 0 = 1, but 0xFF is not valid)
package vp8tunnel

import (
	"encoding/binary"
	"fmt"
	"sync"
	"time"
)

const (
	// DataFrameMarker distinguishes data frames from real VP8 frames.
	DataFrameMarker = 0xFF

	// DataHeaderLen is the overhead per data frame: [0xFF][4B length]
	DataHeaderLen = 5

	// MaxPayloadSize is the maximum payload per VP8 data frame.
	// VP8 frames in WebRTC are typically limited to ~1200 bytes (MTU - RTP overhead).
	MaxPayloadSize = 1100

	// DefaultFPS is the frame rate for keepalive VP8 frames.
	DefaultFPS = 25

	// KeyframeInterval is how often to send a real VP8 keyframe (in frames).
	KeyframeInterval = 60

	// SendQueueSize is the buffer size for outgoing data.
	SendQueueSize = 256

	// RecvQueueSize is the buffer size for incoming data.
	RecvQueueSize = 256
)

// Minimal valid VP8 frames for keepalive.
// These are the smallest valid VP8 frames that a SFU will accept and forward.
var (
	// vp8Keyframe is a minimal VP8 keyframe (I-frame).
	// Format: 3-byte frame tag + 7-byte key frame header + 7 bytes partition data
	vp8Keyframe = []byte{
		0x30, 0x01, 0x00, // frame tag: keyframe, version 0, show_frame=1, partition0 size=0
		0x9d, 0x01, 0x2a, // start code
		0x02, 0x00, // width = 2
		0x02, 0x00, // height = 2
		0x01, 0x34, 0x25, 0x9a, 0x00, 0x03, 0x70, // minimal partition data
	}

	// vp8Interframe is a minimal VP8 interframe (P-frame).
	vp8Interframe = []byte{
		0x31, 0x01, // frame tag: interframe, version 0, show_frame=1, partition0 size=0
	}
)

// Tunnel encodes and decodes data inside VP8 frames.
type Tunnel struct {
	sendQueue  chan []byte
	recvQueue  chan []byte
	done       chan struct{}
	closeOnce  sync.Once
	frameCount uint64

	// SendFrame is called to send a VP8 frame to the WebRTC track.
	// Must be set before calling Start().
	SendFrame func(data []byte, duration time.Duration) error
}

// New creates a new VP8 data tunnel.
func New() *Tunnel {
	return &Tunnel{
		sendQueue: make(chan []byte, SendQueueSize),
		recvQueue: make(chan []byte, RecvQueueSize),
		done:      make(chan struct{}),
	}
}

// Start begins the send loop, encoding data into VP8 frames at the given FPS.
// SendFrame must be set before calling Start.
func (t *Tunnel) Start(fps int) {
	if fps <= 0 {
		fps = DefaultFPS
	}
	interval := time.Second / time.Duration(fps)

	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-t.done:
				return

			case data := <-t.sendQueue:
				// Send data frame
				frame := EncodeDataFrame(data)
				if t.SendFrame != nil {
					t.SendFrame(frame, interval)
				}
				t.frameCount++

				// Send keyframe periodically
				if t.frameCount%KeyframeInterval == 0 {
					if t.SendFrame != nil {
						t.SendFrame(vp8Keyframe, interval)
					}
				}

			case <-ticker.C:
				// No data to send — send keepalive
				t.frameCount++
				var frame []byte
				if t.frameCount%KeyframeInterval == 0 {
					frame = vp8Keyframe
				} else {
					frame = vp8Interframe
				}
				if t.SendFrame != nil {
					t.SendFrame(frame, interval)
				}
			}
		}
	}()
}

// Send queues data for encoding into a VP8 frame and sending.
func (t *Tunnel) Send(data []byte) error {
	select {
	case <-t.done:
		return fmt.Errorf("tunnel closed")
	default:
	}
	if len(data) == 0 {
		return nil
	}
	if len(data) > MaxPayloadSize {
		return fmt.Errorf("payload too large: %d bytes (max %d)", len(data), MaxPayloadSize)
	}
	select {
	case t.sendQueue <- data:
		return nil
	case <-t.done:
		return fmt.Errorf("tunnel closed")
	}
}

// Recv returns the next decoded data packet from the tunnel.
// Blocks until data is available or tunnel is closed.
func (t *Tunnel) Recv() ([]byte, error) {
	select {
	case data := <-t.recvQueue:
		return data, nil
	case <-t.done:
		return nil, fmt.Errorf("tunnel closed")
	}
}

// HandleIncomingFrame processes a received VP8 frame, extracting data if present.
// Call this from the WebRTC OnTrack callback for each received RTP packet payload.
func (t *Tunnel) HandleIncomingFrame(payload []byte) {
	data := DecodeDataFrame(payload)
	if data == nil {
		return // keepalive frame, ignore
	}
	select {
	case t.recvQueue <- data:
	case <-t.done:
	default:
		// Drop packet if recv queue is full (backpressure)
	}
}

// Close stops the tunnel.
func (t *Tunnel) Close() {
	t.closeOnce.Do(func() {
		close(t.done)
	})
}

// Done returns a channel that's closed when the tunnel is closed.
func (t *Tunnel) Done() <-chan struct{} {
	return t.done
}

// --- Encoding/Decoding ---

// EncodeDataFrame wraps payload in a VP8 data frame: [0xFF][4B length][payload]
func EncodeDataFrame(payload []byte) []byte {
	frame := make([]byte, DataHeaderLen+len(payload))
	frame[0] = DataFrameMarker
	binary.BigEndian.PutUint32(frame[1:5], uint32(len(payload)))
	copy(frame[5:], payload)
	return frame
}

// DecodeDataFrame extracts data from a VP8 frame. Returns nil if it's a keepalive.
func DecodeDataFrame(frame []byte) []byte {
	if len(frame) < DataHeaderLen {
		return nil
	}
	if frame[0] != DataFrameMarker {
		return nil // real VP8 frame (keepalive)
	}
	dataLen := binary.BigEndian.Uint32(frame[1:5])
	if dataLen == 0 || int(dataLen) > len(frame)-DataHeaderLen {
		return nil
	}
	out := make([]byte, dataLen)
	copy(out, frame[DataHeaderLen:DataHeaderLen+int(dataLen)])
	return out
}
