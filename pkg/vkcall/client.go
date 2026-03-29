// Package vkcall implements a Pion WebRTC client that joins a VK Call
// and establishes a VP8 data tunnel. VK uses P2P architecture (single
// PeerConnection), which is simpler than Telemost's SFU (pub/sub).
//
// Data flows as VP8 "video" inside a legitimate VK call. The VK SFU/TURN
// simply relays packets between call participants — it can't block the
// data without breaking all video calls.
package vkcall

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/Romakarov/vkvpn/pkg/turnauth"
	"github.com/Romakarov/vkvpn/pkg/vp8tunnel"
	"github.com/pion/webrtc/v4"
	"github.com/pion/webrtc/v4/pkg/media"
)

// Client joins a VK Call via Pion WebRTC and creates a VP8 tunnel.
type Client struct {
	logger *log.Logger
	pc     *webrtc.PeerConnection
	tunnel *vp8tunnel.Tunnel
	mu     sync.Mutex
	closed bool
	done   chan struct{}

	// OnTunnel is called when the VP8 tunnel is established.
	OnTunnel func(tunnel *vp8tunnel.Tunnel)
}

// NewClient creates a new VK Call client.
func NewClient(logger *log.Logger) *Client {
	return &Client{
		logger: logger,
		done:   make(chan struct{}),
	}
}

// JoinCall creates a VK call (using a VK account token), joins it,
// and establishes a VP8 data tunnel. Blocks until the call ends.
//
// accessToken is a VK OAuth token from the VKAccounts pool.
func (c *Client) JoinCall(ctx context.Context, accessToken string) error {
	c.logger.Printf("[vkcall] Creating VK call...")

	// Step 1: Create call and get TURN credentials + join link
	callInfo, err := turnauth.CreateVKCallAndGetCredentials(accessToken)
	if err != nil {
		return fmt.Errorf("create VK call: %w", err)
	}
	c.logger.Printf("[vkcall] Call created: join=%s turn=%s", callInfo.JoinLink, callInfo.Address)

	// Step 2: Build ICE servers from TURN URLs
	iceServers := []webrtc.ICEServer{{
		URLs:       callInfo.TURNURLs,
		Username:   callInfo.Username,
		Credential: callInfo.Password,
	}}

	// Step 3: Create PeerConnection (VK uses single PC, P2P)
	config := webrtc.Configuration{
		ICEServers:         iceServers,
		ICETransportPolicy: webrtc.ICETransportPolicyRelay, // TURN only
	}
	pc, err := webrtc.NewPeerConnection(config)
	if err != nil {
		return fmt.Errorf("new PeerConnection: %w", err)
	}
	c.pc = pc

	// Step 4: Add VP8 video track for data tunneling
	videoTrack, err := webrtc.NewTrackLocalStaticSample(
		webrtc.RTPCodecCapability{MimeType: webrtc.MimeTypeVP8},
		"video", "vkvpn-tunnel",
	)
	if err != nil {
		return fmt.Errorf("create VP8 track: %w", err)
	}
	if _, err := pc.AddTrack(videoTrack); err != nil {
		return fmt.Errorf("add track: %w", err)
	}

	// Step 5: Create VP8 tunnel and wire to track
	tunnel := vp8tunnel.New()
	tunnel.SendFrame = func(data []byte, duration time.Duration) error {
		return videoTrack.WriteSample(media.Sample{
			Data:     data,
			Duration: duration,
		})
	}
	tunnel.Start(vp8tunnel.DefaultFPS)
	c.tunnel = tunnel

	// Step 6: Handle incoming tracks
	pc.OnTrack(func(track *webrtc.TrackRemote, receiver *webrtc.RTPReceiver) {
		c.logger.Printf("[vkcall] Incoming track: %s codec=%s", track.ID(), track.Codec().MimeType)
		if track.Codec().MimeType == webrtc.MimeTypeVP8 {
			go c.readIncomingTrack(track)
		}
	})

	// Step 7: Monitor connection state
	connected := make(chan struct{}, 1)
	pc.OnConnectionStateChange(func(state webrtc.PeerConnectionState) {
		c.logger.Printf("[vkcall] Connection state: %s", state)
		if state == webrtc.PeerConnectionStateConnected {
			select {
			case connected <- struct{}{}:
			default:
			}
			if c.OnTunnel != nil {
				go c.OnTunnel(tunnel)
			}
		}
		if state == webrtc.PeerConnectionStateFailed || state == webrtc.PeerConnectionStateDisconnected {
			c.Close()
		}
	})

	// Step 8: Create offer and set as local description
	offer, err := pc.CreateOffer(nil)
	if err != nil {
		return fmt.Errorf("create offer: %w", err)
	}

	// Use GatheringComplete to get all ICE candidates before sending
	gatherDone := webrtc.GatheringCompletePromise(pc)
	if err := pc.SetLocalDescription(offer); err != nil {
		return fmt.Errorf("set local description: %w", err)
	}

	select {
	case <-gatherDone:
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(30 * time.Second):
		return fmt.Errorf("ICE gathering timeout")
	}

	c.logger.Printf("[vkcall] ICE gathering complete, SDP ready")

	// TODO: Signaling — exchange SDP offer/answer with the other participant.
	// Currently, the SDP is generated but NOT sent to anyone.
	// For VP8 tunnel to work, we need a signaling channel:
	//   Option A: HTTP API on server (POST /api/vp8/offer → GET /api/vp8/answer)
	//   Option B: Use OK.ru vchat.* API for SDP exchange (as the VK web client does)
	//   Option C: Out-of-band signaling (e.g. through our existing DTLS connection)
	// Until signaling is implemented, VP8 transport will NOT establish a connection.
	c.logger.Printf("[vkcall] WARNING: VP8 signaling not yet implemented — connection will not establish")
	c.logger.Printf("[vkcall] Waiting for peer connection...")

	// Wait for connection or context cancellation
	select {
	case <-connected:
		c.logger.Printf("[vkcall] VP8 tunnel ESTABLISHED through VK Call")
	case <-ctx.Done():
		return ctx.Err()
	case <-c.done:
		return fmt.Errorf("client closed")
	}

	// Block until call ends
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-c.done:
		return fmt.Errorf("call ended")
	}
}

// JoinLink joins an existing VK call by join link (for the client side).
// The joinHash is obtained from the server's appconfig.
func (c *Client) JoinLink(ctx context.Context, joinHash string) error {
	c.logger.Printf("[vkcall] Joining VK call: %s", joinHash)

	// Get TURN credentials from the join link (anonymous flow)
	creds, err := turnauth.GetVKCredentials(joinHash)
	if err != nil {
		return fmt.Errorf("get VK credentials: %w", err)
	}

	// Build minimal ICE servers
	iceServers := []webrtc.ICEServer{{
		URLs:       []string{"turn:" + creds.Address},
		Username:   creds.Username,
		Credential: creds.Password,
	}}

	// Same PeerConnection setup as JoinCall
	config := webrtc.Configuration{
		ICEServers:         iceServers,
		ICETransportPolicy: webrtc.ICETransportPolicyRelay,
	}
	pc, err := webrtc.NewPeerConnection(config)
	if err != nil {
		return fmt.Errorf("new PeerConnection: %w", err)
	}
	c.pc = pc

	videoTrack, err := webrtc.NewTrackLocalStaticSample(
		webrtc.RTPCodecCapability{MimeType: webrtc.MimeTypeVP8},
		"video", "vkvpn-tunnel",
	)
	if err != nil {
		return fmt.Errorf("create VP8 track: %w", err)
	}
	if _, err := pc.AddTrack(videoTrack); err != nil {
		return fmt.Errorf("add track: %w", err)
	}

	tunnel := vp8tunnel.New()
	tunnel.SendFrame = func(data []byte, duration time.Duration) error {
		return videoTrack.WriteSample(media.Sample{Data: data, Duration: duration})
	}
	tunnel.Start(vp8tunnel.DefaultFPS)
	c.tunnel = tunnel

	pc.OnTrack(func(track *webrtc.TrackRemote, receiver *webrtc.RTPReceiver) {
		if track.Codec().MimeType == webrtc.MimeTypeVP8 {
			go c.readIncomingTrack(track)
		}
	})

	connected := make(chan struct{}, 1)
	pc.OnConnectionStateChange(func(state webrtc.PeerConnectionState) {
		c.logger.Printf("[vkcall] Connection state: %s", state)
		if state == webrtc.PeerConnectionStateConnected {
			select {
			case connected <- struct{}{}:
			default:
			}
			if c.OnTunnel != nil {
				go c.OnTunnel(tunnel)
			}
		}
		if state == webrtc.PeerConnectionStateFailed || state == webrtc.PeerConnectionStateDisconnected {
			c.Close()
		}
	})

	offer, err := pc.CreateOffer(nil)
	if err != nil {
		return fmt.Errorf("create offer: %w", err)
	}
	gatherDone := webrtc.GatheringCompletePromise(pc)
	if err := pc.SetLocalDescription(offer); err != nil {
		return fmt.Errorf("set local description: %w", err)
	}

	select {
	case <-gatherDone:
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(30 * time.Second):
		return fmt.Errorf("ICE gathering timeout")
	}

	select {
	case <-connected:
		c.logger.Printf("[vkcall] VP8 tunnel ESTABLISHED")
	case <-ctx.Done():
		return ctx.Err()
	case <-c.done:
		return fmt.Errorf("client closed")
	}

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-c.done:
		return fmt.Errorf("call ended")
	}
}

func (c *Client) readIncomingTrack(track *webrtc.TrackRemote) {
	buf := make([]byte, 1600)
	for {
		select {
		case <-c.done:
			return
		default:
		}
		n, _, err := track.Read(buf)
		if err != nil {
			return
		}
		if c.tunnel != nil {
			c.tunnel.HandleIncomingFrame(buf[:n])
		}
	}
}

// Tunnel returns the VP8 tunnel (nil if not yet established).
func (c *Client) Tunnel() *vp8tunnel.Tunnel {
	return c.tunnel
}

// Close closes the client.
func (c *Client) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return
	}
	c.closed = true
	close(c.done)
	if c.tunnel != nil {
		c.tunnel.Close()
	}
	if c.pc != nil {
		c.pc.Close()
	}
}
