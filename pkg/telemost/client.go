package telemost

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/Romakarov/vkvpn/pkg/vp8tunnel"
	"github.com/pion/webrtc/v4"
	"github.com/pion/webrtc/v4/pkg/media"
)

// Client connects to a Yandex Telemost conference as a WebRTC participant
// and establishes a VP8 data tunnel through the SFU.
type Client struct {
	logger *log.Logger

	// pubPC sends VP8 "video" containing our data to the SFU.
	pubPC *webrtc.PeerConnection
	// subPC receives VP8 "video" from the other participant.
	subPC *webrtc.PeerConnection

	sfu     *sfuConn
	tunnel  *vp8tunnel.Tunnel
	confID  string

	mu     sync.Mutex
	closed bool
	done   chan struct{}

	// OnTunnel is called when the VP8 tunnel is established and ready for data.
	OnTunnel func(tunnel *vp8tunnel.Tunnel)
}

// NewClient creates a new Telemost client.
func NewClient(logger *log.Logger) *Client {
	return &Client{
		logger: logger,
		done:   make(chan struct{}),
	}
}

// JoinCall connects to a Telemost conference and establishes the VP8 tunnel.
// confLink is the full URL or conference ID (e.g. "https://telemost.yandex.ru/j/12345").
// Blocks until the call ends or context is cancelled.
func (c *Client) JoinCall(ctx context.Context, confLink string) error {
	c.confID = parseConfID(confLink)
	c.logger.Printf("[telemost] Joining conference %s...", c.confID)

	// Step 1: Get conference info (room, peer, media server URL)
	info, err := fetchConferenceInfo(ctx, c.confID)
	if err != nil {
		return fmt.Errorf("fetch conference: %w", err)
	}
	c.logger.Printf("[telemost] Conference info: room=%s media=%s", info.RoomID, info.MediaURL)

	// Step 2: Connect to SFU and get ICE servers
	sfu, iceServers, err := connectSFU(ctx, info)
	if err != nil {
		return fmt.Errorf("connect SFU: %w", err)
	}
	c.sfu = sfu
	defer sfu.close()

	// Start SFU keepalive
	go sfu.keepalive(ctx)

	c.logger.Printf("[telemost] Connected to SFU, got %d ICE servers", len(iceServers))

	// Step 3: Convert ICE servers to Pion format
	pionICE := toPionICEServers(iceServers)

	// Step 4: Create publisher PeerConnection (sends VP8 video with our data)
	if err := c.createPublisher(ctx, pionICE); err != nil {
		return fmt.Errorf("create publisher: %w", err)
	}

	// Step 5: Process SFU messages (SDP offers/answers, ICE candidates)
	c.logger.Printf("[telemost] Processing SFU signaling...")
	return c.processSFUMessages(ctx)
}

// createPublisher creates the publisher PeerConnection and VP8 track.
func (c *Client) createPublisher(ctx context.Context, iceServers []webrtc.ICEServer) error {
	config := webrtc.Configuration{
		ICEServers:         iceServers,
		ICETransportPolicy: webrtc.ICETransportPolicyRelay, // TURN only — no direct P2P
	}

	pc, err := webrtc.NewPeerConnection(config)
	if err != nil {
		return fmt.Errorf("new PC: %w", err)
	}
	c.pubPC = pc

	// Create VP8 video track for tunneling data
	videoTrack, err := webrtc.NewTrackLocalStaticSample(
		webrtc.RTPCodecCapability{MimeType: webrtc.MimeTypeVP8},
		"video", "tunnel-video",
	)
	if err != nil {
		return fmt.Errorf("create track: %w", err)
	}
	if _, err := pc.AddTrack(videoTrack); err != nil {
		return fmt.Errorf("add track: %w", err)
	}

	// Create VP8 tunnel and wire it to the track
	tunnel := vp8tunnel.New()
	tunnel.SendFrame = func(data []byte, duration time.Duration) error {
		return videoTrack.WriteSample(media.Sample{
			Data:     data,
			Duration: duration,
		})
	}
	tunnel.Start(vp8tunnel.DefaultFPS)
	c.tunnel = tunnel

	// Monitor connection state
	pc.OnConnectionStateChange(func(state webrtc.PeerConnectionState) {
		c.logger.Printf("[telemost] Publisher state: %s", state)
		if state == webrtc.PeerConnectionStateConnected {
			c.logger.Printf("[telemost] VP8 tunnel ESTABLISHED")
			if c.OnTunnel != nil {
				go c.OnTunnel(tunnel)
			}
		}
		if state == webrtc.PeerConnectionStateFailed || state == webrtc.PeerConnectionStateDisconnected {
			c.Close()
		}
	})

	// Gather ICE candidates and send to SFU
	pc.OnICECandidate(func(candidate *webrtc.ICECandidate) {
		if candidate == nil {
			return
		}
		c.sendICECandidate("pub", candidate)
	})

	// Create offer
	offer, err := pc.CreateOffer(nil)
	if err != nil {
		return fmt.Errorf("create offer: %w", err)
	}
	if err := pc.SetLocalDescription(offer); err != nil {
		return fmt.Errorf("set local desc: %w", err)
	}

	// Send offer to SFU
	c.logger.Printf("[telemost] Sending pub offer to SFU...")
	return c.sfu.writeJSON(map[string]interface{}{
		"publisherSdpOffer": map[string]interface{}{
			"sdp":   offer.SDP,
			"pcSeq": 0,
		},
	})
}

// createSubscriber creates the subscriber PeerConnection from an SFU offer.
func (c *Client) createSubscriber(iceServers []webrtc.ICEServer, sdpOffer string) error {
	config := webrtc.Configuration{
		ICEServers:         iceServers,
		ICETransportPolicy: webrtc.ICETransportPolicyRelay,
	}

	pc, err := webrtc.NewPeerConnection(config)
	if err != nil {
		return fmt.Errorf("new sub PC: %w", err)
	}
	c.subPC = pc

	// Handle incoming tracks (VP8 video from other participant)
	pc.OnTrack(func(track *webrtc.TrackRemote, receiver *webrtc.RTPReceiver) {
		c.logger.Printf("[telemost] Incoming track: %s (codec: %s)", track.ID(), track.Codec().MimeType)
		if strings.EqualFold(track.Codec().MimeType, webrtc.MimeTypeVP8) {
			go c.readIncomingTrack(track)
		}
	})

	pc.OnConnectionStateChange(func(state webrtc.PeerConnectionState) {
		c.logger.Printf("[telemost] Subscriber state: %s", state)
	})

	pc.OnICECandidate(func(candidate *webrtc.ICECandidate) {
		if candidate == nil {
			return
		}
		c.sendICECandidate("sub", candidate)
	})

	// Set remote SDP (offer from SFU)
	if err := pc.SetRemoteDescription(webrtc.SessionDescription{
		Type: webrtc.SDPTypeOffer,
		SDP:  sdpOffer,
	}); err != nil {
		return fmt.Errorf("set remote offer: %w", err)
	}

	// Create answer
	answer, err := pc.CreateAnswer(nil)
	if err != nil {
		return fmt.Errorf("create answer: %w", err)
	}
	if err := pc.SetLocalDescription(answer); err != nil {
		return fmt.Errorf("set local desc: %w", err)
	}

	// Send answer to SFU
	return c.sfu.writeJSON(map[string]interface{}{
		"subscriberSdpAnswer": map[string]interface{}{
			"sdp":   answer.SDP,
			"pcSeq": 0,
		},
	})
}

// readIncomingTrack reads VP8 frames from the remote track and feeds them to the tunnel.
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
			c.logger.Printf("[telemost] Track read error: %s", err)
			return
		}
		if c.tunnel != nil {
			c.tunnel.HandleIncomingFrame(buf[:n])
		}
	}
}

// processSFUMessages reads and handles signaling messages from the SFU.
func (c *Client) processSFUMessages(ctx context.Context) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-c.done:
			return fmt.Errorf("client closed")
		default:
		}

		msg, err := c.sfu.readMessage()
		if err != nil {
			return fmt.Errorf("SFU read: %w", err)
		}

		var envelope map[string]json.RawMessage
		if err := json.Unmarshal(msg, &envelope); err != nil {
			continue
		}

		// Handle publisher SDP answer from SFU
		if raw, ok := envelope["publisherSdpAnswer"]; ok {
			var ans struct {
				SDP string `json:"sdp"`
			}
			if json.Unmarshal(raw, &ans) == nil && ans.SDP != "" {
				c.logger.Printf("[telemost] Got pub answer from SFU")
				if c.pubPC != nil {
					c.pubPC.SetRemoteDescription(webrtc.SessionDescription{
						Type: webrtc.SDPTypeAnswer,
						SDP:  ans.SDP,
					})
				}
			}
		}

		// Handle subscriber SDP offer from SFU
		if raw, ok := envelope["subscriberSdpOffer"]; ok {
			var offer struct {
				SDP string `json:"sdp"`
			}
			if json.Unmarshal(raw, &offer) == nil && offer.SDP != "" {
				c.logger.Printf("[telemost] Got sub offer from SFU")
				if c.subPC == nil {
					iceServers := toPionICEServers(nil) // sub uses existing ICE config
					if c.pubPC != nil {
						// Reuse ICE servers from publisher config
						c.createSubscriber(iceServers, offer.SDP)
					}
				}
			}
		}

		// Handle ICE candidates from SFU
		if raw, ok := envelope["iceCandidate"]; ok {
			var cand struct {
				Candidate     string `json:"candidate"`
				SDPMid        string `json:"sdpMid"`
				SDPMLineIndex uint16 `json:"sdpMLineIndex"`
				Role          string `json:"role"`
			}
			if json.Unmarshal(raw, &cand) == nil && cand.Candidate != "" {
				ice := webrtc.ICECandidateInit{
					Candidate: cand.Candidate,
					SDPMid:    &cand.SDPMid,
				}
				if cand.Role == "sub" && c.subPC != nil {
					c.subPC.AddICECandidate(ice)
				} else if c.pubPC != nil {
					c.pubPC.AddICECandidate(ice)
				}
			}
		}
	}
}

// sendICECandidate sends an ICE candidate to the SFU.
func (c *Client) sendICECandidate(role string, candidate *webrtc.ICECandidate) {
	if c.sfu == nil {
		return
	}
	init := candidate.ToJSON()
	c.sfu.writeJSON(map[string]interface{}{
		"iceCandidate": map[string]interface{}{
			"candidate":     init.Candidate,
			"sdpMid":        init.SDPMid,
			"sdpMLineIndex": init.SDPMLineIndex,
			"role":          role,
		},
	})
}

// Close closes the client and all connections.
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
	if c.pubPC != nil {
		c.pubPC.Close()
	}
	if c.subPC != nil {
		c.subPC.Close()
	}
	if c.sfu != nil {
		c.sfu.close()
	}
}

// toPionICEServers converts Telemost ICE server configs to Pion format.
func toPionICEServers(servers []iceServerConfig) []webrtc.ICEServer {
	var result []webrtc.ICEServer
	for _, s := range servers {
		result = append(result, webrtc.ICEServer{
			URLs:       []string(s.URLs),
			Username:   s.Username,
			Credential: s.Credential,
		})
	}
	return result
}
