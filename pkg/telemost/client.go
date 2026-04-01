package telemost

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/pion/webrtc/v4"
	"github.com/pion/webrtc/v4/pkg/media"
)

// Client connects to a Yandex Telemost conference as a WebRTC participant
// and establishes a DataChannel tunnel through the SFU.
type Client struct {
	logger *log.Logger

	pubPC *webrtc.PeerConnection
	subPC *webrtc.PeerConnection

	sfu        *sfuConn
	confID     string
	iceServers []webrtc.ICEServer
	pcSeq      int // incremented on each SDP renegotiation

	// DataChannel tunnel state
	dcPub   *webrtc.DataChannel // DC created on publisher (we initiate)
	dcSub   *webrtc.DataChannel // DC received on subscriber (remote initiates)
	dcRecv  chan []byte          // incoming data from active DC
	dcReady chan struct{}        // closed when DC tunnel is ready

	mu     sync.Mutex
	closed bool
	done   chan struct{}

	// OnDC is called when the DataChannel tunnel is ready for data.
	// The DCPacketConn can be used as net.PacketConn for WireGuard bridge.
	OnDC func(pconn *DCPacketConn)
}

// NewClient creates a new Telemost client.
func NewClient(logger *log.Logger) *Client {
	return &Client{
		logger:  logger,
		done:    make(chan struct{}),
		dcRecv:  make(chan []byte, 256),
		dcReady: make(chan struct{}),
		pcSeq:   1,
	}
}

// JoinCall connects to a Telemost conference and establishes the DataChannel tunnel.
// Blocks until the call ends or context is cancelled.
func (c *Client) JoinCall(ctx context.Context, confLink string) error {
	c.confID = parseConfID(confLink)
	c.logger.Printf("[telemost] Joining conference %s...", c.confID)

	info, err := fetchConferenceInfo(ctx, c.confID)
	if err != nil {
		return fmt.Errorf("fetch conference: %w", err)
	}
	c.logger.Printf("[telemost] Conference info: room=%s media=%s", info.RoomID, info.MediaURL)

	sfu, iceServers, err := connectSFU(ctx, info)
	if err != nil {
		return fmt.Errorf("connect SFU: %w", err)
	}
	c.sfu = sfu
	defer sfu.close()

	go sfu.keepalive(ctx)

	c.logger.Printf("[telemost] Connected to SFU, got %d ICE servers", len(iceServers))
	c.iceServers = toPionICEServers(iceServers)

	if err := c.createPublisher(ctx, c.iceServers); err != nil {
		return fmt.Errorf("create publisher: %w", err)
	}

	c.sendSetSlots(1)
	c.logger.Printf("[telemost] Sent setSlots")

	c.logger.Printf("[telemost] Processing SFU signaling...")
	return c.processSFUMessages(ctx)
}

// createPublisher creates the publisher PeerConnection with audio track only.
// Video track is NOT needed for DataChannel mode — the DC carries the data.
func (c *Client) createPublisher(ctx context.Context, iceServers []webrtc.ICEServer) error {
	config := webrtc.Configuration{
		ICEServers:         iceServers,
		ICETransportPolicy: webrtc.ICETransportPolicyRelay,
	}

	pc, err := webrtc.NewPeerConnection(config)
	if err != nil {
		return fmt.Errorf("new PC: %w", err)
	}
	c.pubPC = pc

	// Audio track (required by SFU — Telemost expects at least audio)
	audioTrack, err := webrtc.NewTrackLocalStaticSample(
		webrtc.RTPCodecCapability{MimeType: webrtc.MimeTypeOpus},
		"audio", "tunnel-audio",
	)
	if err != nil {
		return fmt.Errorf("create audio track: %w", err)
	}
	if _, err := pc.AddTrack(audioTrack); err != nil {
		return fmt.Errorf("add audio track: %w", err)
	}

	// Send silent audio keepalive (SFU may drop participants without media)
	go func() {
		silence := make([]byte, 3) // minimal Opus silence frame
		ticker := time.NewTicker(20 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-c.done:
				return
			case <-ticker.C:
				audioTrack.WriteSample(media.Sample{Data: silence, Duration: 20 * time.Millisecond})
			}
		}
	}()

	// Monitor connection state.
	// After publisher connects, wait 3s then create DataChannel via SDP renegotiation
	// (same approach as upstream dc-creator-telemost.js).
	pc.OnConnectionStateChange(func(state webrtc.PeerConnectionState) {
		c.logger.Printf("[telemost] Publisher state: %s", state)
		if state == webrtc.PeerConnectionStateConnected {
			go func() {
				time.Sleep(3 * time.Second)
				c.logger.Printf("[telemost] Creating DataChannel via renegotiation...")
				c.createAndNegotiateDC()
			}()
		}
		if state == webrtc.PeerConnectionStateFailed {
			c.Close()
		}
	})

	pc.OnICECandidate(func(candidate *webrtc.ICECandidate) {
		if candidate == nil {
			return
		}
		c.sendICECandidate("PUBLISHER", candidate)
	})

	offer, err := pc.CreateOffer(nil)
	if err != nil {
		return fmt.Errorf("create offer: %w", err)
	}
	if err := pc.SetLocalDescription(offer); err != nil {
		return fmt.Errorf("set local desc: %w", err)
	}

	c.logger.Printf("[telemost] Sending pub offer to SFU (pcSeq=%d)...", c.pcSeq)
	return c.sfu.writeJSON(map[string]interface{}{
		"uid": uuid.New().String(),
		"publisherSdpOffer": map[string]interface{}{
			"sdp":   offer.SDP,
			"pcSeq": c.pcSeq,
		},
	})
}

// createAndNegotiateDC creates a DataChannel on the publisher PC and renegotiates SDP.
// Must be called AFTER the publisher is connected (3s delay recommended).
func (c *Client) createAndNegotiateDC() {
	if c.pubPC == nil {
		return
	}

	ordered := true
	dc, err := c.pubPC.CreateDataChannel("sharing", &webrtc.DataChannelInit{
		Ordered: &ordered,
	})
	if err != nil {
		c.logger.Printf("[telemost] DC create error: %s", err)
		return
	}
	c.dcPub = dc
	c.setupDCHandlers(dc, "pub")

	// Renegotiate: create offer with the new DataChannel
	c.pcSeq++
	offer, err := c.pubPC.CreateOffer(nil)
	if err != nil {
		c.logger.Printf("[telemost] DC offer error: %s", err)
		return
	}
	if err := c.pubPC.SetLocalDescription(offer); err != nil {
		c.logger.Printf("[telemost] DC set local desc error: %s", err)
		return
	}

	c.logger.Printf("[telemost] DC renegotiating (pcSeq=%d)...", c.pcSeq)
	c.sfu.writeJSON(map[string]interface{}{
		"uid": uuid.New().String(),
		"publisherSdpOffer": map[string]interface{}{
			"sdp":    offer.SDP,
			"pcSeq":  c.pcSeq,
			"tracks": []interface{}{},
		},
	})
}

// setupDCHandlers configures message handlers on a DataChannel.
func (c *Client) setupDCHandlers(dc *webrtc.DataChannel, side string) {
	dc.OnOpen(func() {
		c.logger.Printf("[telemost] DC 'sharing' OPEN (%s)", side)
		// Start ping loop
		go func() {
			for i := 0; i < 15; i++ {
				select {
				case <-c.dcReady:
					return
				case <-c.done:
					return
				default:
				}
				dc.SendText("tunnel:ping")
				c.logger.Printf("[telemost] DC %s: sent tunnel:ping", side)
				time.Sleep(2 * time.Second)
			}
		}()
	})

	dc.OnMessage(func(msg webrtc.DataChannelMessage) {
		if msg.IsString {
			text := string(msg.Data)
			c.logger.Printf("[telemost] DC %s text: %s", side, text)
			if text == "tunnel:ping" {
				dc.SendText("tunnel:pong")
				c.onDCReady(dc)
			} else if text == "tunnel:pong" {
				c.onDCReady(dc)
			}
			return
		}
		data := make([]byte, len(msg.Data))
		copy(data, msg.Data)
		select {
		case c.dcRecv <- data:
		case <-c.done:
		default:
		}
	})

	dc.OnClose(func() {
		c.logger.Printf("[telemost] DC closed (%s)", side)
	})
}

// onDCReady is called when DC ping/pong handshake completes.
func (c *Client) onDCReady(dc *webrtc.DataChannel) {
	c.mu.Lock()
	defer c.mu.Unlock()

	select {
	case <-c.dcReady:
		return // already ready
	default:
	}

	close(c.dcReady)
	c.logger.Printf("[telemost] === DataChannel TUNNEL READY ===")

	if c.OnDC != nil {
		pconn := NewDCPacketConn(dc, c.dcRecv, c.done)
		go c.OnDC(pconn)
	}
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

	// Handle incoming tracks (drain them to prevent blocking)
	pc.OnTrack(func(track *webrtc.TrackRemote, receiver *webrtc.RTPReceiver) {
		c.logger.Printf("[telemost] Incoming track: %s (codec: %s)", track.ID(), track.Codec().MimeType)
		// Drain track to prevent WebRTC backpressure
		go func() {
			buf := make([]byte, 1500)
			for {
				if _, _, err := track.Read(buf); err != nil {
					return
				}
			}
		}()
	})

	// Handle incoming DataChannel from remote participant
	pc.OnDataChannel(func(dc *webrtc.DataChannel) {
		c.logger.Printf("[telemost] Incoming DC on subscriber: label=%s id=%d", dc.Label(), *dc.ID())
		if dc.Label() == "sharing" {
			c.dcSub = dc
			c.setupDCHandlers(dc, "sub")
		}
	})

	pc.OnConnectionStateChange(func(state webrtc.PeerConnectionState) {
		c.logger.Printf("[telemost] Subscriber state: %s", state)
	})

	pc.OnICECandidate(func(candidate *webrtc.ICECandidate) {
		if candidate == nil {
			return
		}
		c.sendICECandidate("SUBSCRIBER", candidate)
	})

	if err := pc.SetRemoteDescription(webrtc.SessionDescription{
		Type: webrtc.SDPTypeOffer,
		SDP:  sdpOffer,
	}); err != nil {
		return fmt.Errorf("set remote offer: %w", err)
	}

	answer, err := pc.CreateAnswer(nil)
	if err != nil {
		return fmt.Errorf("create answer: %w", err)
	}
	if err := pc.SetLocalDescription(answer); err != nil {
		return fmt.Errorf("set local desc: %w", err)
	}

	return c.sfu.writeJSON(map[string]interface{}{
		"uid": uuid.New().String(),
		"subscriberSdpAnswer": map[string]interface{}{
			"sdp":   answer.SDP,
			"pcSeq": 1,
		},
	})
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

		var msgUID string
		if raw, ok := envelope["uid"]; ok {
			json.Unmarshal(raw, &msgUID)
		}

		sendAck := func() {
			if msgUID != "" {
				c.sfu.writeJSON(map[string]interface{}{
					"uid": msgUID,
					"ack": map[string]interface{}{"status": map[string]interface{}{"code": "OK"}},
				})
			}
		}

		if _, ok := envelope["ack"]; ok {
			continue
		}

		// Handle publisher SDP answer (initial + renegotiation for DC)
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
			sendAck()
			continue
		}

		// Handle subscriber SDP offer
		if raw, ok := envelope["subscriberSdpOffer"]; ok {
			var offer struct {
				SDP string `json:"sdp"`
			}
			if json.Unmarshal(raw, &offer) == nil && offer.SDP != "" {
				// Check for DataChannel in SDP
				hasDC := strings.Contains(offer.SDP, "m=application")
				c.logger.Printf("[telemost] Got sub offer from SFU (hasDataChannel=%v)", hasDC)

				if c.subPC == nil {
					c.createSubscriber(c.iceServers, offer.SDP)
				} else {
					// Renegotiation on existing subscriber (e.g. new DC from remote)
					c.logger.Printf("[telemost] Subscriber renegotiation...")
					c.subPC.SetRemoteDescription(webrtc.SessionDescription{
						Type: webrtc.SDPTypeOffer,
						SDP:  offer.SDP,
					})
					answer, err := c.subPC.CreateAnswer(nil)
					if err == nil {
						c.subPC.SetLocalDescription(answer)
						c.sfu.writeJSON(map[string]interface{}{
							"uid": uuid.New().String(),
							"subscriberSdpAnswer": map[string]interface{}{
								"sdp":   answer.SDP,
								"pcSeq": 1,
							},
						})
					}
				}
			}
			sendAck()
			continue
		}

		// Handle ICE candidates
		if raw, ok := envelope["webrtcIceCandidate"]; ok {
			var cand struct {
				Candidate string `json:"candidate"`
				SDPMid    string `json:"sdpMid"`
				Target    string `json:"target"`
			}
			if json.Unmarshal(raw, &cand) == nil && cand.Candidate != "" {
				c.logger.Printf("[telemost] ICE candidate: target=%s", cand.Target)
				ice := webrtc.ICECandidateInit{
					Candidate: cand.Candidate,
					SDPMid:    &cand.SDPMid,
				}
				if cand.Target == "SUBSCRIBER" && c.subPC != nil {
					c.subPC.AddICECandidate(ice)
				} else if c.pubPC != nil {
					c.pubPC.AddICECandidate(ice)
				}
			}
			sendAck()
			continue
		}

		// Log key SFU messages
		if raw, ok := envelope["slotsConfig"]; ok {
			c.logger.Printf("[telemost] slotsConfig: %s", truncateJSON(raw, 300))
		}

		// Ack everything else
		msgType := "unknown"
		for key := range envelope {
			if key != "uid" {
				msgType = key
				break
			}
		}
		c.logger.Printf("[telemost] SFU msg: %s", msgType)
		sendAck()
	}
}

// sendSetSlots tells the SFU we want to receive media from other participants.
func (c *Client) sendSetSlots(key int) {
	if c.sfu == nil {
		return
	}
	slots := make([]map[string]interface{}, 12)
	for i := 0; i < 8; i++ {
		slots[i] = map[string]interface{}{"width": 368, "height": 207}
	}
	slots[8] = map[string]interface{}{"width": 320, "height": 180}
	slots[9] = map[string]interface{}{"width": 320, "height": 180}
	slots[10] = map[string]interface{}{"width": 256, "height": 144}
	slots[11] = map[string]interface{}{"width": 256, "height": 144}

	c.sfu.writeJSON(map[string]interface{}{
		"uid": uuid.New().String(),
		"setSlots": map[string]interface{}{
			"slots":              slots,
			"audioSlotsCount":    0,
			"gridConfig":         map[string]interface{}{},
			"key":                key,
			"selfViewVisibility": "ON_LOADING_THEN_SHOW",
			"shutdownAllVideo":   nil,
			"withSelfView":       true,
		},
	})
}

func (c *Client) sendICECandidate(target string, candidate *webrtc.ICECandidate) {
	if c.sfu == nil {
		return
	}
	init := candidate.ToJSON()
	ufrag := ""
	if parts := strings.Split(init.Candidate, " ufrag "); len(parts) > 1 {
		ufrag = strings.Fields(parts[1])[0]
	}
	c.sfu.writeJSON(map[string]interface{}{
		"uid": uuid.New().String(),
		"webrtcIceCandidate": map[string]interface{}{
			"candidate":        init.Candidate,
			"sdpMid":           init.SDPMid,
			"sdpMlineIndex":    init.SDPMLineIndex,
			"usernameFragment": ufrag,
			"target":           target,
			"pcSeq":            c.pcSeq,
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
	if c.dcPub != nil {
		c.dcPub.Close()
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

// DCReady returns a channel that's closed when the DataChannel tunnel is ready.
func (c *Client) DCReady() <-chan struct{} {
	return c.dcReady
}

func truncateJSON(raw json.RawMessage, maxLen int) string {
	s := string(raw)
	if len(s) > maxLen {
		return s[:maxLen] + "..."
	}
	return s
}

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
