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
	"github.com/google/uuid"
	"github.com/pion/rtcp"
	"github.com/pion/rtp"
	"github.com/pion/rtp/codecs"
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

	sfu        *sfuConn
	tunnel     *vp8tunnel.Tunnel
	confID     string
	iceServers []webrtc.ICEServer

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

	// Step 3: Convert ICE servers to Pion format and store for reuse
	c.iceServers = toPionICEServers(iceServers)

	// Step 4: Create publisher PeerConnection (sends VP8 video with our data)
	if err := c.createPublisher(ctx, c.iceServers); err != nil {
		return fmt.Errorf("create publisher: %w", err)
	}

	// Step 5: Request subscription to other participants' media.
	// Send setSlots to tell SFU we want to receive 1 video + 1 audio slot.
	// Also request initialSubscriberOffer via capabilitiesOffer in hello.
	c.sendSetSlots(1)
	c.logger.Printf("[telemost] Sent setSlots")

	// Step 6: Process SFU messages (SDP offers/answers, ICE candidates)
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

	// Create audio track (required by Telemost SFU — browser always sends audio+video)
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

	// Create VP8 video track for tunneling data
	videoTrack, err := webrtc.NewTrackLocalStaticSample(
		webrtc.RTPCodecCapability{MimeType: webrtc.MimeTypeVP8},
		"video", "tunnel-video",
	)
	if err != nil {
		return fmt.Errorf("create video track: %w", err)
	}
	if _, err := pc.AddTrack(videoTrack); err != nil {
		return fmt.Errorf("add video track: %w", err)
	}

	// Create VP8 tunnel and wire it to the track
	tunnel := vp8tunnel.New()
	var writeCount uint64
	tunnel.SendFrame = func(data []byte, duration time.Duration) error {
		err := videoTrack.WriteSample(media.Sample{
			Data:     data,
			Duration: duration,
		})
		writeCount++
		if writeCount <= 10 || writeCount%500 == 0 {
			c.logger.Printf("[telemost] WriteSample #%d: size=%d first=0x%02x err=%v", writeCount, len(data), data[0], err)
		}
		return err
	}
	tunnel.Start(vp8tunnel.DefaultFPS)
	c.tunnel = tunnel

	// Monitor connection state
	pc.OnConnectionStateChange(func(state webrtc.PeerConnectionState) {
		c.logger.Printf("[telemost] Publisher state: %s", state)
		if state == webrtc.PeerConnectionStateConnected {
			c.logger.Printf("[telemost] VP8 tunnel ESTABLISHED")

			// After publisher connects, re-send setSlots with incremented key
			// to force SFU to re-evaluate video slot allocation.
			go func() {
				time.Sleep(500 * time.Millisecond)
				c.logger.Printf("[telemost] Re-sending setSlots (key=2) after publisher connected")
				c.sendSetSlots(2)

				// Also try requesting keyframe via SFU signaling
				time.Sleep(500 * time.Millisecond)
				c.sfu.writeJSON(map[string]interface{}{
					"uid": uuid.New().String(),
					"requestKeyframe": map[string]interface{}{},
				})
			}()

			if c.OnTunnel != nil {
				go c.OnTunnel(tunnel)
			}
		}
		if state == webrtc.PeerConnectionStateDisconnected {
			c.logger.Printf("[telemost] Publisher disconnected (may recover via ICE restart)")
		}
		if state == webrtc.PeerConnectionStateFailed {
			c.Close()
		}
	})

	// Trickle ICE: send candidates separately as webrtcIceCandidate
	// (browser sends SDP with 0 candidates, then trickles them)
	pc.OnICECandidate(func(candidate *webrtc.ICECandidate) {
		if candidate == nil {
			return
		}
		c.sendICECandidate("PUBLISHER", candidate)
	})

	// Create and send offer immediately (no candidates in SDP)
	offer, err := pc.CreateOffer(nil)
	if err != nil {
		return fmt.Errorf("create offer: %w", err)
	}
	if err := pc.SetLocalDescription(offer); err != nil {
		return fmt.Errorf("set local desc: %w", err)
	}

	c.logger.Printf("[telemost] Sending pub offer to SFU (trickle ICE)...")
	return c.sfu.writeJSON(map[string]interface{}{
		"uid": uuid.New().String(),
		"publisherSdpOffer": map[string]interface{}{
			"sdp":   offer.SDP,
			"pcSeq": 1,
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
		if state == webrtc.PeerConnectionStateConnected {
			// Send periodic PLI (Picture Loss Indication) to request video keyframes from SFU.
			// Some SFUs don't forward video until the subscriber explicitly requests it.
			go func() {
				for i := 0; i < 10; i++ {
					time.Sleep(1 * time.Second)
					for _, receiver := range pc.GetReceivers() {
						if receiver.Track() != nil && strings.Contains(strings.ToLower(receiver.Track().Codec().MimeType), "video") {
							ssrc := receiver.Track().SSRC()
							c.logger.Printf("[telemost] Sending PLI for video SSRC=%d", ssrc)
							pc.WriteRTCP([]rtcp.Packet{
								&rtcp.PictureLossIndication{
									MediaSSRC: uint32(ssrc),
								},
							})
						}
					}
				}
			}()
		}
	})

	// Trickle ICE for subscriber
	pc.OnICECandidate(func(candidate *webrtc.ICECandidate) {
		if candidate == nil {
			return
		}
		c.sendICECandidate("SUBSCRIBER", candidate)
	})

	// Set remote SDP (offer from SFU)
	if err := pc.SetRemoteDescription(webrtc.SessionDescription{
		Type: webrtc.SDPTypeOffer,
		SDP:  sdpOffer,
	}); err != nil {
		return fmt.Errorf("set remote offer: %w", err)
	}

	// Create and send answer (trickle ICE)
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

// readIncomingTrack reads VP8 frames from the remote track, depacketizes RTP,
// strips VP8 payload descriptors, reassembles frames, and feeds them to the tunnel.
func (c *Client) readIncomingTrack(track *webrtc.TrackRemote) {
	buf := make([]byte, 65535)
	var frameBuf []byte
	var rtpCount, frameCount, dataCount uint64

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

		// 1. Parse RTP packet
		pkt := &rtp.Packet{}
		if err := pkt.Unmarshal(buf[:n]); err != nil {
			c.logger.Printf("[telemost] RTP unmarshal error: %s", err)
			continue
		}

		rtpCount++
		if rtpCount <= 5 || rtpCount%500 == 0 {
			c.logger.Printf("[telemost] RTP #%d: size=%d payloadLen=%d marker=%v ssrc=%d",
				rtpCount, n, len(pkt.Payload), pkt.Marker, pkt.SSRC)
		}

		// 2. Strip VP8 RTP payload descriptor
		vp8Pkt := &codecs.VP8Packet{}
		payload, err := vp8Pkt.Unmarshal(pkt.Payload)
		if err != nil || len(payload) == 0 {
			continue
		}

		// 3. Frame reassembly: S=1 starts new frame, Marker=true ends frame
		if vp8Pkt.S == 1 {
			frameBuf = make([]byte, 0, 2048)
		}
		if frameBuf != nil {
			frameBuf = append(frameBuf, payload...)
		}

		if pkt.Marker && frameBuf != nil {
			frameCount++
			if frameCount <= 5 || frameCount%100 == 0 {
				first := byte(0)
				if len(frameBuf) > 0 {
					first = frameBuf[0]
				}
				c.logger.Printf("[telemost] Frame #%d: size=%d first=0x%02x (rtpPkts=%d)",
					frameCount, len(frameBuf), first, rtpCount)
			}

			if c.tunnel != nil {
				if len(frameBuf) > 0 && frameBuf[0] == vp8tunnel.DataFrameMarker {
					dataCount++
					if dataCount <= 5 || dataCount%100 == 0 {
						c.logger.Printf("[telemost] DATA frame #%d: size=%d", dataCount, len(frameBuf))
					}
				}
				c.tunnel.HandleIncomingFrame(frameBuf)
			}
			frameBuf = nil
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

		// Extract uid for ack echo
		var msgUID string
		if raw, ok := envelope["uid"]; ok {
			json.Unmarshal(raw, &msgUID)
		}

		// Send ack echoing the message uid (required by Yandex SFU protocol)
		sendAck := func() {
			if msgUID != "" {
				c.sfu.writeJSON(map[string]interface{}{
					"uid": msgUID,
					"ack": map[string]interface{}{"status": map[string]interface{}{"code": "OK"}},
				})
			}
		}

		// Skip ack messages from SFU
		if _, ok := envelope["ack"]; ok {
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
			sendAck()
		}

		// Handle subscriber SDP offer from SFU
		if raw, ok := envelope["subscriberSdpOffer"]; ok {
			var offer struct {
				SDP string `json:"sdp"`
			}
			if json.Unmarshal(raw, &offer) == nil && offer.SDP != "" {
				// Log video/audio m-lines with direction and SSRC info
				videoLines, audioLines := 0, 0
				var currentMedia string
				var videoDetails []string
				for _, line := range strings.Split(offer.SDP, "\r\n") {
					if strings.HasPrefix(line, "m=video") {
						videoLines++
						currentMedia = "video"
						videoDetails = append(videoDetails, fmt.Sprintf("  m-line %d: %s", videoLines, line))
					} else if strings.HasPrefix(line, "m=audio") {
						audioLines++
						currentMedia = "audio"
					}
					if currentMedia == "video" {
						if strings.HasPrefix(line, "a=sendrecv") || strings.HasPrefix(line, "a=recvonly") ||
							strings.HasPrefix(line, "a=sendonly") || strings.HasPrefix(line, "a=inactive") {
							videoDetails = append(videoDetails, fmt.Sprintf("    direction: %s", line))
						}
						if strings.HasPrefix(line, "a=ssrc:") {
							videoDetails = append(videoDetails, fmt.Sprintf("    %s", line))
						}
						if strings.HasPrefix(line, "a=mid:") {
							videoDetails = append(videoDetails, fmt.Sprintf("    %s", line))
						}
					}
				}
				c.logger.Printf("[telemost] Got sub offer from SFU (audio=%d video=%d m-lines)", audioLines, videoLines)
				for _, d := range videoDetails {
					c.logger.Printf("[telemost] Sub SDP %s", d)
				}
				if c.subPC == nil && c.pubPC != nil {
					c.createSubscriber(c.iceServers, offer.SDP)
				}
			}
			sendAck()
		}

		// Handle ICE candidates from SFU (Yandex uses "webrtcIceCandidate" key)
		if raw, ok := envelope["webrtcIceCandidate"]; ok {
			var cand struct {
				Candidate     string `json:"candidate"`
				SDPMid        string `json:"sdpMid"`
				SDPMLineIndex uint16 `json:"sdpMlineIndex"`
				Target        string `json:"target"`
			}
			if json.Unmarshal(raw, &cand) == nil && cand.Candidate != "" {
				c.logger.Printf("[telemost] ICE candidate from SFU: target=%s", cand.Target)
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

		// Log detailed content of key SFU messages for debugging
		if raw, ok := envelope["slotsConfig"]; ok {
			c.logger.Printf("[telemost] slotsConfig: %s", truncateJSON(raw, 500))
		}
		if raw, ok := envelope["upsertDescription"]; ok {
			c.logger.Printf("[telemost] upsertDescription: %s", truncateJSON(raw, 500))
		}
		if raw, ok := envelope["updateDescription"]; ok {
			c.logger.Printf("[telemost] updateDescription: %s", truncateJSON(raw, 500))
		}

		// Ack ALL other SFU messages with uid (catch-all for unknown types).
		msgType := "unknown"
		for key := range envelope {
			if key != "uid" {
				msgType = key
				break
			}
		}
		c.logger.Printf("[telemost] SFU msg: %s (uid=%s)", msgType, msgUID)
		sendAck()
	}
}

// sendICECandidate sends an ICE candidate to the SFU using Yandex format.
// sendSetSlots tells the SFU we want to receive video/audio from other participants.
// Format reverse-engineered from Telemost SDK browser traffic.
func (c *Client) sendSetSlots(key int) {
	if c.sfu == nil {
		return
	}
	// Telemost SDK sends 12 slots with varying resolutions for the grid layout.
	// We replicate this exactly to match expected behavior.
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

	// Extract usernameFragment from candidate string (Pion doesn't fill UsernameFragment)
	// Format: "... ufrag XXXX ..."
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
			"target":           target, // "PUBLISHER" or "SUBSCRIBER"
			"pcSeq":            1,
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

// truncateJSON returns a JSON string truncated to maxLen bytes.
func truncateJSON(raw json.RawMessage, maxLen int) string {
	s := string(raw)
	if len(s) > maxLen {
		return s[:maxLen] + "..."
	}
	return s
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
