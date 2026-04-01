// Package telemost implements a Pion WebRTC client that joins a Yandex Telemost
// conference call and establishes a VP8 data tunnel through the SFU.
//
// This bypasses TURN relay blocking because data flows as "video" inside
// a legitimate video call — the SFU can't block it without breaking all calls.
package telemost

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/websocket"
)

const userAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:144.0) Gecko/20100101 Firefox/144.0"

// confBaseURL is the Telemost API endpoint. Overridable for testing.
var confBaseURL = "https://cloud-api.yandex.ru"

// conferenceInfo holds data returned by the Telemost conference API.
type conferenceInfo struct {
	RoomID    string `json:"room_id"`
	PeerID    string `json:"peer_id"`
	MediaURL  string // WebSocket URL for the SFU media server
	Credentials string `json:"credentials"`
}

// fetchConferenceInfo gets room/peer/media info from a Telemost conference link.
func fetchConferenceInfo(ctx context.Context, confID string) (*conferenceInfo, error) {
	path := fmt.Sprintf("/telemost_front/v2/telemost/conferences/https%%3A%%2F%%2Ftelemost.yandex.ru%%2Fj%%2F%s/connection?next_gen_media_platform_allowed=false", confID)

	client := &http.Client{Timeout: 30 * time.Second}
	defer client.CloseIdleConnections()

	req, err := http.NewRequestWithContext(ctx, "GET", confBaseURL+path, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Referer", "https://telemost.yandex.ru/")
	req.Header.Set("Origin", "https://telemost.yandex.ru")
	req.Header.Set("Client-Instance-Id", uuid.New().String())

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("conference API: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("conference API: status=%s body=%s", resp.Status, string(body))
	}

	var raw struct {
		RoomID              string `json:"room_id"`
		PeerID              string `json:"peer_id"`
		ClientConfiguration struct {
			MediaServerURL string `json:"media_server_url"`
		} `json:"client_configuration"`
		Credentials string `json:"credentials"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return nil, fmt.Errorf("decode conference: %w", err)
	}

	return &conferenceInfo{
		RoomID:      raw.RoomID,
		PeerID:      raw.PeerID,
		MediaURL:    raw.ClientConfiguration.MediaServerURL,
		Credentials: raw.Credentials,
	}, nil
}

// sfuConn wraps a WebSocket connection to the Telemost SFU media server.
type sfuConn struct {
	ws  *websocket.Conn
	wmu sync.Mutex // protects writes — gorilla/websocket doesn't support concurrent writes
}

// connectSFU establishes a WebSocket to the SFU media server and sends the hello.
func connectSFU(ctx context.Context, info *conferenceInfo) (*sfuConn, []iceServerConfig, error) {
	h := http.Header{}
	h.Set("Origin", "https://telemost.yandex.ru")
	h.Set("User-Agent", userAgent)

	dialer := websocket.Dialer{}
	ws, _, err := dialer.DialContext(ctx, info.MediaURL, h)
	if err != nil {
		return nil, nil, fmt.Errorf("SFU WS dial: %w", err)
	}

	sfu := &sfuConn{ws: ws}

	// Override ping handler to use our mutex-protected write path
	ws.SetPingHandler(func(data string) error {
		sfu.wmu.Lock()
		defer sfu.wmu.Unlock()
		return ws.WriteControl(websocket.PongMessage, []byte(data), time.Now().Add(5*time.Second))
	})

	// Send hello message
	hello := buildHello(info.PeerID, info.RoomID, info.Credentials)
	if err := sfu.writeJSON(hello); err != nil {
		ws.Close()
		return nil, nil, fmt.Errorf("SFU hello: %w", err)
	}

	// Read until we get serverHello with ICE servers
	ws.SetReadDeadline(time.Now().Add(15 * time.Second))
	for {
		_, msg, err := ws.ReadMessage()
		if err != nil {
			ws.Close()
			return nil, nil, fmt.Errorf("SFU read: %w", err)
		}

		// Skip ACK messages
		var ack struct {
			Ack struct {
				Status struct {
					Code string `json:"code"`
				} `json:"status"`
			} `json:"ack"`
		}
		if json.Unmarshal(msg, &ack) == nil && ack.Ack.Status.Code != "" {
			continue
		}

		// Parse serverHello for ICE servers
		var serverHello struct {
			UID         string `json:"uid"`
			ServerHello struct {
				RtcConfiguration struct {
					IceServers []iceServerConfig `json:"iceServers"`
				} `json:"rtcConfiguration"`
			} `json:"serverHello"`
		}
		if json.Unmarshal(msg, &serverHello) == nil {
			ice := serverHello.ServerHello.RtcConfiguration.IceServers
			if len(ice) > 0 {
				ws.SetReadDeadline(time.Time{}) // clear deadline
				// Send ack echoing the serverHello uid (required by Yandex SFU)
				sfu.writeJSON(map[string]interface{}{
					"uid": serverHello.UID,
					"ack": map[string]interface{}{
						"status": map[string]interface{}{"code": "OK"},
					},
				})
				return sfu, ice, nil
			}
		}
	}
}

// readMessage reads the next JSON message from the SFU.
func (s *sfuConn) readMessage() (json.RawMessage, error) {
	_, msg, err := s.ws.ReadMessage()
	if err != nil {
		return nil, err
	}
	return json.RawMessage(msg), nil
}

// writeJSON sends a JSON message to the SFU (goroutine-safe).
func (s *sfuConn) writeJSON(v interface{}) error {
	s.wmu.Lock()
	defer s.wmu.Unlock()
	return s.ws.WriteJSON(v)
}

// close closes the WebSocket.
func (s *sfuConn) close() error {
	return s.ws.Close()
}

// keepalive sends periodic WebSocket ping frames to keep the SFU connection alive.
func (s *sfuConn) keepalive(ctx context.Context) {
	ticker := time.NewTicker(4 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.wmu.Lock()
			s.ws.WriteControl(websocket.PingMessage, nil, time.Now().Add(5*time.Second))
			s.wmu.Unlock()
		}
	}
}

// iceServerConfig matches the ICE server format from Telemost SFU.
type iceServerConfig struct {
	URLs       flexURLs `json:"urls"`
	Username   string   `json:"username,omitempty"`
	Credential string   `json:"credential,omitempty"`
}

// flexURLs handles JSON urls field that can be string or []string.
type flexURLs []string

func (f *flexURLs) UnmarshalJSON(data []byte) error {
	var s string
	if json.Unmarshal(data, &s) == nil {
		*f = []string{s}
		return nil
	}
	var arr []string
	if err := json.Unmarshal(data, &arr); err != nil {
		return err
	}
	*f = arr
	return nil
}

// buildHello creates the hello message for the Telemost SFU.
func buildHello(participantID, roomID, credentials string) map[string]interface{} {
	return map[string]interface{}{
		"uid": uuid.New().String(),
		"hello": map[string]interface{}{
			"participantMeta": map[string]interface{}{
				"name": "Гость", "role": "SPEAKER", "description": "",
				"sendAudio": true, "sendVideo": true,
			},
			"participantAttributes": map[string]interface{}{
				"name": "Гость", "role": "SPEAKER", "description": "",
			},
			"sendAudio":              true,
			"sendVideo":              true,
			"sendSharing":            false,
			"participantId":          participantID,
			"roomId":                 roomID,
			"serviceName":            "telemost",
			"credentials":            credentials,
			"sdkInitializationId":    uuid.New().String(),
			"disablePublisher":       false,
			"disableSubscriber":      false,
			"disableSubscriberAudio": false,
			"sdkInfo": map[string]interface{}{
				"implementation": "browser", "version": "5.15.0",
				"userAgent": userAgent, "hwConcurrency": 4,
			},
			"capabilitiesOffer": map[string]interface{}{
				"offerAnswerMode":             []string{"SEPARATE"},
				"initialSubscriberOffer":      []string{"ON_HELLO"},
				"slotsMode":                   []string{"FROM_CONTROLLER"},
				"simulcastMode":               []string{"DISABLED"},
				"selfVadStatus":               []string{"FROM_SERVER"},
				"dataChannelSharing":          []string{"TO_RTP"},
				"videoEncoderConfig":          []string{"NO_CONFIG"},
				"dataChannelVideoCodec":       []string{"VP8"},
				"bandwidthLimitationReason":   []string{"BANDWIDTH_REASON_DISABLED"},
				"sdkDefaultDeviceManagement":  []string{"SDK_DEFAULT_DEVICE_MANAGEMENT_DISABLED"},
				"joinOrderLayout":             []string{"JOIN_ORDER_LAYOUT_DISABLED"},
				"pinLayout":                   []string{"PIN_LAYOUT_DISABLED"},
				"sendSelfViewVideoSlot":       []string{"SEND_SELF_VIEW_VIDEO_SLOT_DISABLED"},
				"serverLayoutTransition":      []string{"SERVER_LAYOUT_TRANSITION_DISABLED"},
				"sdkPublisherOptimizeBitrate": []string{"SDK_PUBLISHER_OPTIMIZE_BITRATE_DISABLED"},
				"sdkNetworkLostDetection":     []string{"SDK_NETWORK_LOST_DETECTION_DISABLED"},
				"sdkNetworkPathMonitor":       []string{"SDK_NETWORK_PATH_MONITOR_DISABLED"},
				"publisherVp9":                []string{"PUBLISH_VP9_DISABLED"},
				"svcMode":                     []string{"SVC_MODE_DISABLED"},
				"subscriberOfferAsyncAck":     []string{"SUBSCRIBER_OFFER_ASYNC_ACK_DISABLED"},
				"svcModes":                    []string{"FALSE"},
				"reportTelemetryModes":        []string{"TRUE"},
				"keepDefaultDevicesModes":     []string{"TRUE"},
			},
		},
	}
}

// parseConfID extracts the conference ID from a full Telemost URL.
func parseConfID(link string) string {
	if strings.Contains(link, "j/") {
		parts := strings.Split(link, "j/")
		link = parts[len(parts)-1]
	}
	if idx := strings.IndexAny(link, "/?#"); idx != -1 {
		link = link[:idx]
	}
	return link
}
