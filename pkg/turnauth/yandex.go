package turnauth

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/websocket"
)

// yandexConfBaseURL is the base URL for the Yandex conference API. Overridable for testing.
var yandexConfBaseURL = "https://cloud-api.yandex.ru"

// ErrYandexDeprecated is returned when attempting to use Yandex Telemost TURN.
var ErrYandexDeprecated = fmt.Errorf("Yandex Telemost TURN is no longer available: Telemost blocked relay to external IPs (March 2026)")

// GetYandexCredentials extracts TURN credentials from a Yandex Telemost link.
//
// Deprecated: Yandex Telemost blocked TURN relay to external IPs in March 2026.
// This function is kept for reference but returns ErrYandexDeprecated.
// Use GetVKCredentials or GetVKCredentialsWithToken instead.
func GetYandexCredentials(link string) (*Credentials, error) {
	return nil, ErrYandexDeprecated
}

// getYandexCredentialsImpl is the original implementation, kept for reference.
// nolint: unused
func getYandexCredentialsImpl(link string) (*Credentials, error) {
	// Extract just the conference ID if full URL provided
	if strings.Contains(link, "j/") {
		parts := strings.Split(link, "j/")
		link = parts[len(parts)-1]
	}
	if idx := strings.IndexAny(link, "/?#"); idx != -1 {
		link = link[:idx]
	}

	telemostConfPath := fmt.Sprintf("/telemost_front/v2/telemost/conferences/https%%3A%%2F%%2Ftelemost.yandex.ru%%2Fj%%2F%s/connection?next_gen_media_platform_allowed=false", link)
	const userAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:144.0) Gecko/20100101 Firefox/144.0"

	type conferenceResponse struct {
		URI                 string `json:"uri"`
		RoomID              string `json:"room_id"`
		PeerID              string `json:"peer_id"`
		ClientConfiguration struct {
			MediaServerURL string `json:"media_server_url"`
		} `json:"client_configuration"`
		Credentials string `json:"credentials"`
	}

	endpoint := yandexConfBaseURL + telemostConfPath
	client := &http.Client{
		Timeout: 20 * time.Second,
		Transport: &http.Transport{
			MaxIdleConns:        100,
			MaxIdleConnsPerHost: 100,
			IdleConnTimeout:     90 * time.Second,
		},
	}
	defer client.CloseIdleConnections()
	req, err := http.NewRequest("GET", endpoint, nil)
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
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("GetConference: status=%s body=%s", resp.Status, string(body))
	}

	var result conferenceResponse
	if err = json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decode conf: %v", err)
	}

	// WebSocket handshake to get ICE servers
	h := http.Header{}
	h.Set("Origin", "https://telemost.yandex.ru")
	h.Set("User-Agent", userAgent)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	dialer := websocket.Dialer{}
	conn, _, err := dialer.DialContext(ctx, result.ClientConfiguration.MediaServerURL, h)
	if err != nil {
		return nil, fmt.Errorf("ws dial: %w", err)
	}
	defer conn.Close()

	// Build hello request
	helloReq := buildHelloRequest(result.PeerID, result.RoomID, result.Credentials, userAgent)
	if err := conn.WriteJSON(helloReq); err != nil {
		return nil, fmt.Errorf("ws write: %w", err)
	}

	conn.SetReadDeadline(time.Now().Add(15 * time.Second))
	for {
		_, msg, err := conn.ReadMessage()
		if err != nil {
			return nil, fmt.Errorf("ws read: %w", err)
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

		// Parse server hello for ICE servers
		var wssResp struct {
			ServerHello struct {
				RtcConfiguration struct {
					IceServers []struct {
						Urls       flexUrls `json:"urls"`
						Username   string   `json:"username,omitempty"`
						Credential string   `json:"credential,omitempty"`
					} `json:"iceServers"`
				} `json:"rtcConfiguration"`
			} `json:"serverHello"`
		}
		if err := json.Unmarshal(msg, &wssResp); err == nil {
			ice := wssResp.ServerHello.RtcConfiguration.IceServers
			for _, s := range ice {
				for _, u := range s.Urls {
					if !strings.HasPrefix(u, "turn:") && !strings.HasPrefix(u, "turns:") {
						continue
					}
					if strings.Contains(u, "transport=tcp") {
						continue
					}
					clean := strings.Split(u, "?")[0]
					address := strings.TrimPrefix(strings.TrimPrefix(clean, "turn:"), "turns:")
					return &Credentials{Username: s.Username, Password: s.Credential, Address: address}, nil
				}
			}
		}
	}
}

// flexUrls handles JSON that can be either a string or []string for urls field.
type flexUrls []string

func (f *flexUrls) UnmarshalJSON(data []byte) error {
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

// YandexSession keeps a Telemost WebSocket alive to prevent credential expiry.
type YandexSession struct {
	creds  *Credentials
	conn   *websocket.Conn
	cancel context.CancelFunc
	done   chan struct{}
}

func (s *YandexSession) Credentials() *Credentials { return s.creds }

func (s *YandexSession) Close() error {
	s.cancel()
	<-s.done
	return s.conn.Close()
}

// GetYandexCredentialsWithKeepalive extracts TURN credentials and keeps the
// WebSocket session alive with periodic pings.
//
// Deprecated: Yandex Telemost blocked TURN relay to external IPs in March 2026.
// Returns ErrYandexDeprecated.
func GetYandexCredentialsWithKeepalive(link string) (*YandexSession, error) {
	return nil, ErrYandexDeprecated
}

// getYandexCredentialsWithKeepaliveImpl is the original implementation, kept for reference.
// nolint: unused
func getYandexCredentialsWithKeepaliveImpl(link string) (*YandexSession, error) {
	if strings.Contains(link, "j/") {
		parts := strings.Split(link, "j/")
		link = parts[len(parts)-1]
	}
	if idx := strings.IndexAny(link, "/?#"); idx != -1 {
		link = link[:idx]
	}

	telemostConfPath := fmt.Sprintf("/telemost_front/v2/telemost/conferences/https%%3A%%2F%%2Ftelemost.yandex.ru%%2Fj%%2F%s/connection?next_gen_media_platform_allowed=false", link)
	const userAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:144.0) Gecko/20100101 Firefox/144.0"

	type conferenceResponse struct {
		RoomID              string `json:"room_id"`
		PeerID              string `json:"peer_id"`
		ClientConfiguration struct {
			MediaServerURL string `json:"media_server_url"`
		} `json:"client_configuration"`
		Credentials string `json:"credentials"`
	}

	endpoint := yandexConfBaseURL + telemostConfPath
	client := &http.Client{Timeout: 20 * time.Second}
	defer client.CloseIdleConnections()
	req, err := http.NewRequest("GET", endpoint, nil)
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
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("GetConference: status=%s body=%s", resp.Status, string(body))
	}

	var result conferenceResponse
	if err = json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decode conf: %v", err)
	}

	h := http.Header{}
	h.Set("Origin", "https://telemost.yandex.ru")
	h.Set("User-Agent", userAgent)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	dialer := websocket.Dialer{}
	conn, _, err := dialer.DialContext(ctx, result.ClientConfiguration.MediaServerURL, h)
	if err != nil {
		return nil, fmt.Errorf("ws dial: %w", err)
	}

	helloReq := buildHelloRequest(result.PeerID, result.RoomID, result.Credentials, userAgent)
	if err := conn.WriteJSON(helloReq); err != nil {
		conn.Close()
		return nil, fmt.Errorf("ws write: %w", err)
	}

	// Read until we get TURN credentials
	conn.SetReadDeadline(time.Now().Add(15 * time.Second))
	var creds *Credentials
	for creds == nil {
		_, msg, err := conn.ReadMessage()
		if err != nil {
			conn.Close()
			return nil, fmt.Errorf("ws read: %w", err)
		}
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
		var wssResp struct {
			ServerHello struct {
				RtcConfiguration struct {
					IceServers []struct {
						Urls       flexUrls `json:"urls"`
						Username   string   `json:"username,omitempty"`
						Credential string   `json:"credential,omitempty"`
					} `json:"iceServers"`
				} `json:"rtcConfiguration"`
			} `json:"serverHello"`
		}
		if json.Unmarshal(msg, &wssResp) == nil {
			ice := wssResp.ServerHello.RtcConfiguration.IceServers
			for _, s := range ice {
				for _, u := range s.Urls {
					if !strings.HasPrefix(u, "turn:") && !strings.HasPrefix(u, "turns:") {
						continue
					}
					if strings.Contains(u, "transport=tcp") {
						continue
					}
					clean := strings.Split(u, "?")[0]
					address := strings.TrimPrefix(strings.TrimPrefix(clean, "turn:"), "turns:")
					creds = &Credentials{Username: s.Username, Password: s.Credential, Address: address}
					break
				}
				if creds != nil {
					break
				}
			}
		}
	}

	// Clear read deadline for keepalive phase
	conn.SetReadDeadline(time.Time{})

	// Start keepalive goroutine — sends WebSocket pings every 30 seconds
	kaCtx, kaCancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-kaCtx.Done():
				return
			case <-ticker.C:
				if err := conn.WriteControl(websocket.PingMessage, nil, time.Now().Add(5*time.Second)); err != nil {
					return
				}
			}
		}
	}()

	return &YandexSession{
		creds:  creds,
		conn:   conn,
		cancel: kaCancel,
		done:   done,
	}, nil
}

func buildHelloRequest(participantID, roomID, credentials, userAgent string) map[string]interface{} {
	return map[string]interface{}{
		"uid": uuid.New().String(),
		"hello": map[string]interface{}{
			"participantMeta": map[string]interface{}{
				"name": "Гость", "role": "SPEAKER", "description": "",
				"sendAudio": false, "sendVideo": false,
			},
			"participantAttributes": map[string]interface{}{
				"name": "Гость", "role": "SPEAKER", "description": "",
			},
			"sendAudio":              false,
			"sendVideo":              false,
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
