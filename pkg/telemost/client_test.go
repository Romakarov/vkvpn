package telemost

import (
	"encoding/json"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/gorilla/websocket"
)

func testLogger() *log.Logger {
	return log.New(os.Stderr, "test: ", log.LstdFlags)
}

func TestParseConfID(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"12345", "12345"},
		{"https://telemost.yandex.ru/j/12345", "12345"},
		{"https://telemost.yandex.ru/j/12345?key=val", "12345"},
		{"https://telemost.yandex.ru/j/12345#frag", "12345"},
		{"telemost.yandex.ru/j/ABC-DEF-123", "ABC-DEF-123"},
	}
	for _, tt := range tests {
		got := parseConfID(tt.input)
		if got != tt.want {
			t.Errorf("parseConfID(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestBuildHello(t *testing.T) {
	hello := buildHello("peer1", "room1", "cred1")
	helloData, ok := hello["hello"].(map[string]interface{})
	if !ok {
		t.Fatal("hello field missing")
	}
	if helloData["participantId"] != "peer1" {
		t.Errorf("expected peer1, got %v", helloData["participantId"])
	}
	if helloData["roomId"] != "room1" {
		t.Errorf("expected room1, got %v", helloData["roomId"])
	}
	if helloData["credentials"] != "cred1" {
		t.Errorf("expected cred1, got %v", helloData["credentials"])
	}
	if helloData["serviceName"] != "telemost" {
		t.Errorf("expected telemost, got %v", helloData["serviceName"])
	}
}

func TestFlexURLs(t *testing.T) {
	// Single string
	var f1 flexURLs
	if err := json.Unmarshal([]byte(`"turn:1.2.3.4:3478"`), &f1); err != nil {
		t.Fatal(err)
	}
	if len(f1) != 1 || f1[0] != "turn:1.2.3.4:3478" {
		t.Errorf("single: got %v", f1)
	}

	// Array
	var f2 flexURLs
	if err := json.Unmarshal([]byte(`["turn:a:3478","stun:b:3478"]`), &f2); err != nil {
		t.Fatal(err)
	}
	if len(f2) != 2 {
		t.Errorf("array: got %v", f2)
	}
}

func TestToPionICEServers(t *testing.T) {
	servers := []iceServerConfig{
		{
			URLs:       flexURLs{"turn:1.2.3.4:3478", "turn:1.2.3.4:3478?transport=tcp"},
			Username:   "user",
			Credential: "pass",
		},
		{
			URLs: flexURLs{"stun:stun.example.com:3478"},
		},
	}

	pion := toPionICEServers(servers)
	if len(pion) != 2 {
		t.Fatalf("expected 2 servers, got %d", len(pion))
	}
	if pion[0].Username != "user" {
		t.Errorf("expected username 'user', got %q", pion[0].Username)
	}
	if len(pion[0].URLs) != 2 {
		t.Errorf("expected 2 URLs, got %d", len(pion[0].URLs))
	}
}

func TestFetchConferenceInfo(t *testing.T) {
	// Mock Telemost conference API
	wsUpgrader := websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}

	mux := http.NewServeMux()
	mux.HandleFunc("/telemost_front/", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"room_id": "room-test",
			"peer_id": "peer-test",
			"client_configuration": map[string]interface{}{
				"media_server_url": "ws://localhost/ws",
			},
			"credentials": "cred-test",
		})
	})
	mux.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
		conn, err := wsUpgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()

		// Read hello
		conn.ReadMessage()

		// Send serverHello with ICE servers
		conn.WriteJSON(map[string]interface{}{
			"serverHello": map[string]interface{}{
				"rtcConfiguration": map[string]interface{}{
					"iceServers": []map[string]interface{}{
						{
							"urls":       []string{"turn:10.0.0.1:3478?transport=udp"},
							"username":   "test-user",
							"credential": "test-pass",
						},
					},
				},
			},
		})
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	// Override base URL
	orig := confBaseURL
	confBaseURL = server.URL
	defer func() { confBaseURL = orig }()

	info, err := fetchConferenceInfo(t.Context(), "12345")
	if err != nil {
		t.Fatalf("fetchConferenceInfo: %v", err)
	}
	if info.RoomID != "room-test" {
		t.Errorf("expected room-test, got %q", info.RoomID)
	}
	if info.PeerID != "peer-test" {
		t.Errorf("expected peer-test, got %q", info.PeerID)
	}
	if info.Credentials != "cred-test" {
		t.Errorf("expected cred-test, got %q", info.Credentials)
	}
}

func TestConnectSFU(t *testing.T) {
	wsUpgrader := websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := wsUpgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()

		// Read hello
		conn.ReadMessage()

		// Send ACK first (should be skipped)
		conn.WriteJSON(map[string]interface{}{
			"ack": map[string]interface{}{
				"status": map[string]interface{}{
					"code": "OK",
				},
			},
		})

		// Send serverHello
		conn.WriteJSON(map[string]interface{}{
			"serverHello": map[string]interface{}{
				"rtcConfiguration": map[string]interface{}{
					"iceServers": []map[string]interface{}{
						{
							"urls":       "turn:10.0.0.1:3478?transport=udp",
							"username":   "yandex-user",
							"credential": "yandex-pass",
						},
					},
				},
			},
		})
	}))
	defer server.Close()

	wsURL := "ws" + strings.TrimPrefix(server.URL, "http")
	info := &conferenceInfo{
		RoomID:      "room1",
		PeerID:      "peer1",
		MediaURL:    wsURL,
		Credentials: "cred1",
	}

	sfu, iceServers, err := connectSFU(t.Context(), info)
	if err != nil {
		t.Fatalf("connectSFU: %v", err)
	}
	defer sfu.close()

	if len(iceServers) != 1 {
		t.Fatalf("expected 1 ICE server, got %d", len(iceServers))
	}
	if iceServers[0].Username != "yandex-user" {
		t.Errorf("expected yandex-user, got %q", iceServers[0].Username)
	}
}

func TestNewClient(t *testing.T) {
	c := NewClient(testLogger())
	if c == nil {
		t.Fatal("NewClient returned nil")
	}
	c.Close()
	// Double close should be safe
	c.Close()
}
