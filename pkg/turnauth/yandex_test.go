package turnauth

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gorilla/websocket"
)

func TestGetYandexCredentials(t *testing.T) {
	// Mock WebSocket server that returns ICE servers
	wsUpgrader := websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}

	mux := http.NewServeMux()
	// Conference API
	mux.HandleFunc("/telemost_front/", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"room_id": "room123",
			"peer_id": "peer456",
			"client_configuration": map[string]interface{}{
				"media_server_url": "", // will be set below
			},
			"credentials": "cred789",
		})
	})
	// WebSocket endpoint
	mux.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
		conn, err := wsUpgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()

		// Read hello
		_, _, err = conn.ReadMessage()
		if err != nil {
			return
		}

		// Send server hello with ICE servers
		resp := map[string]interface{}{
			"serverHello": map[string]interface{}{
				"rtcConfiguration": map[string]interface{}{
					"iceServers": []map[string]interface{}{
						{
							"urls":       []string{"stun:stun.example.com:3478"},
							"username":   "",
							"credential": "",
						},
						{
							"urls":       []string{"turn:10.0.0.1:3478?transport=udp", "turn:10.0.0.1:3478?transport=tcp"},
							"username":   "yandex_user",
							"credential": "yandex_pass",
						},
					},
				},
			},
		}
		conn.WriteJSON(resp)
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	wsURL := "ws" + strings.TrimPrefix(server.URL, "http") + "/ws"

	// Override conference endpoint to return correct WS URL
	mux2 := http.NewServeMux()
	mux2.HandleFunc("/telemost_front/", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"room_id": "room123",
			"peer_id": "peer456",
			"client_configuration": map[string]interface{}{
				"media_server_url": wsURL,
			},
			"credentials": "cred789",
		})
	})
	mux2.HandleFunc("/ws", mux.ServeHTTP)
	server2 := httptest.NewServer(mux2)
	defer server2.Close()

	// Override base URL
	orig := yandexConfBaseURL
	yandexConfBaseURL = server2.URL
	defer func() { yandexConfBaseURL = orig }()

	creds, err := GetYandexCredentials("https://telemost.yandex.ru/j/12345")
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	if creds.Username != "yandex_user" {
		t.Errorf("expected username 'yandex_user', got %q", creds.Username)
	}
	if creds.Password != "yandex_pass" {
		t.Errorf("expected password 'yandex_pass', got %q", creds.Password)
	}
	if creds.Address != "10.0.0.1:3478" {
		t.Errorf("expected address '10.0.0.1:3478', got %q", creds.Address)
	}
}

func TestGetYandexCredentialsLinkParsing(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"12345", "12345"},
		{"https://telemost.yandex.ru/j/12345", "12345"},
		{"https://telemost.yandex.ru/j/12345?key=val", "12345"},
	}
	for _, tt := range tests {
		link := tt.input
		if strings.Contains(link, "j/") {
			parts := strings.Split(link, "j/")
			link = parts[len(parts)-1]
		}
		if idx := strings.IndexAny(link, "/?#"); idx != -1 {
			link = link[:idx]
		}
		if link != tt.want {
			t.Errorf("input=%q: got %q, want %q", tt.input, link, tt.want)
		}
	}
}

func TestGetYandexCredentialsServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "error", 500)
	}))
	defer server.Close()

	orig := yandexConfBaseURL
	yandexConfBaseURL = server.URL
	defer func() { yandexConfBaseURL = orig }()

	_, err := GetYandexCredentials("12345")
	if err == nil {
		t.Fatal("expected error on server error")
	}
}

func TestFlexUrls(t *testing.T) {
	// Test single string
	var f flexUrls
	if err := json.Unmarshal([]byte(`"turn:example.com:3478"`), &f); err != nil {
		t.Fatal(err)
	}
	if len(f) != 1 || f[0] != "turn:example.com:3478" {
		t.Errorf("single string: got %v", f)
	}

	// Test array
	var f2 flexUrls
	if err := json.Unmarshal([]byte(`["turn:a:3478","turn:b:3478"]`), &f2); err != nil {
		t.Fatal(err)
	}
	if len(f2) != 2 {
		t.Errorf("array: got %v", f2)
	}
}

func TestBuildHelloRequest(t *testing.T) {
	req := buildHelloRequest("peer1", "room1", "cred1", "ua")
	hello, ok := req["hello"].(map[string]interface{})
	if !ok {
		t.Fatal("hello not a map")
	}
	if hello["participantId"] != "peer1" {
		t.Errorf("expected peer1, got %v", hello["participantId"])
	}
	if hello["roomId"] != "room1" {
		t.Errorf("expected room1, got %v", hello["roomId"])
	}
	if hello["credentials"] != "cred1" {
		t.Errorf("expected cred1, got %v", hello["credentials"])
	}
}
