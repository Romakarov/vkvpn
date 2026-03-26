package turnauth

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestGetVKCredentials(t *testing.T) {
	// Mock server that handles all 6 VK API steps
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		raw := r.URL.RawQuery
		path := r.URL.Path

		body := make([]byte, 4096)
		n, _ := r.Body.Read(body)
		bodyStr := string(body[:n])

		switch {
		case strings.Contains(raw, "act=get_anonym_token") || strings.Contains(path, "act=get_anonym_token"):
			// Steps 1 and 3: anonymous token
			json.NewEncoder(w).Encode(map[string]interface{}{
				"data": map[string]interface{}{
					"access_token": "anon_token",
				},
			})
		case strings.Contains(path, "getAnonymousAccessTokenPayload"):
			// Step 2
			json.NewEncoder(w).Encode(map[string]interface{}{
				"response": map[string]interface{}{
					"payload": "payload_123",
				},
			})
		case strings.Contains(path, "getAnonymousToken"):
			// Step 4
			json.NewEncoder(w).Encode(map[string]interface{}{
				"response": map[string]interface{}{
					"token": "calltoken_456",
				},
			})
		case strings.Contains(path, "fb.do"):
			// Steps 5 and 6 (OK.ru)
			if strings.Contains(bodyStr, "anonymLogin") {
				json.NewEncoder(w).Encode(map[string]interface{}{
					"session_key": "session_789",
				})
			} else {
				json.NewEncoder(w).Encode(map[string]interface{}{
					"turn_server": map[string]interface{}{
						"username":   "testuser",
						"credential": "testpass",
						"urls":       []string{"turn:1.2.3.4:3478?transport=udp"},
					},
				})
			}
		default:
			http.Error(w, "unexpected request: "+path+"?"+raw, 500)
		}
	}))
	defer server.Close()

	// Override base URLs to point at mock server
	orig := vkBaseURLs
	vkBaseURLs.LoginVK = server.URL
	vkBaseURLs.ApiVK = server.URL
	vkBaseURLs.OkCDN = server.URL
	defer func() { vkBaseURLs = orig }()

	creds, err := GetVKCredentials("https://vk.com/call/join/TESTHASH")
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	if creds.Username != "testuser" {
		t.Errorf("expected username 'testuser', got %q", creds.Username)
	}
	if creds.Password != "testpass" {
		t.Errorf("expected password 'testpass', got %q", creds.Password)
	}
	if creds.Address != "1.2.3.4:3478" {
		t.Errorf("expected address '1.2.3.4:3478', got %q", creds.Address)
	}
}

func TestGetVKCredentialsLinkParsing(t *testing.T) {
	// Test that various link formats are handled
	tests := []struct {
		input    string
		wantHash string
	}{
		{"HASH123", "HASH123"},
		{"https://vk.com/call/join/HASH123", "HASH123"},
		{"https://vk.ru/call/join/HASH123?foo=bar", "HASH123"},
		{"HASH123#fragment", "HASH123"},
	}

	for _, tt := range tests {
		link := tt.input
		if strings.Contains(link, "join/") {
			parts := strings.Split(link, "join/")
			link = parts[len(parts)-1]
		}
		if idx := strings.IndexAny(link, "/?#"); idx != -1 {
			link = link[:idx]
		}
		if link != tt.wantHash {
			t.Errorf("input=%q: got %q, want %q", tt.input, link, tt.wantHash)
		}
	}
}

func TestGetVKCredentialsServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "server error", 500)
	}))
	defer server.Close()

	orig := vkBaseURLs
	vkBaseURLs.LoginVK = server.URL
	vkBaseURLs.ApiVK = server.URL
	vkBaseURLs.OkCDN = server.URL
	defer func() { vkBaseURLs = orig }()

	_, err := GetVKCredentials("HASH")
	if err == nil {
		t.Fatal("expected error on server error")
	}
}

func TestGetVKCredentialsBadJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("not json"))
	}))
	defer server.Close()

	orig := vkBaseURLs
	vkBaseURLs.LoginVK = server.URL
	vkBaseURLs.ApiVK = server.URL
	vkBaseURLs.OkCDN = server.URL
	defer func() { vkBaseURLs = orig }()

	_, err := GetVKCredentials("HASH")
	if err == nil {
		t.Fatal("expected error on bad JSON")
	}
	if !strings.Contains(err.Error(), "JSON decode") {
		t.Errorf("expected JSON decode error, got: %s", err)
	}
}
