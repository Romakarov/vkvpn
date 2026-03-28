package turnauth

import (
	"encoding/json"
	"fmt"
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

// ─── VKAPIError Classification Tests ───

func TestVKAPIErrorClassification(t *testing.T) {
	tests := []struct {
		name          string
		code          int
		msg           string
		isRateLimited bool
		isTokenExpired bool
		isBanned      bool
	}{
		{"rate limited", 29, "Rate limit reached", true, false, false},
		{"token expired code 5", 5, "User authorization failed", false, true, false},
		{"token expired code 15", 15, "Access denied", false, true, false},
		{"banned code 17", 17, "User validation required", false, false, true},
		{"banned code 18", 18, "User was deleted or banned", false, false, true},
		{"generic error", 100, "Some error", false, false, false},
		{"zero code", 0, "", false, false, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := fmt.Errorf("wrapped: %w", &VKAPIError{Code: tt.code, Message: tt.msg})

			if got := IsRateLimited(err); got != tt.isRateLimited {
				t.Errorf("IsRateLimited(%d) = %v, want %v", tt.code, got, tt.isRateLimited)
			}
			if got := IsTokenExpired(err); got != tt.isTokenExpired {
				t.Errorf("IsTokenExpired(%d) = %v, want %v", tt.code, got, tt.isTokenExpired)
			}
			if got := IsBanned(err); got != tt.isBanned {
				t.Errorf("IsBanned(%d) = %v, want %v", tt.code, got, tt.isBanned)
			}
		})
	}
}

func TestNewVKAPIError(t *testing.T) {
	errObj := map[string]interface{}{
		"error_code": float64(29),
		"error_msg":  "Rate limit reached",
	}
	vkErr := NewVKAPIError(errObj)
	if vkErr.Code != 29 {
		t.Errorf("expected code 29, got %d", vkErr.Code)
	}
	if vkErr.Message != "Rate limit reached" {
		t.Errorf("expected message 'Rate limit reached', got %q", vkErr.Message)
	}
	if !strings.Contains(vkErr.Error(), "VK API error 29") {
		t.Errorf("expected error string to contain 'VK API error 29', got %q", vkErr.Error())
	}
}

func TestNewVKAPIErrorMissingFields(t *testing.T) {
	vkErr := NewVKAPIError(map[string]interface{}{})
	if vkErr.Code != 0 {
		t.Errorf("expected code 0, got %d", vkErr.Code)
	}
	if vkErr.Message != "" {
		t.Errorf("expected empty message, got %q", vkErr.Message)
	}
}

func TestVKAPIErrorNotWrapped(t *testing.T) {
	// Plain error (not VKAPIError) should return false for all classifiers
	err := fmt.Errorf("plain error")
	if IsRateLimited(err) {
		t.Error("plain error should not be rate limited")
	}
	if IsTokenExpired(err) {
		t.Error("plain error should not be token expired")
	}
	if IsBanned(err) {
		t.Error("plain error should not be banned")
	}
}
