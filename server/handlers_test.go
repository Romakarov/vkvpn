package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

// setupTestConfig creates a test config with temp file and sets the global cfg
func setupTestConfig(t *testing.T) func() {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")

	oldCfg := cfg
	cfg = &Config{
		path:       path,
		ServerIP:   "10.0.0.1",
		WGPort:     51820,
		WGSubnet:   "10.66.66.0/24",
		ServerPriv: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
		ServerPub:  "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=",
		DNS:        "1.1.1.1, 8.8.8.8",
		DTLSPort:   56000,
		AdminPass:  "testpass123",
		Clients: []Client{
			{
				Name:       "alice",
				PrivateKey: "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC=",
				PublicKey:  "DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD=",
				IP:         "10.66.66.2",
				CreatedAt:  "2025-01-01 00:00",
				Enabled:    true,
			},
		},
	}
	cfg.Save()

	return func() {
		cfg = oldCfg
		os.RemoveAll(dir)
	}
}

// ─── Auth Middleware Tests ───

func TestAuthNoToken(t *testing.T) {
	cleanup := setupTestConfig(t)
	defer cleanup()

	handler := authMiddleware(apiGetStatus)
	req := httptest.NewRequest("GET", "/api/status", nil)
	w := httptest.NewRecorder()
	handler(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

func TestAuthWrongToken(t *testing.T) {
	cleanup := setupTestConfig(t)
	defer cleanup()

	handler := authMiddleware(apiGetStatus)
	req := httptest.NewRequest("GET", "/api/status?token=wrongpass", nil)
	w := httptest.NewRecorder()
	handler(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

func TestAuthCorrectToken(t *testing.T) {
	cleanup := setupTestConfig(t)
	defer cleanup()

	handler := authMiddleware(apiGetStatus)
	req := httptest.NewRequest("GET", "/api/status?token=testpass123", nil)
	w := httptest.NewRecorder()
	handler(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}

func TestAuthHeader(t *testing.T) {
	cleanup := setupTestConfig(t)
	defer cleanup()

	handler := authMiddleware(apiGetStatus)
	req := httptest.NewRequest("GET", "/api/status", nil)
	req.Header.Set("X-Admin-Token", "testpass123")
	w := httptest.NewRecorder()
	handler(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}

func TestAuthCookie(t *testing.T) {
	cleanup := setupTestConfig(t)
	defer cleanup()

	handler := authMiddleware(apiGetStatus)
	req := httptest.NewRequest("GET", "/api/status", nil)
	req.AddCookie(&http.Cookie{Name: "admin_token", Value: "testpass123"})
	w := httptest.NewRecorder()
	handler(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}

// ─── GET /api/status ───

func TestApiGetStatus(t *testing.T) {
	cleanup := setupTestConfig(t)
	defer cleanup()

	req := httptest.NewRequest("GET", "/api/status", nil)
	w := httptest.NewRecorder()
	apiGetStatus(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if resp["server_ip"] != "10.0.0.1" {
		t.Fatalf("expected server_ip 10.0.0.1, got %v", resp["server_ip"])
	}
	if resp["clients"].(float64) != 1 {
		t.Fatalf("expected 1 client, got %v", resp["clients"])
	}
}

// ─── POST /api/clients/add ───

func TestApiAddClient(t *testing.T) {
	cleanup := setupTestConfig(t)
	defer cleanup()

	body := bytes.NewBufferString(`{"name":"bob"}`)
	req := httptest.NewRequest("POST", "/api/clients/add", body)
	w := httptest.NewRecorder()
	apiAddClient(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]string
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["status"] != "ok" {
		t.Fatalf("expected status ok, got %s", resp["status"])
	}
	if resp["ip"] != "10.66.66.3" {
		t.Fatalf("expected IP 10.66.66.3, got %s", resp["ip"])
	}

	// Verify client was added
	cfg.mu.RLock()
	found := false
	for _, cl := range cfg.Clients {
		if cl.Name == "bob" {
			found = true
		}
	}
	cfg.mu.RUnlock()
	if !found {
		t.Fatal("client bob not found after add")
	}
}

func TestApiAddClientEmptyName(t *testing.T) {
	cleanup := setupTestConfig(t)
	defer cleanup()

	body := bytes.NewBufferString(`{"name":""}`)
	req := httptest.NewRequest("POST", "/api/clients/add", body)
	w := httptest.NewRecorder()
	apiAddClient(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

func TestApiAddClientMethodNotAllowed(t *testing.T) {
	cleanup := setupTestConfig(t)
	defer cleanup()

	req := httptest.NewRequest("GET", "/api/clients/add", nil)
	w := httptest.NewRecorder()
	apiAddClient(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", w.Code)
	}
}

// ─── POST /api/clients/delete ───

func TestApiDeleteClient(t *testing.T) {
	cleanup := setupTestConfig(t)
	defer cleanup()

	body := bytes.NewBufferString(`{"name":"alice"}`)
	req := httptest.NewRequest("POST", "/api/clients/delete", body)
	w := httptest.NewRecorder()
	apiDeleteClient(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	cfg.mu.RLock()
	if len(cfg.Clients) != 0 {
		t.Fatalf("expected 0 clients, got %d", len(cfg.Clients))
	}
	cfg.mu.RUnlock()
}

func TestApiDeleteClientNotFound(t *testing.T) {
	cleanup := setupTestConfig(t)
	defer cleanup()

	body := bytes.NewBufferString(`{"name":"nonexistent"}`)
	req := httptest.NewRequest("POST", "/api/clients/delete", body)
	w := httptest.NewRecorder()
	apiDeleteClient(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", w.Code)
	}
}

// ─── POST /api/clients/toggle ───

func TestApiToggleClient(t *testing.T) {
	cleanup := setupTestConfig(t)
	defer cleanup()

	// Alice starts enabled
	body := bytes.NewBufferString(`{"name":"alice"}`)
	req := httptest.NewRequest("POST", "/api/clients/toggle", body)
	w := httptest.NewRecorder()
	apiToggleClient(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	cfg.mu.RLock()
	if cfg.Clients[0].Enabled {
		t.Fatal("expected alice to be disabled after toggle")
	}
	cfg.mu.RUnlock()
}

// ─── GET /api/clients/config ───

func TestApiClientConfig(t *testing.T) {
	cleanup := setupTestConfig(t)
	defer cleanup()

	req := httptest.NewRequest("GET", "/api/clients/config?name=alice", nil)
	w := httptest.NewRecorder()
	apiClientConfig(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var resp map[string]string
	json.Unmarshal(w.Body.Bytes(), &resp)
	conf := resp["config"]
	if !containsStr(conf, "PrivateKey = CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC=") {
		t.Fatal("missing PrivateKey in config")
	}
	if !containsStr(conf, "MTU = 1280") {
		t.Fatal("missing MTU in config")
	}
}

func TestApiClientConfigNotFound(t *testing.T) {
	cleanup := setupTestConfig(t)
	defer cleanup()

	req := httptest.NewRequest("GET", "/api/clients/config?name=unknown", nil)
	w := httptest.NewRecorder()
	apiClientConfig(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", w.Code)
	}
}

func TestApiClientConfigNoName(t *testing.T) {
	cleanup := setupTestConfig(t)
	defer cleanup()

	req := httptest.NewRequest("GET", "/api/clients/config", nil)
	w := httptest.NewRecorder()
	apiClientConfig(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

// ─── GET /api/clients/appconfig ───

func TestApiAppConfig(t *testing.T) {
	cleanup := setupTestConfig(t)
	defer cleanup()

	cfg.mu.Lock()
	cfg.ActiveLink = "https://vk.com/call/join/abc123"
	cfg.LinkType = "vk"
	cfg.mu.Unlock()

	req := httptest.NewRequest("GET", "/api/clients/appconfig?name=alice", nil)
	w := httptest.NewRecorder()
	apiAppConfig(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)

	if resp["server"] != "10.0.0.1" {
		t.Fatalf("expected server 10.0.0.1, got %v", resp["server"])
	}
	if resp["provider"] != "vk" {
		t.Fatalf("expected provider vk, got %v", resp["provider"])
	}
	if resp["wg_address"] != "10.66.66.2" {
		t.Fatalf("expected wg_address 10.66.66.2, got %v", resp["wg_address"])
	}
	if resp["dtls_fingerprint"] == nil {
		t.Fatal("expected dtls_fingerprint field")
	}
}

// ─── POST /api/link ───

func TestApiSetLink(t *testing.T) {
	cleanup := setupTestConfig(t)
	defer cleanup()

	body := bytes.NewBufferString(`{"link":"https://vk.com/call/join/test123"}`)
	req := httptest.NewRequest("POST", "/api/link", body)
	w := httptest.NewRecorder()
	apiSetLink(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	cfg.mu.RLock()
	if cfg.ActiveLink != "https://vk.com/call/join/test123" {
		t.Fatalf("expected link to be set, got %s", cfg.ActiveLink)
	}
	if cfg.LinkType != "vk" {
		t.Fatalf("expected type vk, got %s", cfg.LinkType)
	}
	cfg.mu.RUnlock()
}

func TestApiSetLinkYandex(t *testing.T) {
	cleanup := setupTestConfig(t)
	defer cleanup()

	body := bytes.NewBufferString(`{"link":"https://telemost.yandex.ru/j/123456"}`)
	req := httptest.NewRequest("POST", "/api/link", body)
	w := httptest.NewRecorder()
	apiSetLink(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	cfg.mu.RLock()
	if cfg.LinkType != "yandex" {
		t.Fatalf("expected type yandex, got %s", cfg.LinkType)
	}
	cfg.mu.RUnlock()
}

func TestApiSetLinkUnknownType(t *testing.T) {
	cleanup := setupTestConfig(t)
	defer cleanup()

	body := bytes.NewBufferString(`{"link":"https://example.com/unknown"}`)
	req := httptest.NewRequest("POST", "/api/link", body)
	w := httptest.NewRecorder()
	apiSetLink(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

// ─── GET /api/clients (list) ───

func TestApiListClients(t *testing.T) {
	cleanup := setupTestConfig(t)
	defer cleanup()

	req := httptest.NewRequest("GET", "/api/clients", nil)
	w := httptest.NewRecorder()
	apiListClients(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var clients []map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &clients)
	if len(clients) != 1 {
		t.Fatalf("expected 1 client, got %d", len(clients))
	}
	if clients[0]["name"] != "alice" {
		t.Fatalf("expected alice, got %v", clients[0]["name"])
	}
}

// ─── GET /api/logs ───

func TestApiLogs(t *testing.T) {
	cleanup := setupTestConfig(t)
	defer cleanup()

	req := httptest.NewRequest("GET", "/api/logs", nil)
	w := httptest.NewRecorder()
	apiLogs(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}

// ─── Bcrypt Auth ───

func TestAuthBcrypt(t *testing.T) {
	cleanup := setupTestConfig(t)
	defer cleanup()

	// Set bcrypt hash and clear plaintext
	hash, _ := bcrypt.GenerateFromPassword([]byte("securepass"), bcrypt.DefaultCost)
	cfg.mu.Lock()
	cfg.AdminPassHash = string(hash)
	cfg.AdminPass = ""
	cfg.mu.Unlock()

	handler := authMiddleware(apiGetStatus)

	// Correct password
	req := httptest.NewRequest("GET", "/api/status?token=securepass", nil)
	w := httptest.NewRecorder()
	handler(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 with correct bcrypt pass, got %d", w.Code)
	}

	// Wrong password
	req = httptest.NewRequest("GET", "/api/status?token=wrongpass", nil)
	w = httptest.NewRecorder()
	handler(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 with wrong pass, got %d", w.Code)
	}
}

// ─── Input Validation ───

func TestApiAddClientInvalidName(t *testing.T) {
	cleanup := setupTestConfig(t)
	defer cleanup()

	body := bytes.NewBufferString(`{"name":"bad name!@#"}`)
	req := httptest.NewRequest("POST", "/api/clients/add", body)
	w := httptest.NewRecorder()
	apiAddClient(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid name, got %d", w.Code)
	}
}

func TestApiAddClientDuplicate(t *testing.T) {
	cleanup := setupTestConfig(t)
	defer cleanup()

	body := bytes.NewBufferString(`{"name":"alice"}`)
	req := httptest.NewRequest("POST", "/api/clients/add", body)
	w := httptest.NewRecorder()
	apiAddClient(w, req)

	if w.Code != http.StatusConflict {
		t.Fatalf("expected 409 for duplicate, got %d", w.Code)
	}
}

// ─── Health Check ───

func TestApiHealth(t *testing.T) {
	req := httptest.NewRequest("GET", "/api/health", nil)
	w := httptest.NewRecorder()
	apiHealth(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["status"] != "ok" {
		t.Fatalf("expected status ok, got %v", resp["status"])
	}
	if resp["version"] == nil {
		t.Fatal("missing version in health response")
	}
}

func TestRateLimiting(t *testing.T) {
	cleanup := setupTestConfig(t)
	defer cleanup()

	// Reset the global rate limiter
	authLimiter = &rateLimiter{failures: make(map[string]*failEntry)}

	handler := authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// Send 10 bad requests — all should get 401
	for i := 0; i < rateLimitMaxFail; i++ {
		req := httptest.NewRequest("GET", "/api/status?token=wrong", nil)
		req.RemoteAddr = "1.2.3.4:12345"
		w := httptest.NewRecorder()
		handler(w, req)
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("request %d: expected 401, got %d", i+1, w.Code)
		}
	}

	// 11th request should get 429
	req := httptest.NewRequest("GET", "/api/status?token=wrong", nil)
	req.RemoteAddr = "1.2.3.4:12345"
	w := httptest.NewRecorder()
	handler(w, req)
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429, got %d", w.Code)
	}

	// Correct password should still be blocked (rate limited)
	req = httptest.NewRequest("GET", "/api/status?token=testpass123", nil)
	req.RemoteAddr = "1.2.3.4:12345"
	w = httptest.NewRecorder()
	handler(w, req)
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429 even with correct pass, got %d", w.Code)
	}

	// Different IP should not be rate limited
	req = httptest.NewRequest("GET", "/api/status?token=testpass123", nil)
	req.RemoteAddr = "5.6.7.8:12345"
	w = httptest.NewRecorder()
	handler(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("different IP: expected 200, got %d", w.Code)
	}
}
