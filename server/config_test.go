package main

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"
)

func TestLoadConfigEmpty(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	cfg, err := loadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg == nil {
		t.Fatal("config is nil")
	}
	if cfg.WGPort != 0 {
		t.Fatalf("expected 0, got %d", cfg.WGPort)
	}
}

func TestLoadConfigExisting(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")

	b := []byte(`{
		"server_ip": "1.2.3.4",
		"wg_port": 51820,
		"wg_subnet": "10.66.66.0/24",
		"dns": "1.1.1.1",
		"clients": [{"name": "test", "ip": "10.66.66.2", "public_key": "abc", "enabled": true}]
	}`)
	os.WriteFile(path, b, 0600)

	cfg, err := loadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ServerIP != "1.2.3.4" {
		t.Fatalf("expected 1.2.3.4, got %s", cfg.ServerIP)
	}
	if len(cfg.Clients) != 1 {
		t.Fatalf("expected 1 client, got %d", len(cfg.Clients))
	}
}

func TestConfigSave(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")

	cfg := &Config{path: path, ServerIP: "5.6.7.8", WGPort: 51820}
	if err := cfg.Save(); err != nil {
		t.Fatal(err)
	}

	cfg2, err := loadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg2.ServerIP != "5.6.7.8" {
		t.Fatalf("expected 5.6.7.8, got %s", cfg2.ServerIP)
	}
}

func TestNextIP(t *testing.T) {
	cfg := &Config{
		WGSubnet: "10.66.66.0/24",
		Clients:  []Client{},
	}

	ip := cfg.nextIP()
	if ip != "10.66.66.2" {
		t.Fatalf("expected 10.66.66.2, got %s", ip)
	}

	cfg.Clients = append(cfg.Clients, Client{IP: "10.66.66.2"})
	ip = cfg.nextIP()
	if ip != "10.66.66.3" {
		t.Fatalf("expected 10.66.66.3, got %s", ip)
	}
}

func TestClientConfig(t *testing.T) {
	cfg := &Config{
		ServerIP:  "144.124.247.27",
		WGPort:    51820,
		ServerPub: "SERVERPUBKEY123=",
		DNS:       "1.1.1.1, 8.8.8.8",
	}
	cl := Client{
		PrivateKey: "CLIENTPRIVKEY123=",
		IP:         "10.66.66.2",
	}

	conf := cfg.clientConfig(cl)
	if conf == "" {
		t.Fatal("empty config")
	}
	// Check essential fields
	if !contains(conf, "PrivateKey = CLIENTPRIVKEY123=") {
		t.Fatal("missing PrivateKey")
	}
	if !contains(conf, "Address = 10.66.66.2/32") {
		t.Fatal("missing Address")
	}
	if !contains(conf, "Endpoint = 144.124.247.27:51820") {
		t.Fatal("missing Endpoint")
	}
	if !contains(conf, "MTU = 1280") {
		t.Fatal("missing MTU")
	}
	if !contains(conf, "AllowedIPs = 0.0.0.0/0") {
		t.Fatal("missing AllowedIPs")
	}
}

func TestWgGenKey(t *testing.T) {
	priv, pub, err := wgGenKey()
	if err != nil {
		t.Fatal(err)
	}

	// Verify base64 encoding and key lengths
	privBytes, err := base64.StdEncoding.DecodeString(priv)
	if err != nil {
		t.Fatalf("invalid base64 private key: %v", err)
	}
	if len(privBytes) != 32 {
		t.Fatalf("expected 32-byte private key, got %d", len(privBytes))
	}

	pubBytes, err := base64.StdEncoding.DecodeString(pub)
	if err != nil {
		t.Fatalf("invalid base64 public key: %v", err)
	}
	if len(pubBytes) != 32 {
		t.Fatalf("expected 32-byte public key, got %d", len(pubBytes))
	}

	// Verify clamping
	if privBytes[0]&7 != 0 {
		t.Fatal("private key not clamped: low bits")
	}
	if privBytes[31]&128 != 0 {
		t.Fatal("private key not clamped: high bit")
	}
	if privBytes[31]&64 == 0 {
		t.Fatal("private key not clamped: bit 254")
	}

	// Verify uniqueness
	priv2, pub2, err := wgGenKey()
	if err != nil {
		t.Fatal(err)
	}
	if priv == priv2 {
		t.Fatal("generated duplicate private keys")
	}
	if pub == pub2 {
		t.Fatal("generated duplicate public keys")
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(s) > 0 && containsStr(s, sub))
}

func containsStr(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
