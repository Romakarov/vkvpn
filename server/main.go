package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"math/big"

	"regexp"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/curve25519"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/pion/dtls/v3"
	"github.com/pion/dtls/v3/pkg/crypto/selfsign"
)

//go:embed web/*
var webFS embed.FS

// ─── Config ───

type Config struct {
	mu          sync.RWMutex
	path        string
	ServerIP    string   `json:"server_ip"`
	WGPort      int      `json:"wg_port"`
	WGSubnet    string   `json:"wg_subnet"`
	ServerPriv  string   `json:"server_private_key"`
	ServerPub   string   `json:"server_public_key"`
	DNS         string   `json:"dns"`
	ActiveLink  string   `json:"active_link"`
	LinkType    string   `json:"link_type"`
	Clients     []Client    `json:"clients"`
	Links       []LinkEntry `json:"links,omitempty"`
	DTLSPort      int      `json:"dtls_port"`
	AdminPass     string   `json:"admin_pass,omitempty"`     // legacy plaintext, migrated on startup
	AdminPassHash string   `json:"admin_pass_hash,omitempty"` // bcrypt hash
}

type Client struct {
	Name       string `json:"name"`
	PrivateKey string `json:"private_key,omitempty"` // deprecated: only for legacy clients
	PublicKey  string `json:"public_key"`
	IP         string `json:"ip"`
	CreatedAt  string `json:"created_at"`
	Enabled    bool   `json:"enabled"`
}

type LinkEntry struct {
	URL     string `json:"url"`
	Type    string `json:"type"`    // "vk" or "yandex"
	AddedAt string `json:"added_at"` // RFC3339
	Active  bool   `json:"active"`
}

func loadConfig(path string) (*Config, error) {
	cfg := &Config{path: path}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return cfg, nil
		}
		return nil, err
	}
	if err := json.Unmarshal(data, cfg); err != nil {
		return nil, err
	}
	cfg.path = path
	return cfg, nil
}

func (c *Config) Save() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	// Backup existing config before overwriting
	if _, err := os.Stat(c.path); err == nil {
		backupDir := filepath.Join(filepath.Dir(c.path), "backups")
		os.MkdirAll(backupDir, 0700)
		ts := time.Now().Format("20060102-150405")
		backupPath := filepath.Join(backupDir, fmt.Sprintf("config-%s.json", ts))
		if old, err := os.ReadFile(c.path); err == nil {
			os.WriteFile(backupPath, old, 0600)
		}
		// Rotate: keep last 10 backups
		entries, _ := os.ReadDir(backupDir)
		if len(entries) > 10 {
			for _, e := range entries[:len(entries)-10] {
				os.Remove(filepath.Join(backupDir, e.Name()))
			}
		}
	}
	return os.WriteFile(c.path, data, 0600)
}

// ─── WireGuard management ───

func wgGenKey() (priv, pub string, err error) {
	var key [32]byte
	if _, err := rand.Read(key[:]); err != nil {
		return "", "", fmt.Errorf("generate key: %w", err)
	}
	// Clamp private key per Curve25519 spec
	key[0] &= 248
	key[31] &= 127
	key[31] |= 64
	priv = base64.StdEncoding.EncodeToString(key[:])

	pubKey, err := curve25519.X25519(key[:], curve25519.Basepoint)
	if err != nil {
		return "", "", fmt.Errorf("derive pubkey: %w", err)
	}
	pub = base64.StdEncoding.EncodeToString(pubKey)
	return priv, pub, nil
}

func (c *Config) nextIP() string {
	// Subnet like 10.0.0.0/24 — server is .1, clients start from .2
	parts := strings.Split(c.WGSubnet, "/")
	base := parts[0]
	octets := strings.Split(base, ".")
	used := map[string]bool{"1": true} // server
	for _, cl := range c.Clients {
		ipParts := strings.Split(cl.IP, ".")
		if len(ipParts) == 4 {
			used[ipParts[3]] = true
		}
	}
	for i := 2; i <= 254; i++ {
		s := fmt.Sprintf("%d", i)
		if !used[s] {
			return fmt.Sprintf("%s.%s.%s.%d", octets[0], octets[1], octets[2], i)
		}
	}
	return ""
}

func detectInterface() string {
	out, err := exec.Command("ip", "route", "get", "1.1.1.1").Output()
	if err != nil {
		return "eth0"
	}
	fields := strings.Fields(string(out))
	for i, f := range fields {
		if f == "dev" && i+1 < len(fields) {
			return fields[i+1]
		}
	}
	return "eth0"
}

func (c *Config) applyWireGuard() error {
	c.mu.RLock()
	defer c.mu.RUnlock()
	confPath := "/etc/wireguard/wg0.conf"
	iface := detectInterface()
	var sb strings.Builder
	sb.WriteString("[Interface]\n")
	sb.WriteString(fmt.Sprintf("PrivateKey = %s\n", c.ServerPriv))
	sb.WriteString(fmt.Sprintf("Address = %s\n", strings.Replace(c.WGSubnet, ".0/", ".1/", 1)))
	sb.WriteString(fmt.Sprintf("ListenPort = %d\n", c.WGPort))
	sb.WriteString(fmt.Sprintf("PostUp = iptables -A FORWARD -i wg0 -j ACCEPT; iptables -t nat -A POSTROUTING -o %s -j MASQUERADE\n", iface))
	sb.WriteString(fmt.Sprintf("PostDown = iptables -D FORWARD -i wg0 -j ACCEPT; iptables -t nat -D POSTROUTING -o %s -j MASQUERADE\n", iface))
	sb.WriteString("\n")

	for _, cl := range c.Clients {
		if !cl.Enabled {
			continue
		}
		sb.WriteString("[Peer]\n")
		sb.WriteString(fmt.Sprintf("PublicKey = %s\n", cl.PublicKey))
		sb.WriteString(fmt.Sprintf("AllowedIPs = %s/32\n", cl.IP))
		sb.WriteString("\n")
	}

	if err := os.WriteFile(confPath, []byte(sb.String()), 0600); err != nil {
		return fmt.Errorf("write wg0.conf: %w", err)
	}

	// Restart WireGuard with new config
	exec.Command("systemctl", "restart", "wg-quick@wg0").Run()
	return nil
}

func (c *Config) clientConfig(cl Client) string {
	serverAddr := c.ServerIP
	if serverAddr == "" {
		serverAddr = "YOUR_SERVER_IP"
	}
	var sb strings.Builder
	sb.WriteString("[Interface]\n")
	sb.WriteString(fmt.Sprintf("PrivateKey = %s\n", cl.PrivateKey))
	sb.WriteString(fmt.Sprintf("Address = %s/32\n", cl.IP))
	sb.WriteString(fmt.Sprintf("DNS = %s\n", c.DNS))
	sb.WriteString("MTU = 1280\n")
	sb.WriteString("\n")
	sb.WriteString("[Peer]\n")
	sb.WriteString(fmt.Sprintf("PublicKey = %s\n", c.ServerPub))
	sb.WriteString(fmt.Sprintf("Endpoint = %s:%d\n", serverAddr, c.WGPort))
	sb.WriteString("AllowedIPs = 0.0.0.0/0\n")
	sb.WriteString("PersistentKeepalive = 25\n")
	return sb.String()
}

// ─── Log buffer ───

type LogBuffer struct {
	mu      sync.Mutex
	entries []LogEntry
	max     int
	id      int64
}

type LogEntry struct {
	ID      int64  `json:"id"`
	Time    string `json:"time"`
	Message string `json:"message"`
}

func NewLogBuffer(size int) *LogBuffer {
	return &LogBuffer{entries: make([]LogEntry, 0, size), max: size}
}

func (lb *LogBuffer) Write(p []byte) (int, error) {
	lb.mu.Lock()
	defer lb.mu.Unlock()
	lb.id++
	entry := LogEntry{
		ID:      lb.id,
		Time:    time.Now().Format("15:04:05"),
		Message: strings.TrimSpace(string(p)),
	}
	if len(lb.entries) >= lb.max {
		// Copy to prevent underlying array growth (slice leak)
		newEntries := make([]LogEntry, lb.max-1, lb.max)
		copy(newEntries, lb.entries[1:])
		lb.entries = newEntries
	}
	lb.entries = append(lb.entries, entry)
	return len(p), nil
}

func (lb *LogBuffer) Entries(afterID int64) []LogEntry {
	lb.mu.Lock()
	defer lb.mu.Unlock()
	if afterID <= 0 {
		out := make([]LogEntry, len(lb.entries))
		copy(out, lb.entries)
		return out
	}
	for i, e := range lb.entries {
		if e.ID > afterID {
			out := make([]LogEntry, len(lb.entries)-i)
			copy(out, lb.entries[i:])
			return out
		}
	}
	return nil
}

// ─── Globals ───

var (
	cfg    *Config
	logBuf = NewLogBuffer(500)
	logger *log.Logger
)

func init() {
	w := io.MultiWriter(os.Stderr, logBuf)
	logger = log.New(w, "", log.LstdFlags)
}

// ─── DTLS Certificate ───

var dtlsFingerprint string

func loadOrGenerateDTLSCert(certPath, keyPath string) (tls.Certificate, error) {
	// Try to load existing cert
	if _, err := os.Stat(certPath); err == nil {
		cert, err := tls.LoadX509KeyPair(certPath, keyPath)
		if err == nil {
			if len(cert.Certificate) > 0 {
				hash := sha256.Sum256(cert.Certificate[0])
				dtlsFingerprint = hex.EncodeToString(hash[:])
				logger.Printf("Loaded DTLS certificate, fingerprint: %s", dtlsFingerprint)
			}
			return cert, nil
		}
		logger.Printf("Warning: failed to load existing cert, regenerating: %s", err)
	}

	// Generate new self-signed cert
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("generate key: %w", err)
	}

	sn, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	tmpl := &x509.Certificate{
		SerialNumber: sn,
		Subject:      pkix.Name{},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(10 * 365 * 24 * time.Hour), // 10 years
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("create cert: %w", err)
	}

	// Save cert
	os.MkdirAll(filepath.Dir(certPath), 0700)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	if err := os.WriteFile(certPath, certPEM, 0600); err != nil {
		return tls.Certificate{}, fmt.Errorf("write cert: %w", err)
	}

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("marshal key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
		return tls.Certificate{}, fmt.Errorf("write key: %w", err)
	}

	hash := sha256.Sum256(certDER)
	dtlsFingerprint = hex.EncodeToString(hash[:])
	logger.Printf("Generated new DTLS certificate, fingerprint: %s", dtlsFingerprint)

	return tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  key,
	}, nil
}

func loadOrGenerateWebCert(certPath, keyPath string) (tls.Certificate, error) {
	// Try to load existing cert
	if _, err := os.Stat(certPath); err == nil {
		cert, err := tls.LoadX509KeyPair(certPath, keyPath)
		if err == nil {
			logger.Printf("Loaded web TLS certificate from %s", certPath)
			return cert, nil
		}
		logger.Printf("Warning: failed to load existing web cert, regenerating: %s", err)
	}

	// Generate new self-signed cert for web
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("generate key: %w", err)
	}

	sn2, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	tmpl := &x509.Certificate{
		SerialNumber: sn2,
		Subject:      pkix.Name{},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("create cert: %w", err)
	}

	os.MkdirAll(filepath.Dir(certPath), 0700)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	if err := os.WriteFile(certPath, certPEM, 0600); err != nil {
		return tls.Certificate{}, fmt.Errorf("write cert: %w", err)
	}

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("marshal key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
		return tls.Certificate{}, fmt.Errorf("write key: %w", err)
	}

	logger.Printf("Generated new web TLS certificate at %s", certPath)
	return tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  key,
	}, nil
}

// ─── DTLS Server ───

func runDTLSServer(ctx context.Context, listenAddr string, connectAddr string) {
	certificate, err := loadOrGenerateDTLSCert("/etc/vkvpn/dtls-cert.pem", "/etc/vkvpn/dtls-key.pem")
	if err != nil {
		logger.Printf("Warning: failed to load/generate persistent cert, using ephemeral: %s", err)
		certificate, err = selfsign.GenerateSelfSigned()
		if err != nil {
			logger.Fatalf("Failed to generate certificate: %s", err)
		}
	}

	config := &dtls.Config{
		Certificates:          []tls.Certificate{certificate},
		ExtendedMasterSecret:  dtls.RequireExtendedMasterSecret,
		CipherSuites:          []dtls.CipherSuiteID{dtls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
		ConnectionIDGenerator: dtls.OnlySendCIDGenerator(),
	}

	addr, err := net.ResolveUDPAddr("udp", listenAddr)
	if err != nil {
		logger.Fatalf("Failed to resolve address: %s", err)
	}

	listener, err := dtls.Listen("udp", addr, config)
	if err != nil {
		logger.Fatalf("Failed to listen DTLS: %s", err)
	}
	context.AfterFunc(ctx, func() {
		listener.Close()
	})

	logger.Printf("DTLS server listening on %s", listenAddr)

	// Limit concurrent DTLS handshakes to prevent DoS
	handshakeSem := make(chan struct{}, 50)

	var wg sync.WaitGroup
	for {
		select {
		case <-ctx.Done():
			wg.Wait()
			return
		default:
		}

		conn, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				break
			}
			logger.Printf("Accept error: %s", err)
			continue
		}

		// Rate limit handshakes
		select {
		case handshakeSem <- struct{}{}:
		default:
			conn.Close()
			logger.Printf("DTLS handshake rate limited, dropping connection")
			continue
		}

		wg.Add(1)
		go func(conn net.Conn) {
			defer func() { <-handshakeSem }()
			defer wg.Done()
			defer conn.Close()
			activeDTLSConns.Add(1)
			defer activeDTLSConns.Add(-1)
			logger.Printf("DTLS connection from %s", conn.RemoteAddr())

			ctx1, cancel1 := context.WithTimeout(ctx, 30*time.Second)
			dtlsConn, ok := conn.(*dtls.Conn)
			if !ok {
				logger.Println("Type error")
				cancel1()
				return
			}
			if err := dtlsConn.HandshakeContext(ctx1); err != nil {
				logger.Printf("Handshake error: %s", err)
				cancel1()
				return
			}
			cancel1()
			logger.Println("DTLS handshake done")

			serverConn, err := net.Dial("udp", connectAddr)
			if err != nil {
				logger.Printf("Connect error: %s", err)
				return
			}
			defer serverConn.Close()

			var bridgeWg sync.WaitGroup
			bridgeWg.Add(2)
			ctx2, cancel2 := context.WithCancel(ctx)
			context.AfterFunc(ctx2, func() {
				conn.SetDeadline(time.Now())
				serverConn.SetDeadline(time.Now())
			})

			go func() {
				defer bridgeWg.Done()
				defer cancel2()
				buf := make([]byte, 1600)
				for {
					select {
					case <-ctx2.Done():
						return
					default:
					}
					conn.SetReadDeadline(time.Now().Add(5 * time.Minute))
					n, err := conn.Read(buf)
					if err != nil {
						logger.Printf("Read error: %s", err)
						return
					}
					serverConn.SetWriteDeadline(time.Now().Add(5 * time.Minute))
					if _, err = serverConn.Write(buf[:n]); err != nil {
						logger.Printf("Write error: %s", err)
						return
					}
				}
			}()

			go func() {
				defer bridgeWg.Done()
				defer cancel2()
				buf := make([]byte, 1600)
				for {
					select {
					case <-ctx2.Done():
						return
					default:
					}
					serverConn.SetReadDeadline(time.Now().Add(30 * time.Minute))
					n, err := serverConn.Read(buf)
					if err != nil {
						logger.Printf("Read error: %s", err)
						return
					}
					conn.SetWriteDeadline(time.Now().Add(30 * time.Minute))
					if _, err = conn.Write(buf[:n]); err != nil {
						logger.Printf("Write error: %s", err)
						return
					}
				}
			}()

			bridgeWg.Wait()
			logger.Printf("DTLS connection closed: %s", conn.RemoteAddr())
		}(conn)
	}
}

// ─── Web API handlers ───

func generateAdminPass() string {
	b := make([]byte, 16)
	rand.Read(b)
	return base64.URLEncoding.EncodeToString(b)[:16]
}

func (c *Config) checkPassword(password string) bool {
	c.mu.RLock()
	hash := c.AdminPassHash
	plain := c.AdminPass
	c.mu.RUnlock()

	if hash != "" {
		return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil
	}
	// Legacy plaintext fallback
	return plain != "" && plain == password
}

var clientNameRe = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,64}$`)

// ─── Session store ───

type sessionStore struct {
	mu       sync.Mutex
	sessions map[string]time.Time // token -> expiry
}

var sessions = &sessionStore{sessions: make(map[string]time.Time)}

func (s *sessionStore) Create() string {
	b := make([]byte, 32)
	rand.Read(b)
	token := base64.URLEncoding.EncodeToString(b)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[token] = time.Now().Add(30 * 24 * time.Hour)
	// Cleanup expired sessions (simple inline GC)
	for k, exp := range s.sessions {
		if time.Now().After(exp) {
			delete(s.sessions, k)
		}
	}
	return token
}

func (s *sessionStore) Valid(token string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	exp, ok := s.sessions[token]
	if !ok {
		return false
	}
	if time.Now().After(exp) {
		delete(s.sessions, token)
		return false
	}
	return true
}

// ─── Rate limiting ───

type rateLimiter struct {
	mu       sync.Mutex
	failures map[string]*failEntry
}

type failEntry struct {
	count    int
	resetAt  time.Time
}

var authLimiter = newRateLimiter()

func newRateLimiter() *rateLimiter {
	rl := &rateLimiter{failures: make(map[string]*failEntry)}
	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		for range ticker.C {
			rl.mu.Lock()
			now := time.Now()
			for k, e := range rl.failures {
				if now.After(e.resetAt) {
					delete(rl.failures, k)
				}
			}
			rl.mu.Unlock()
		}
	}()
	return rl
}

const (
	rateLimitWindow  = time.Minute
	rateLimitMaxFail = 10
)

func (rl *rateLimiter) isLimited(ip string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	e, ok := rl.failures[ip]
	if !ok {
		return false
	}
	if time.Now().After(e.resetAt) {
		delete(rl.failures, ip)
		return false
	}
	return e.count >= rateLimitMaxFail
}

func (rl *rateLimiter) recordFailure(ip string) {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	e, ok := rl.failures[ip]
	if !ok || time.Now().After(e.resetAt) {
		rl.failures[ip] = &failEntry{count: 1, resetAt: time.Now().Add(rateLimitWindow)}
		return
	}
	e.count++
}

func (rl *rateLimiter) reset(ip string) {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	delete(rl.failures, ip)
}

func clientIP(r *http.Request) string {
	// Do not trust X-Forwarded-For without a reverse proxy — spoofable
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	return host
}

func setSessionCookie(w http.ResponseWriter, r *http.Request) {
	sessToken := sessions.Create()
	http.SetCookie(w, &http.Cookie{
		Name:     "session",
		Value:    sessToken,
		Path:     "/",
		MaxAge:   86400 * 30,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		Secure:   r.TLS != nil,
	})
}

func authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cfg.mu.RLock()
		hasPass := cfg.AdminPassHash != "" || cfg.AdminPass != ""
		cfg.mu.RUnlock()

		if !hasPass {
			next(w, r)
			return
		}

		ip := clientIP(r)
		if authLimiter.isLimited(ip) {
			http.Error(w, "too many requests", http.StatusTooManyRequests)
			return
		}

		// Check session cookie (preferred — no password in cookie)
		if cookie, err := r.Cookie("session"); err == nil && sessions.Valid(cookie.Value) {
			authLimiter.reset(ip)
			next(w, r)
			return
		}
		// Check header (for API clients)
		if h := r.Header.Get("X-Admin-Token"); h != "" && cfg.checkPassword(h) {
			authLimiter.reset(ip)
			next(w, r)
			return
		}
		// Check query param (for initial login — creates session)
		if tok := r.URL.Query().Get("token"); tok != "" && cfg.checkPassword(tok) {
			authLimiter.reset(ip)
			setSessionCookie(w, r)
			next(w, r)
			return
		}

		authLimiter.recordFailure(ip)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	}
}

func apiGetStatus(w http.ResponseWriter, r *http.Request) {
	cfg.mu.RLock()
	resp := map[string]interface{}{
		"server_ip":   cfg.ServerIP,
		"wg_port":     cfg.WGPort,
		"dtls_port":   cfg.DTLSPort,
		"active_link": cfg.ActiveLink,
		"link_type":   cfg.LinkType,
		"clients":     len(cfg.Clients),
		"dns":         cfg.DNS,
		"subnet":      cfg.WGSubnet,
	}
	cfg.mu.RUnlock()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func detectLinkType(link string) string {
	if strings.Contains(link, "vk.com") || strings.Contains(link, "vk.ru") {
		return "vk"
	}
	if strings.Contains(link, "telemost") || strings.Contains(link, "yandex") {
		return "yandex"
	}
	return ""
}

func apiSetLink(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	var req struct {
		Link string `json:"link"`
		Type string `json:"type"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if req.Type == "" {
		req.Type = detectLinkType(req.Link)
		if req.Type == "" {
			http.Error(w, "cannot detect link type, specify 'type' field", http.StatusBadRequest)
			return
		}
	}

	entry := LinkEntry{
		URL:     req.Link,
		Type:    req.Type,
		AddedAt: time.Now().Format(time.RFC3339),
		Active:  true,
	}

	cfg.mu.Lock()
	cfg.ActiveLink = req.Link
	cfg.LinkType = req.Type
	// Deactivate old links of same type, add new
	for i := range cfg.Links {
		if cfg.Links[i].Type == req.Type {
			cfg.Links[i].Active = false
		}
	}
	cfg.Links = append(cfg.Links, entry)
	cfg.mu.Unlock()
	cfg.Save()

	logger.Printf("Link updated: type=%s link=%s", req.Type, req.Link)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

func apiDeleteLink(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	var req struct {
		URL string `json:"url"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	cfg.mu.Lock()
	found := false
	newLinks := make([]LinkEntry, 0, len(cfg.Links))
	for _, l := range cfg.Links {
		if l.URL == req.URL {
			found = true
			continue
		}
		newLinks = append(newLinks, l)
	}
	cfg.Links = newLinks
	// If deleted link was the active one, clear it or set next active
	if cfg.ActiveLink == req.URL {
		cfg.ActiveLink = ""
		cfg.LinkType = ""
		for i := len(cfg.Links) - 1; i >= 0; i-- {
			if cfg.Links[i].Active {
				cfg.ActiveLink = cfg.Links[i].URL
				cfg.LinkType = cfg.Links[i].Type
				break
			}
		}
	}
	cfg.mu.Unlock()

	if !found {
		http.Error(w, "link not found", http.StatusNotFound)
		return
	}
	cfg.Save()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

func apiActiveLink(w http.ResponseWriter, r *http.Request) {
	cfg.mu.RLock()
	resp := map[string]interface{}{
		"active_link": cfg.ActiveLink,
		"link_type":   cfg.LinkType,
		"links":       cfg.Links,
	}
	cfg.mu.RUnlock()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func apiListClients(w http.ResponseWriter, r *http.Request) {
	cfg.mu.RLock()
	clients := make([]map[string]interface{}, len(cfg.Clients))
	for i, cl := range cfg.Clients {
		clients[i] = map[string]interface{}{
			"name":       cl.Name,
			"ip":         cl.IP,
			"public_key": cl.PublicKey,
			"created_at": cl.CreatedAt,
			"enabled":    cl.Enabled,
		}
	}
	cfg.mu.RUnlock()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(clients)
}

func apiAddClient(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	var req struct {
		Name      string `json:"name"`
		PublicKey string `json:"public_key"` // client-provided WG public key (preferred)
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if req.Name == "" {
		http.Error(w, "name required", http.StatusBadRequest)
		return
	}
	if !clientNameRe.MatchString(req.Name) {
		http.Error(w, "invalid name: must match [a-zA-Z0-9_-]{1,64}", http.StatusBadRequest)
		return
	}
	// Check for duplicate name
	cfg.mu.RLock()
	for _, cl := range cfg.Clients {
		if cl.Name == req.Name {
			cfg.mu.RUnlock()
			http.Error(w, "client already exists", http.StatusConflict)
			return
		}
	}
	cfg.mu.RUnlock()

	var priv, pub string
	if req.PublicKey != "" {
		// Client provided their own public key — server never sees private key
		pub = req.PublicKey
		// Validate base64 format (32 bytes)
		if decoded, err := base64.StdEncoding.DecodeString(pub); err != nil || len(decoded) != 32 {
			http.Error(w, "invalid public_key: must be 32-byte base64", http.StatusBadRequest)
			return
		}
	} else {
		// Legacy: generate keys on server (for backward compatibility)
		var err error
		priv, pub, err = wgGenKey()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}

	cfg.mu.Lock()
	ip := cfg.nextIP()
	if ip == "" {
		cfg.mu.Unlock()
		http.Error(w, "no free IPs", http.StatusConflict)
		return
	}
	cl := Client{
		Name:       req.Name,
		PrivateKey: priv, // empty when client provides public_key
		PublicKey:  pub,
		IP:         ip,
		CreatedAt:  time.Now().Format("2006-01-02 15:04"),
		Enabled:    true,
	}
	cfg.Clients = append(cfg.Clients, cl)
	cfg.mu.Unlock()

	if err := cfg.Save(); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	cfg.applyWireGuard()
	logger.Printf("Client added: %s (%s)", cl.Name, cl.IP)

	resp := map[string]string{"status": "ok", "ip": ip}
	if priv != "" {
		resp["warning"] = "server-generated keys (deprecated): pass public_key in request for better security"
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func apiDeleteClient(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	var req struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	cfg.mu.Lock()
	found := false
	for i, cl := range cfg.Clients {
		if cl.Name == req.Name {
			cfg.Clients = append(cfg.Clients[:i], cfg.Clients[i+1:]...)
			found = true
			break
		}
	}
	cfg.mu.Unlock()

	if !found {
		http.Error(w, "client not found", http.StatusNotFound)
		return
	}

	cfg.Save()
	cfg.applyWireGuard()
	logger.Printf("Client deleted: %s", req.Name)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

func apiToggleClient(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	var req struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	cfg.mu.Lock()
	for i, cl := range cfg.Clients {
		if cl.Name == req.Name {
			cfg.Clients[i].Enabled = !cfg.Clients[i].Enabled
			break
		}
	}
	cfg.mu.Unlock()

	cfg.Save()
	cfg.applyWireGuard()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

func apiClientConfig(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	if name == "" {
		http.Error(w, "name required", http.StatusBadRequest)
		return
	}

	cfg.mu.RLock()
	var found *Client
	for _, cl := range cfg.Clients {
		if cl.Name == name {
			c := cl
			found = &c
			break
		}
	}
	if found == nil {
		cfg.mu.RUnlock()
		http.Error(w, "client not found", http.StatusNotFound)
		return
	}
	conf := cfg.clientConfig(*found)
	cfg.mu.RUnlock()

	format := r.URL.Query().Get("format")
	if format == "file" {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s.conf", name))
		w.Write([]byte(conf))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"config": conf})
}

// apiAppConfig returns a full app config JSON for Android/desktop clients.
// Contains everything needed: server, WG keys, active link.
func apiAppConfig(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	if name == "" {
		http.Error(w, "name required", http.StatusBadRequest)
		return
	}

	cfg.mu.RLock()
	var found *Client
	for _, cl := range cfg.Clients {
		if cl.Name == name {
			c := cl
			found = &c
			break
		}
	}
	if found == nil {
		cfg.mu.RUnlock()
		http.Error(w, "client not found", http.StatusNotFound)
		return
	}

	appCfg := map[string]interface{}{
		"server":           cfg.ServerIP,
		"link":             cfg.ActiveLink,
		"provider":         cfg.LinkType,
		"wg_pubkey":        cfg.ServerPub,
		"wg_address":       found.IP,
		"wg_dns":           cfg.DNS,
		"wg_port":          cfg.WGPort,
		"dtls_port":        cfg.DTLSPort,
		"name":             found.Name,
		"dtls_fingerprint": dtlsFingerprint,
	}
	// Only include private key for legacy server-generated clients
	if found.PrivateKey != "" {
		appCfg["wg_privkey"] = found.PrivateKey
	}
	cfg.mu.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(appCfg)
}

func apiLogs(w http.ResponseWriter, r *http.Request) {
	var afterID int64
	if v := r.URL.Query().Get("after"); v != "" {
		fmt.Sscanf(v, "%d", &afterID)
	}
	entries := logBuf.Entries(afterID)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(entries)
}

// ─── Health check ───

var (
	version         = "dev"
	startTime       = time.Now()
	activeDTLSConns atomic.Int64
)

func apiLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	ip := clientIP(r)
	if authLimiter.isLimited(ip) {
		http.Error(w, "too many requests", http.StatusTooManyRequests)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<16)
	var req struct {
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if req.Password == "" || !cfg.checkPassword(req.Password) {
		authLimiter.recordFailure(ip)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	authLimiter.reset(ip)
	setSessionCookie(w, r)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

func apiHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

// ─── WireGuard metrics ───

type clientMetrics struct {
	Name          string `json:"name"`
	IP            string `json:"ip"`
	Online        bool   `json:"online"`
	LastHandshake int64  `json:"last_handshake"` // unix timestamp, 0 if never
	RxBytes       int64  `json:"rx_bytes"`
	TxBytes       int64  `json:"tx_bytes"`
	Enabled       bool   `json:"enabled"`
}

func parseWGHandshakes() map[string]int64 {
	out, err := exec.Command("wg", "show", "wg0", "latest-handshakes").Output()
	if err != nil {
		return nil
	}
	m := make(map[string]int64)
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		parts := strings.Fields(line)
		if len(parts) == 2 {
			ts, _ := strconv.ParseInt(parts[1], 10, 64)
			m[parts[0]] = ts
		}
	}
	return m
}

func parseWGTransfer() map[string][2]int64 {
	out, err := exec.Command("wg", "show", "wg0", "transfer").Output()
	if err != nil {
		return nil
	}
	m := make(map[string][2]int64)
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		parts := strings.Fields(line)
		if len(parts) == 3 {
			rx, _ := strconv.ParseInt(parts[1], 10, 64)
			tx, _ := strconv.ParseInt(parts[2], 10, 64)
			m[parts[0]] = [2]int64{rx, tx}
		}
	}
	return m
}

func apiMetrics(w http.ResponseWriter, r *http.Request) {
	handshakes := parseWGHandshakes()
	transfers := parseWGTransfer()
	now := time.Now().Unix()

	cfg.mu.RLock()
	clients := make([]clientMetrics, 0, len(cfg.Clients))
	for _, c := range cfg.Clients {
		cm := clientMetrics{
			Name:    c.Name,
			IP:      c.IP,
			Enabled: c.Enabled,
		}
		if ts, ok := handshakes[c.PublicKey]; ok {
			cm.LastHandshake = ts
			cm.Online = ts > 0 && (now-ts) < 180 // 3 minutes
		}
		if tr, ok := transfers[c.PublicKey]; ok {
			cm.RxBytes = tr[0]
			cm.TxBytes = tr[1]
		}
		clients = append(clients, cm)
	}
	cfg.mu.RUnlock()

	resp := map[string]interface{}{
		"clients":          clients,
		"dtls_connections": activeDTLSConns.Load(),
		"uptime_seconds":   int(time.Since(startTime).Seconds()),
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// ─── Init config ───

func initConfig(configPath, serverIP string, wgPort, dtlsPort int) {
	var err error
	cfg, err = loadConfig(configPath)
	if err != nil {
		logger.Fatalf("Failed to load config: %s", err)
	}

	needSave := false
	if cfg.ServerIP == "" && serverIP != "" {
		cfg.ServerIP = serverIP
		needSave = true
	}
	if cfg.WGPort == 0 {
		cfg.WGPort = wgPort
		needSave = true
	}
	if cfg.DTLSPort == 0 {
		cfg.DTLSPort = dtlsPort
		needSave = true
	}
	if cfg.WGSubnet == "" {
		cfg.WGSubnet = "10.66.66.0/24"
		needSave = true
	}
	if cfg.DNS == "" {
		cfg.DNS = "1.1.1.1, 8.8.8.8"
		needSave = true
	}
	if cfg.ServerPriv == "" {
		priv, pub, err := wgGenKey()
		if err != nil {
			logger.Printf("Warning: wg not installed, keys not generated: %s", err)
		} else {
			cfg.ServerPriv = priv
			cfg.ServerPub = pub
			needSave = true
		}
	}
	// Migrate plaintext password to bcrypt hash
	if cfg.AdminPass != "" && cfg.AdminPassHash == "" {
		hash, err := bcrypt.GenerateFromPassword([]byte(cfg.AdminPass), bcrypt.DefaultCost)
		if err != nil {
			logger.Printf("Warning: failed to hash password: %s", err)
		} else {
			cfg.AdminPassHash = string(hash)
			logger.Printf("Admin password migrated to bcrypt")
			cfg.AdminPass = "" // clear plaintext
			needSave = true
		}
	}
	if cfg.AdminPass == "" && cfg.AdminPassHash == "" {
		pass := generateAdminPass()
		hash, err := bcrypt.GenerateFromPassword([]byte(pass), bcrypt.DefaultCost)
		if err != nil {
			logger.Fatalf("Failed to hash password: %s", err)
		}
		cfg.AdminPassHash = string(hash)
		needSave = true
		// Print to stderr only (not to log buffer / journalctl visible API)
		fmt.Fprintf(os.Stderr, "\n  *** Admin password: %s ***\n  (save this, it won't be shown again)\n\n", pass)
	}
	if needSave {
		cfg.Save()
	}
}

// ─── Main ───

func main() {
	configPath := flag.String("config", "/etc/vkvpn/config.json", "config file path")
	serverIP := flag.String("ip", "", "server public IP")
	webAddr := flag.String("web", "0.0.0.0:8080", "web admin address")
	tlsCert := flag.String("tls-cert", "", "TLS certificate for HTTPS admin panel")
	tlsKey := flag.String("tls-key", "", "TLS key for HTTPS admin panel")
	autoTLS := flag.Bool("auto-tls", true, "auto-generate self-signed TLS cert for HTTPS (default: enabled)")
	dtlsAddr := flag.String("dtls", "0.0.0.0:56000", "DTLS listen address")
	wgConnect := flag.String("wg-connect", "127.0.0.1:51820", "WireGuard address to forward to")
	wgPort := flag.Int("wg-port", 51820, "WireGuard listen port")
	dtlsPort := flag.Int("dtls-port", 56000, "DTLS listen port (for config)")
	flag.Parse()

	// Ensure config dir exists
	os.MkdirAll(filepath.Dir(*configPath), 0700)

	initConfig(*configPath, *serverIP, *wgPort, *dtlsPort)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		<-signalChan
		logger.Printf("Shutting down gracefully...")
		if cfg != nil {
			if err := cfg.Save(); err != nil {
				logger.Printf("Warning: failed to save config on shutdown: %s", err)
			} else {
				logger.Printf("Config saved")
			}
		}
		cancel()
		<-signalChan
		logger.Fatalf("Forced exit...")
	}()

	// Start DTLS server
	go runDTLSServer(ctx, *dtlsAddr, *wgConnect)

	// Apply WireGuard config
	if cfg.ServerPriv != "" {
		if err := cfg.applyWireGuard(); err != nil {
			logger.Printf("Warning: failed to apply WireGuard: %s", err)
		}
	}

	// Web server
	mux := http.NewServeMux()
	mux.HandleFunc("/api/health", apiHealth) // no auth needed
	mux.HandleFunc("/api/login", apiLogin)   // POST login — returns session cookie
	mux.HandleFunc("/api/status", authMiddleware(apiGetStatus))
	mux.HandleFunc("/api/link", authMiddleware(apiSetLink))
	mux.HandleFunc("/api/link/delete", authMiddleware(apiDeleteLink))
	mux.HandleFunc("/api/link/active", authMiddleware(apiActiveLink))
	mux.HandleFunc("/api/clients", authMiddleware(apiListClients))
	mux.HandleFunc("/api/clients/add", authMiddleware(apiAddClient))
	mux.HandleFunc("/api/clients/delete", authMiddleware(apiDeleteClient))
	mux.HandleFunc("/api/clients/toggle", authMiddleware(apiToggleClient))
	mux.HandleFunc("/api/clients/config", authMiddleware(apiClientConfig))
	mux.HandleFunc("/api/clients/appconfig", authMiddleware(apiAppConfig))
	mux.HandleFunc("/api/logs", authMiddleware(apiLogs))
	mux.HandleFunc("/api/metrics", authMiddleware(apiMetrics))

	webContent, _ := fs.Sub(webFS, "web")
	fileServer := http.FileServer(http.FS(webContent))
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if tok := r.URL.Query().Get("token"); tok != "" && cfg.checkPassword(tok) {
			setSessionCookie(w, r)
		}
		fileServer.ServeHTTP(w, r)
	})

	server := &http.Server{Addr: *webAddr, Handler: mux}
	go func() {
		<-ctx.Done()
		server.Shutdown(context.Background())
	}()

	// Determine TLS mode
	useTLS := false
	if *tlsCert != "" && *tlsKey != "" {
		useTLS = true
	} else if *autoTLS {
		certDir := filepath.Dir(*configPath)
		webCertPath := filepath.Join(certDir, "web-cert.pem")
		webKeyPath := filepath.Join(certDir, "web-key.pem")
		_, err := loadOrGenerateWebCert(webCertPath, webKeyPath)
		if err != nil {
			logger.Fatalf("Failed to generate web TLS cert: %s", err)
		}
		*tlsCert = webCertPath
		*tlsKey = webKeyPath
		useTLS = true
	}

	proto := "http"
	if useTLS {
		proto = "https"
	}
	logger.Printf("Admin panel: %s://%s/ (use token to authenticate)", proto, *webAddr)
	logger.Printf("DTLS server: %s", *dtlsAddr)

	if useTLS {
		if err := server.ListenAndServeTLS(*tlsCert, *tlsKey); err != http.ErrServerClosed {
			logger.Fatalf("Web server error: %s", err)
		}
	} else {
		if err := server.ListenAndServe(); err != http.ErrServerClosed {
			logger.Fatalf("Web server error: %s", err)
		}
	}
}
