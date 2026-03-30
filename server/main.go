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
	mrand "math/rand"

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
	"net/url"
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

	"github.com/Romakarov/vkvpn/pkg/sessionmux"
	"github.com/Romakarov/vkvpn/pkg/turnauth"
	"github.com/Romakarov/vkvpn/pkg/telemost"
	"github.com/Romakarov/vkvpn/pkg/vp8tunnel"
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
	VKAccounts  []VKAccount `json:"vk_accounts,omitempty"`
	DTLSPort      int        `json:"dtls_port"`
	AdminPass     string     `json:"admin_pass,omitempty"`     // legacy plaintext, migrated on startup
	AdminPassHash string     `json:"admin_pass_hash,omitempty"` // bcrypt hash
	Pool          PoolConfig `json:"pool_config,omitempty"`
	// VP8 transport — second protocol that tunnels data through Telemost video stream.
	VP8Enabled   bool   `json:"vp8_enabled,omitempty"`
	TelemostLink string `json:"telemost_link,omitempty"`
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

// VKAccount holds a VK OAuth account used for server-side TURN credential extraction
type VKAccount struct {
	ID           string `json:"id"`            // VK user ID
	Name         string `json:"name"`          // display name
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresAt    int64  `json:"expires_at"`    // unix timestamp
	AddedAt      string `json:"added_at"`
	Enabled      bool   `json:"enabled"`
	LastError    string `json:"last_error,omitempty"`
	// Pool management fields
	Status       string `json:"status,omitempty"`         // "idle", "calling", "cooldown", "rate_limited", "banned", "token_expired"
	CallsToday   int    `json:"calls_today,omitempty"`
	LastCallAt   int64  `json:"last_call_at,omitempty"`
	NextCallAt   int64  `json:"next_call_at,omitempty"`
	FailCount    int    `json:"fail_count,omitempty"`
	LastResetDay string `json:"last_reset_day,omitempty"`
}

// PoolConfig holds settings for VK account pool rotation and natural behavior simulation
type PoolConfig struct {
	MaxCallsPerDay  int `json:"max_calls_per_day"`   // max calls per account per day (default 5)
	MinCallMinutes  int `json:"min_call_min"`         // min call duration in minutes (default 60)
	MaxCallMinutes  int `json:"max_call_min"`         // max call duration in minutes (default 180)
	MinBreakMinutes int `json:"min_break_min"`        // min break between calls (default 30)
	MaxBreakMinutes int `json:"max_break_min"`        // max break between calls (default 120)
	RotationMinutes int `json:"rotation_min"`          // how often to rotate client assignments (default 120)
}

func defaultPoolConfig() PoolConfig {
	return PoolConfig{
		MaxCallsPerDay:  5,
		MinCallMinutes:  60,
		MaxCallMinutes:  180,
		MinBreakMinutes: 30,
		MaxBreakMinutes: 120,
		RotationMinutes: 120,
	}
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

	// Hot-reload WireGuard peers without restarting the interface
	syncCmd := exec.Command("bash", "-c", "wg syncconf wg0 <(wg-quick strip wg0)")
	if out, err := syncCmd.CombinedOutput(); err != nil {
		logger.Printf("wg syncconf failed: %s (%s), falling back to restart", err, string(out))
		// Fallback: full restart
		if err2 := exec.Command("systemctl", "restart", "wg-quick@wg0").Run(); err2 != nil {
			exec.Command("wg-quick", "down", "wg0").Run()
			exec.Command("wg-quick", "up", "wg0").Run()
		}
	}
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
		ConnectionIDGenerator: dtls.RandomCIDGenerator(8), // 8-byte CID for NAT rebinding resilience
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

	// Session multiplexer: groups DTLS connections by client session ID.
	// Each session gets ONE UDP socket to WireGuard (prevents endpoint thrashing).
	mux := sessionmux.NewMux(connectAddr, logger)
	defer mux.Stop()

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

			// Read first packet to determine client type.
			// New clients send magic byte 0x00 + 16-byte Session UUID.
			// Legacy clients send WireGuard packets (first byte 1-4).
			sid, isSession, firstPkt, err := sessionmux.ReadSessionHandshake(conn)
			if err != nil {
				logger.Printf("First packet read error: %s", err)
				return
			}

			if !isSession {
				// Legacy client — create dedicated WG socket (backward compatible)
				logger.Printf("Legacy client from %s (no session ID)", conn.RemoteAddr())
				legacyBridgeWithFirstPacket(ctx, conn, connectAddr, firstPkt)
				return
			}

			sess, err := mux.GetOrCreateSession(sid)
			if err != nil {
				logger.Printf("Session create error: %s", err)
				return
			}
			sess.AddConn(conn)
			defer sess.RemoveConn(conn)

			// Start WG→DTLS bridge exactly once per session (sync.Once inside)
			sess.StartWGBridge()

			logger.Printf("DTLS conn joined session %s (conns: %d)", sid, sess.ConnCount())

			// DTLS→WG bridge for this connection
			sessionmux.BridgeDTLSToWG(sess, conn)

			logger.Printf("DTLS connection closed: %s (session %s, remaining: %d)",
				conn.RemoteAddr(), sid, sess.ConnCount())
		}(conn)
	}
}

// legacyBridgeWithFirstPacket handles legacy clients that don't send a Session ID.
// firstPkt is the WireGuard packet already read from the connection.
func legacyBridgeWithFirstPacket(ctx context.Context, conn net.Conn, connectAddr string, firstPkt []byte) {
	serverConn, err := net.Dial("udp", connectAddr)
	if err != nil {
		logger.Printf("Connect error: %s", err)
		return
	}
	defer serverConn.Close()

	// Forward the first WG packet that was already read
	if len(firstPkt) > 0 {
		if _, err = serverConn.Write(firstPkt); err != nil {
			logger.Printf("Write first packet error: %s", err)
			return
		}
	}

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
				return
			}
			serverConn.SetWriteDeadline(time.Now().Add(5 * time.Minute))
			if _, err = serverConn.Write(buf[:n]); err != nil {
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
				return
			}
			conn.SetWriteDeadline(time.Now().Add(30 * time.Minute))
			if _, err = conn.Write(buf[:n]); err != nil {
				return
			}
		}
	}()

	bridgeWg.Wait()
	logger.Printf("Legacy DTLS connection closed: %s", conn.RemoteAddr())
}

// ─── VP8/Telemost Server (secondary transport) ───

var vp8Status struct {
	sync.RWMutex
	Connected   bool
	ConnectedAt time.Time
	LastError   string
	BytesIn     int64
	BytesOut    int64
}

// runVP8Server connects to Telemost and bridges VP8 tunnel to WireGuard.
// Reads TelemostLink from config each iteration, automatically reconnects.
func runVP8Server(ctx context.Context, wgAddr string) {
	logger.Printf("VP8 transport starting (Telemost mode)")

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		cfg.mu.RLock()
		link := cfg.TelemostLink
		cfg.mu.RUnlock()

		if link == "" {
			logger.Printf("VP8: no Telemost link configured, waiting 30s...")
			vp8Status.Lock()
			vp8Status.Connected = false
			vp8Status.LastError = "no Telemost link configured"
			vp8Status.Unlock()
			select {
			case <-time.After(30 * time.Second):
			case <-ctx.Done():
				return
			}
			continue
		}

		client := telemost.NewClient(logger)
		client.OnTunnel = func(tunnel *vp8tunnel.Tunnel) {
			logger.Printf("VP8 tunnel established via Telemost — bridging to WireGuard %s", wgAddr)
			vp8Status.Lock()
			vp8Status.Connected = true
			vp8Status.ConnectedAt = time.Now()
			vp8Status.LastError = ""
			vp8Status.Unlock()
			bridgeVP8ToWG(tunnel, wgAddr)
			vp8Status.Lock()
			vp8Status.Connected = false
			vp8Status.Unlock()
		}

		err := client.JoinCall(ctx, link)
		client.Close()
		if ctx.Err() != nil {
			return
		}
		errMsg := ""
		if err != nil {
			errMsg = err.Error()
		}
		vp8Status.Lock()
		vp8Status.Connected = false
		vp8Status.LastError = errMsg
		vp8Status.Unlock()
		logger.Printf("VP8 Telemost session ended: %v — reconnecting in 5s...", err)
		select {
		case <-time.After(5 * time.Second):
		case <-ctx.Done():
			return
		}
	}
}

// bridgeVP8ToWG bridges a VP8 tunnel to WireGuard UDP.
func bridgeVP8ToWG(tunnel *vp8tunnel.Tunnel, wgAddr string) {
	pconn := vp8tunnel.NewPacketConn(tunnel)

	wgConn, err := net.Dial("udp", wgAddr)
	if err != nil {
		logger.Printf("VP8: WG dial error: %s", err)
		return
	}
	defer wgConn.Close()

	var wg sync.WaitGroup
	wg.Add(2)

	// VP8 → WG
	go func() {
		defer wg.Done()
		buf := make([]byte, 1600)
		for {
			n, _, err := pconn.ReadFrom(buf)
			if err != nil {
				return
			}
			if _, err = wgConn.Write(buf[:n]); err != nil {
				return
			}
		}
	}()

	// WG → VP8
	go func() {
		defer wg.Done()
		buf := make([]byte, 1600)
		for {
			wgConn.SetReadDeadline(time.Now().Add(30 * time.Minute))
			n, err := wgConn.Read(buf)
			if err != nil {
				return
			}
			if _, err = pconn.WriteTo(buf[:n], nil); err != nil {
				return
			}
		}
	}()

	wg.Wait()
	logger.Printf("VP8 bridge closed")
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
	rateLimitMaxFail = 100
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
		SameSite: http.SameSiteLaxMode,
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

		// Only count as failure if they actually tried to authenticate
		// (provided a token/password that was wrong, not just missing auth)
		tok := r.URL.Query().Get("token")
		hdr := r.Header.Get("X-Admin-Token")
		if tok != "" || hdr != "" {
			authLimiter.recordFailure(ip)
		}
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

func apiVP8Config(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		cfg.mu.RLock()
		resp := map[string]interface{}{
			"enabled":       cfg.VP8Enabled,
			"telemost_link": cfg.TelemostLink,
		}
		cfg.mu.RUnlock()
		vp8Status.RLock()
		resp["connected"] = vp8Status.Connected
		if !vp8Status.ConnectedAt.IsZero() {
			resp["connected_at"] = vp8Status.ConnectedAt.Format(time.RFC3339)
		}
		resp["last_error"] = vp8Status.LastError
		resp["bytes_in"] = atomic.LoadInt64(&vp8Status.BytesIn)
		resp["bytes_out"] = atomic.LoadInt64(&vp8Status.BytesOut)
		vp8Status.RUnlock()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)

	case http.MethodPost:
		var req struct {
			Enabled      *bool   `json:"enabled"`
			TelemostLink *string `json:"telemost_link"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		cfg.mu.Lock()
		if req.Enabled != nil {
			cfg.VP8Enabled = *req.Enabled
		}
		if req.TelemostLink != nil {
			cfg.TelemostLink = *req.TelemostLink
		}
		cfg.mu.Unlock()
		cfg.Save()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})

	default:
		http.Error(w, "GET or POST", http.StatusMethodNotAllowed)
	}
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

	// Include server-side TURN credentials from pool (per-client assignment)
	if user, pass, addr, ok := credPool.GetOrAssignCreds(found.Name); ok {
		appCfg["turn_username"] = user
		appCfg["turn_password"] = pass
		appCfg["turn_address"] = addr
		appCfg["creds_mode"] = "server"
	} else {
		// Fallback to legacy single cache
		turnCredsCache.RLock()
		if turnCredsCache.Username != "" && time.Now().Before(turnCredsCache.ExpiresAt) {
			appCfg["turn_username"] = turnCredsCache.Username
			appCfg["turn_password"] = turnCredsCache.Password
			appCfg["turn_address"] = turnCredsCache.Address
			appCfg["creds_mode"] = "server"
		}
		turnCredsCache.RUnlock()
	}

	// Include VP8 transport status
	cfg.mu.RLock()
	if cfg.VP8Enabled && cfg.TelemostLink != "" {
		appCfg["vp8_enabled"] = true
		appCfg["telemost_link"] = cfg.TelemostLink
	}
	cfg.mu.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(appCfg)
}

// ─── VK OAuth + Server-side TURN credentials ───

// oauthStateStore prevents CSRF on OAuth callback
var oauthStates sync.Map // state string → expiry time.Time

func generateOAuthState() string {
	b := make([]byte, 16)
	rand.Read(b)
	state := hex.EncodeToString(b)
	oauthStates.Store(state, time.Now().Add(10*time.Minute))
	return state
}

func validateOAuthState(state string) bool {
	v, ok := oauthStates.LoadAndDelete(state)
	if !ok {
		return false
	}
	return time.Now().Before(v.(time.Time))
}

// Cached TURN credentials extracted by the server (legacy — kept for backward compat)
var turnCredsCache struct {
	sync.RWMutex
	Username  string    `json:"username"`
	Password  string    `json:"password"`
	Address   string    `json:"address"`
	FetchedAt time.Time `json:"fetched_at"`
	ExpiresAt time.Time `json:"expires_at"`
	AccountID string    `json:"account_id"`
	Error     string    `json:"error,omitempty"`
}

// ─── Credential Pool ───

// ActiveCall represents a live VK call producing TURN credentials
type ActiveCall struct {
	AccountID  string
	AccountName string
	Username   string
	Password   string
	Address    string
	StartedAt  time.Time
	ExpiresAt  time.Time // planned call end time (1-3 hours)
	Clients    []string  // assigned VPN client names
}

// CredentialPool manages multiple VK accounts and their TURN credentials
type CredentialPool struct {
	mu          sync.RWMutex
	activeCalls map[string]*ActiveCall // account_id -> active call
	assignments map[string]string      // client_name -> account_id
	roundRobin  int
}

var credPool = &CredentialPool{
	activeCalls: make(map[string]*ActiveCall),
	assignments: make(map[string]string),
}

// GetOrAssignCreds assigns a client to an active call and returns its credentials.
// If the client is already assigned to an active call, returns those creds.
// Otherwise picks the call with fewest assigned clients (round-robin).
func (p *CredentialPool) GetOrAssignCreds(clientName string) (username, password, address string, ok bool) {
	p.mu.Lock()
	defer p.mu.Unlock()

	// Already assigned?
	if accID, exists := p.assignments[clientName]; exists {
		if call, active := p.activeCalls[accID]; active {
			return call.Username, call.Password, call.Address, true
		}
		// Assigned account no longer active — reassign
		delete(p.assignments, clientName)
	}

	// Find call with fewest clients
	if len(p.activeCalls) == 0 {
		return "", "", "", false
	}

	var bestCall *ActiveCall
	var bestID string
	bestCount := int(^uint(0) >> 1) // max int

	for id, call := range p.activeCalls {
		if len(call.Clients) < bestCount {
			bestCount = len(call.Clients)
			bestCall = call
			bestID = id
		}
	}

	if bestCall == nil {
		return "", "", "", false
	}

	// Assign
	p.assignments[clientName] = bestID
	bestCall.Clients = append(bestCall.Clients, clientName)
	return bestCall.Username, bestCall.Password, bestCall.Address, true
}

// ReleaseClient removes a client's assignment
func (p *CredentialPool) ReleaseClient(clientName string) {
	p.mu.Lock()
	defer p.mu.Unlock()

	accID, exists := p.assignments[clientName]
	if !exists {
		return
	}
	delete(p.assignments, clientName)

	if call, ok := p.activeCalls[accID]; ok {
		for i, c := range call.Clients {
			if c == clientName {
				call.Clients = append(call.Clients[:i], call.Clients[i+1:]...)
				break
			}
		}
	}
}

// AddCall registers an active call with TURN credentials
func (p *CredentialPool) AddCall(accountID, accountName, username, password, address string, expiresAt time.Time) {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.activeCalls[accountID] = &ActiveCall{
		AccountID:   accountID,
		AccountName: accountName,
		Username:    username,
		Password:    password,
		Address:     address,
		StartedAt:   time.Now(),
		ExpiresAt:   expiresAt,
	}
}

// EndCall removes an active call and unassigns all its clients
func (p *CredentialPool) EndCall(accountID string) []string {
	p.mu.Lock()
	defer p.mu.Unlock()

	call, ok := p.activeCalls[accountID]
	if !ok {
		return nil
	}

	orphanedClients := call.Clients
	delete(p.activeCalls, accountID)

	// Remove assignments for orphaned clients
	for _, c := range orphanedClients {
		delete(p.assignments, c)
	}
	return orphanedClients
}

// GetAnyCreds returns any available credentials (backward compat for single-account mode)
func (p *CredentialPool) GetAnyCreds() (username, password, address string, ok bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	for _, call := range p.activeCalls {
		return call.Username, call.Password, call.Address, true
	}
	return "", "", "", false
}

// Stats returns pool statistics
func (p *CredentialPool) Stats() (activeCalls, assignedClients, totalClients int) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	activeCalls = len(p.activeCalls)
	assignedClients = len(p.assignments)
	for _, call := range p.activeCalls {
		totalClients += len(call.Clients)
	}
	return
}

// ActiveCallsList returns a snapshot of all active calls (for admin UI)
func (p *CredentialPool) ActiveCallsList() []map[string]interface{} {
	p.mu.RLock()
	defer p.mu.RUnlock()

	var result []map[string]interface{}
	for _, call := range p.activeCalls {
		result = append(result, map[string]interface{}{
			"account_id":   call.AccountID,
			"account_name": call.AccountName,
			"turn_address": call.Address,
			"started_at":   call.StartedAt.Format("15:04:05"),
			"expires_at":   call.ExpiresAt.Format("15:04:05"),
			"clients":      call.Clients,
			"client_count": len(call.Clients),
		})
	}
	return result
}

const (
	vkClientID     = "6287487"
	vkClientSecret = "QbYic1K3lEV5kTGiqlq2"
)

// apiVKAuthURL generates a VK OAuth URL for the admin to authorize a VK account
func apiVKAuthURL(w http.ResponseWriter, r *http.Request) {
	state := generateOAuthState()
	// Build redirect URI from current request
	scheme := "https"
	if r.TLS == nil {
		scheme = "http"
	}
	host := r.Host
	redirectURI := fmt.Sprintf("%s://%s/api/vk/callback", scheme, host)

	authURL := fmt.Sprintf(
		"https://oauth.vk.com/authorize?client_id=%s&redirect_uri=%s&scope=audio,video,offline&response_type=code&state=%s&v=5.264",
		vkClientID,
		url.QueryEscape(redirectURI),
		state,
	)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"url":   authURL,
		"state": state,
	})
}

// apiVKCallback handles the OAuth callback from VK (no auth middleware — VK redirects here)
func apiVKCallback(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")
	if code == "" || state == "" {
		errMsg := r.URL.Query().Get("error_description")
		if errMsg == "" {
			errMsg = "missing code or state"
		}
		http.Error(w, errMsg, http.StatusBadRequest)
		return
	}
	if !validateOAuthState(state) {
		http.Error(w, "invalid or expired state", http.StatusForbidden)
		return
	}

	// Build redirect URI (must match the one used in auth-url)
	scheme := "https"
	if r.TLS == nil {
		scheme = "http"
	}
	redirectURI := fmt.Sprintf("%s://%s/api/vk/callback", scheme, r.Host)

	// Exchange code for access token
	tokenURL := "https://oauth.vk.com/access_token"
	resp, err := http.Get(fmt.Sprintf(
		"%s?client_id=%s&client_secret=%s&redirect_uri=%s&code=%s",
		tokenURL, vkClientID, vkClientSecret, url.QueryEscape(redirectURI), code,
	))
	if err != nil {
		http.Error(w, "token exchange failed: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	var tokenResp struct {
		AccessToken  string `json:"access_token"`
		ExpiresIn    int    `json:"expires_in"`
		UserID       int    `json:"user_id"`
		Error        string `json:"error"`
		ErrorDesc    string `json:"error_description"`
	}
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		http.Error(w, "invalid token response", http.StatusBadGateway)
		return
	}
	if tokenResp.Error != "" {
		http.Error(w, fmt.Sprintf("VK error: %s — %s", tokenResp.Error, tokenResp.ErrorDesc), http.StatusBadGateway)
		return
	}
	if tokenResp.AccessToken == "" {
		http.Error(w, "empty access token from VK", http.StatusBadGateway)
		return
	}

	// Calculate expiry
	expiresAt := int64(0)
	if tokenResp.ExpiresIn > 0 {
		expiresAt = time.Now().Unix() + int64(tokenResp.ExpiresIn)
	}

	account := VKAccount{
		ID:          fmt.Sprintf("%d", tokenResp.UserID),
		Name:        fmt.Sprintf("vk_%d", tokenResp.UserID),
		AccessToken: tokenResp.AccessToken,
		ExpiresAt:   expiresAt,
		AddedAt:     time.Now().Format(time.RFC3339),
		Enabled:     true,
	}

	cfg.mu.Lock()
	// Replace if same user ID exists
	found := false
	for i, a := range cfg.VKAccounts {
		if a.ID == account.ID {
			cfg.VKAccounts[i] = account
			found = true
			break
		}
	}
	if !found {
		cfg.VKAccounts = append(cfg.VKAccounts, account)
	}
	cfg.mu.Unlock()
	cfg.Save()

	logger.Printf("VK account added: user_id=%s", account.ID)

	// Show success page (admin's browser is redirected here)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, `<!DOCTYPE html><html><body>
<h2>VK account linked successfully!</h2>
<p>User ID: %s</p>
<p>You can close this tab and return to the admin panel.</p>
<script>window.opener && window.opener.postMessage('vk-auth-ok','*');</script>
</body></html>`, account.ID)
}

// apiVKAccounts lists VK accounts
func apiVKAccounts(w http.ResponseWriter, r *http.Request) {
	cfg.mu.RLock()
	accounts := make([]map[string]interface{}, len(cfg.VKAccounts))
	for i, a := range cfg.VKAccounts {
		accounts[i] = map[string]interface{}{
			"id":         a.ID,
			"name":       a.Name,
			"enabled":    a.Enabled,
			"added_at":   a.AddedAt,
			"expires_at": a.ExpiresAt,
			"last_error": a.LastError,
			"has_token":  a.AccessToken != "",
		}
	}
	cfg.mu.RUnlock()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(accounts)
}

// apiVKDeleteAccount removes a VK account
func apiVKDeleteAccount(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.ID == "" {
		http.Error(w, "id required", http.StatusBadRequest)
		return
	}
	cfg.mu.Lock()
	for i, a := range cfg.VKAccounts {
		if a.ID == req.ID {
			cfg.VKAccounts = append(cfg.VKAccounts[:i], cfg.VKAccounts[i+1:]...)
			break
		}
	}
	cfg.mu.Unlock()
	cfg.Save()
	logger.Printf("VK account removed: %s", req.ID)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

// apiVKAddToken manually adds a VK access token (for when OAuth redirect doesn't work)
func apiVKAddToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	var req struct {
		Token string `json:"token"`
		Name  string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Token == "" {
		http.Error(w, "token required", http.StatusBadRequest)
		return
	}
	if req.Name == "" {
		req.Name = "manual"
	}

	account := VKAccount{
		ID:          fmt.Sprintf("manual_%d", time.Now().Unix()),
		Name:        req.Name,
		AccessToken: req.Token,
		AddedAt:     time.Now().Format(time.RFC3339),
		Enabled:     true,
	}

	cfg.mu.Lock()
	cfg.VKAccounts = append(cfg.VKAccounts, account)
	cfg.mu.Unlock()
	cfg.Save()

	logger.Printf("VK token added manually: name=%s", req.Name)

	// Immediately try to refresh credentials
	go refreshTurnCredentials()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok", "id": account.ID})
}

// apiVKCredentials returns the current cached TURN credentials (debug)
func apiVKCredentials(w http.ResponseWriter, r *http.Request) {
	turnCredsCache.RLock()
	resp := map[string]interface{}{
		"username":   turnCredsCache.Username,
		"address":    turnCredsCache.Address,
		"fetched_at": turnCredsCache.FetchedAt,
		"expires_at": turnCredsCache.ExpiresAt,
		"account_id": turnCredsCache.AccountID,
		"error":      turnCredsCache.Error,
		"has_creds":  turnCredsCache.Username != "",
	}
	turnCredsCache.RUnlock()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// apiVKRefreshCreds manually triggers a credential refresh
func apiVKRefreshCreds(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	refreshTurnCredentials()
	apiVKCredentials(w, r)
}

// apiVKBulkAddTokens adds multiple VK tokens at once
func apiVKBulkAddTokens(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Tokens []struct {
			Token string `json:"token"`
			Name  string `json:"name"`
		} `json:"tokens"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}

	added := 0
	for _, t := range req.Tokens {
		if t.Token == "" {
			continue
		}
		name := t.Name
		if name == "" {
			name = fmt.Sprintf("account_%d", time.Now().UnixNano())
		}
		id := fmt.Sprintf("bulk_%d", time.Now().UnixNano())

		acc := VKAccount{
			ID:          id,
			Name:        name,
			AccessToken: t.Token,
			AddedAt:     time.Now().Format(time.RFC3339),
			Enabled:     true,
			Status:      "idle",
		}

		cfg.mu.Lock()
		cfg.VKAccounts = append(cfg.VKAccounts, acc)
		cfg.mu.Unlock()
		added++
		time.Sleep(10 * time.Millisecond) // ensure unique IDs
	}

	cfg.Save()
	logger.Printf("Bulk added %d VK accounts", added)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"added": added,
		"total": len(cfg.VKAccounts),
	})
}

// apiVKToggleAccount enables/disables a VK account
func apiVKToggleAccount(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}

	cfg.mu.Lock()
	found := false
	for i, a := range cfg.VKAccounts {
		if a.ID == req.ID {
			cfg.VKAccounts[i].Enabled = !cfg.VKAccounts[i].Enabled
			if !cfg.VKAccounts[i].Enabled {
				// End active call if disabling
				credPool.EndCall(a.ID)
				cfg.VKAccounts[i].Status = "idle"
			}
			found = true
			break
		}
	}
	cfg.mu.Unlock()

	if !found {
		http.Error(w, "account not found", http.StatusNotFound)
		return
	}
	cfg.Save()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

// apiVKPoolStatus returns pool health statistics
func apiVKPoolStatus(w http.ResponseWriter, r *http.Request) {
	cfg.mu.RLock()
	total := len(cfg.VKAccounts)
	healthy, rateLimited, banned, tokenExpired, calling, cooldown := 0, 0, 0, 0, 0, 0
	for _, a := range cfg.VKAccounts {
		if !a.Enabled {
			continue
		}
		switch a.Status {
		case "calling":
			calling++
			healthy++
		case "rate_limited":
			rateLimited++
		case "banned":
			banned++
		case "token_expired":
			tokenExpired++
		case "cooldown":
			cooldown++
			healthy++
		default: // "idle" or ""
			healthy++
		}
	}
	pc := cfg.Pool
	cfg.mu.RUnlock()

	if pc.MinCallMinutes == 0 {
		pc = defaultPoolConfig()
	}

	activeCalls, assignedClients, _ := credPool.Stats()
	calls := credPool.ActiveCallsList()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"total_accounts":    total,
		"healthy":           healthy,
		"calling":           calling,
		"cooldown":          cooldown,
		"rate_limited":      rateLimited,
		"banned":            banned,
		"token_expired":     tokenExpired,
		"active_calls":      activeCalls,
		"assigned_clients":  assignedClients,
		"active_calls_list": calls,
		"pool_config":       pc,
	})
}

// apiVKPoolConfig updates pool rotation settings
func apiVKPoolConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	var pc PoolConfig
	if err := json.NewDecoder(r.Body).Decode(&pc); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}

	// Validate
	if pc.MaxCallsPerDay < 1 {
		pc.MaxCallsPerDay = 5
	}
	if pc.MinCallMinutes < 5 {
		pc.MinCallMinutes = 5
	}
	if pc.MaxCallMinutes < pc.MinCallMinutes {
		pc.MaxCallMinutes = pc.MinCallMinutes + 60
	}
	if pc.MinBreakMinutes < 1 {
		pc.MinBreakMinutes = 1
	}
	if pc.MaxBreakMinutes < pc.MinBreakMinutes {
		pc.MaxBreakMinutes = pc.MinBreakMinutes + 30
	}
	if pc.RotationMinutes < 10 {
		pc.RotationMinutes = 10
	}

	cfg.mu.Lock()
	cfg.Pool = pc
	cfg.mu.Unlock()
	cfg.Save()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(pc)
}

// refreshTurnCredentials fetches TURN credentials for a single account (legacy + pool)
func refreshTurnCredentials() {
	// Delegate to call scheduler — start calls for eligible accounts
	runSchedulerTick()
}

// startCallForAccount creates a VK call and gets TURN credentials for one account
func startCallForAccount(account *VKAccount) error {
	creds, err := turnauth.GetVKCredentialsWithToken("", account.AccessToken)
	if err != nil {
		logger.Printf("TURN credential fetch failed (account=%s): %s", account.ID, err)

		// Classify error and update account status
		cfg.mu.Lock()
		for i, a := range cfg.VKAccounts {
			if a.ID == account.ID {
				cfg.VKAccounts[i].LastError = err.Error()
				cfg.VKAccounts[i].FailCount++
				if turnauth.IsRateLimited(err) {
					cfg.VKAccounts[i].Status = "rate_limited"
					cfg.VKAccounts[i].NextCallAt = time.Now().Add(30 * time.Minute).Unix()
				} else if turnauth.IsTokenExpired(err) {
					cfg.VKAccounts[i].Status = "token_expired"
				} else if turnauth.IsBanned(err) {
					cfg.VKAccounts[i].Status = "banned"
					cfg.VKAccounts[i].Enabled = false
				} else if cfg.VKAccounts[i].FailCount >= 3 {
					cfg.VKAccounts[i].Status = "rate_limited"
					cfg.VKAccounts[i].NextCallAt = time.Now().Add(15 * time.Minute).Unix()
				}
				break
			}
		}
		cfg.mu.Unlock()
		return err
	}

	// Success — get pool config for call duration
	cfg.mu.RLock()
	pc := cfg.Pool
	cfg.mu.RUnlock()
	if pc.MinCallMinutes == 0 {
		pc = defaultPoolConfig()
	}

	callDuration := time.Duration(pc.MinCallMinutes+mrand.Intn(max(1, pc.MaxCallMinutes-pc.MinCallMinutes))) * time.Minute
	expiresAt := time.Now().Add(callDuration)

	// Add to credential pool
	credPool.AddCall(account.ID, account.Name, creds.Username, creds.Password, creds.Address, expiresAt)

	// Update legacy cache (backward compat)
	turnCredsCache.Lock()
	turnCredsCache.Username = creds.Username
	turnCredsCache.Password = creds.Password
	turnCredsCache.Address = creds.Address
	turnCredsCache.FetchedAt = time.Now()
	turnCredsCache.ExpiresAt = expiresAt
	turnCredsCache.AccountID = account.ID
	turnCredsCache.Error = ""
	turnCredsCache.Unlock()

	// Update account state
	cfg.mu.Lock()
	for i, a := range cfg.VKAccounts {
		if a.ID == account.ID {
			cfg.VKAccounts[i].LastError = ""
			cfg.VKAccounts[i].FailCount = 0
			cfg.VKAccounts[i].Status = "calling"
			cfg.VKAccounts[i].CallsToday++
			cfg.VKAccounts[i].LastCallAt = time.Now().Unix()
			break
		}
	}
	cfg.mu.Unlock()

	logger.Printf("Call started: user=%s addr=%s (account=%s, duration=%s)", creds.Username, creds.Address, account.ID, callDuration)
	return nil
}

// runSchedulerTick runs one iteration of the call scheduler
func runSchedulerTick() {
	now := time.Now()
	today := now.Format("2006-01-02")

	cfg.mu.RLock()
	pc := cfg.Pool
	accounts := make([]VKAccount, len(cfg.VKAccounts))
	copy(accounts, cfg.VKAccounts)
	cfg.mu.RUnlock()

	if pc.MinCallMinutes == 0 {
		pc = defaultPoolConfig()
	}

	// Phase 1: Reset daily counters if new day
	cfg.mu.Lock()
	for i := range cfg.VKAccounts {
		if cfg.VKAccounts[i].LastResetDay != today {
			cfg.VKAccounts[i].CallsToday = 0
			cfg.VKAccounts[i].LastResetDay = today
			// Reset rate-limited accounts at day boundary
			if cfg.VKAccounts[i].Status == "rate_limited" {
				cfg.VKAccounts[i].Status = "idle"
				cfg.VKAccounts[i].FailCount = 0
			}
		}
	}
	cfg.mu.Unlock()

	// Phase 2: End expired calls
	credPool.mu.RLock()
	var expiredCalls []string
	for accID, call := range credPool.activeCalls {
		if now.After(call.ExpiresAt) {
			expiredCalls = append(expiredCalls, accID)
		}
	}
	credPool.mu.RUnlock()

	for _, accID := range expiredCalls {
		orphans := credPool.EndCall(accID)
		logger.Printf("Call ended for account %s, %d clients orphaned", accID, len(orphans))

		// Set account to cooldown with random break
		breakDuration := time.Duration(pc.MinBreakMinutes+mrand.Intn(max(1, pc.MaxBreakMinutes-pc.MinBreakMinutes))) * time.Minute
		cfg.mu.Lock()
		for i, a := range cfg.VKAccounts {
			if a.ID == accID {
				cfg.VKAccounts[i].Status = "cooldown"
				cfg.VKAccounts[i].NextCallAt = now.Add(breakDuration).Unix()
				break
			}
		}
		cfg.mu.Unlock()
	}

	// Phase 3: Start new calls for eligible accounts
	// Re-read accounts after updates
	cfg.mu.RLock()
	accounts = make([]VKAccount, len(cfg.VKAccounts))
	copy(accounts, cfg.VKAccounts)
	cfg.mu.RUnlock()

	// Count active clients that need credentials
	credPool.mu.RLock()
	activeCallCount := len(credPool.activeCalls)
	credPool.mu.RUnlock()

	for _, acc := range accounts {
		if !acc.Enabled || acc.AccessToken == "" {
			continue
		}
		// Skip accounts already in a call
		credPool.mu.RLock()
		_, alreadyCalling := credPool.activeCalls[acc.ID]
		credPool.mu.RUnlock()
		if alreadyCalling {
			continue
		}
		// Skip accounts at daily limit
		if acc.CallsToday >= pc.MaxCallsPerDay {
			continue
		}
		// Skip accounts in cooldown/rate_limited that aren't ready yet
		if (acc.Status == "cooldown" || acc.Status == "rate_limited") && now.Unix() < acc.NextCallAt {
			continue
		}
		// Skip banned/expired accounts
		if acc.Status == "banned" || acc.Status == "token_expired" {
			continue
		}

		// Start a call for this account
		// Stagger: don't start more than one call per tick
		if err := startCallForAccount(&acc); err == nil {
			activeCallCount++
			break // one call per tick to stagger naturally
		}
	}

	// Update legacy turnCredsCache error if no active calls
	if activeCallCount == 0 {
		turnCredsCache.Lock()
		if turnCredsCache.Error == "" {
			enabledCount := 0
			for _, a := range accounts {
				if a.Enabled && a.AccessToken != "" {
					enabledCount++
				}
			}
			if enabledCount == 0 {
				turnCredsCache.Error = "no enabled VK accounts"
			}
		}
		turnCredsCache.Unlock()
	}
}

// startCallScheduler runs the call scheduler as a background goroutine
func startCallScheduler(ctx context.Context) {
	// Initial fetch after 5 seconds (let server start up)
	time.Sleep(5 * time.Second)
	runSchedulerTick()

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			runSchedulerTick()
		}
	}
}

// startCredentialManager is an alias for startCallScheduler (backward compat)
func startCredentialManager(ctx context.Context) {
	startCallScheduler(ctx)
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

// ─── Device Logs ───

type DeviceLogEntry struct {
	Device    string `json:"device"`
	Time      string `json:"time"`
	Message   string `json:"message"`
	Level     string `json:"level"` // info, warn, error
	Received  int64  `json:"received"`
}

type DeviceLogStore struct {
	mu      sync.RWMutex
	entries []DeviceLogEntry
	max     int
}

var deviceLogs = &DeviceLogStore{max: 2000}

func (s *DeviceLogStore) Add(entries []DeviceLogEntry) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now().Unix()
	for i := range entries {
		entries[i].Received = now
	}
	s.entries = append(s.entries, entries...)
	// Trim to max
	if len(s.entries) > s.max {
		s.entries = s.entries[len(s.entries)-s.max:]
	}
}

func (s *DeviceLogStore) Get(device string, since int64) []DeviceLogEntry {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var result []DeviceLogEntry
	for _, e := range s.entries {
		if since > 0 && e.Received <= since {
			continue
		}
		if device != "" && e.Device != device {
			continue
		}
		result = append(result, e)
	}
	return result
}

func (s *DeviceLogStore) Cleanup(maxAge time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cutoff := time.Now().Add(-maxAge).Unix()
	n := 0
	for _, e := range s.entries {
		if e.Received > cutoff {
			s.entries[n] = e
			n++
		}
	}
	s.entries = s.entries[:n]
}

// POST /api/device-logs — receive logs from device (no auth needed — device sends its name)
func apiDeviceLogsPush(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20) // 1MB max
	var req struct {
		Device  string           `json:"device"`
		Entries []DeviceLogEntry `json:"entries"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if req.Device == "" || len(req.Entries) == 0 {
		http.Error(w, "device and entries required", http.StatusBadRequest)
		return
	}
	// Validate and set device name on all entries
	for i := range req.Entries {
		req.Entries[i].Device = req.Device
	}
	deviceLogs.Add(req.Entries)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

// GET /api/device-logs — view device logs (auth required)
func apiDeviceLogsGet(w http.ResponseWriter, r *http.Request) {
	device := r.URL.Query().Get("device")
	var since int64
	if v := r.URL.Query().Get("since"); v != "" {
		since, _ = strconv.ParseInt(v, 10, 64)
	}
	entries := deviceLogs.Get(device, since)
	if entries == nil {
		entries = []DeviceLogEntry{}
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(entries)
}

func init() {
	// Cleanup device logs every hour (keep 24h)
	go func() {
		for range time.Tick(time.Hour) {
			deviceLogs.Cleanup(24 * time.Hour)
		}
	}()
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

	// Start DTLS server (primary transport: TURN)
	go runDTLSServer(ctx, *dtlsAddr, *wgConnect)

	// Start VP8 server (secondary transport: data inside VK Call video stream)
	cfg.mu.RLock()
	vp8On := cfg.VP8Enabled
	cfg.mu.RUnlock()
	if vp8On {
		go runVP8Server(ctx, *wgConnect)
	}

	// Start background TURN credential manager
	go startCredentialManager(ctx)

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
	mux.HandleFunc("/api/vp8", authMiddleware(apiVP8Config))
	mux.HandleFunc("/api/clients", authMiddleware(apiListClients))
	mux.HandleFunc("/api/clients/add", authMiddleware(apiAddClient))
	mux.HandleFunc("/api/clients/delete", authMiddleware(apiDeleteClient))
	mux.HandleFunc("/api/clients/toggle", authMiddleware(apiToggleClient))
	mux.HandleFunc("/api/clients/config", authMiddleware(apiClientConfig))
	mux.HandleFunc("/api/clients/appconfig", authMiddleware(apiAppConfig))
	mux.HandleFunc("/api/vk/auth-url", authMiddleware(apiVKAuthURL))
	mux.HandleFunc("/api/vk/callback", apiVKCallback) // no auth — VK redirects here
	mux.HandleFunc("/api/vk/accounts", authMiddleware(apiVKAccounts))
	mux.HandleFunc("/api/vk/accounts/delete", authMiddleware(apiVKDeleteAccount))
	mux.HandleFunc("/api/vk/accounts/add-token", authMiddleware(apiVKAddToken))
	mux.HandleFunc("/api/vk/credentials", authMiddleware(apiVKCredentials))
	mux.HandleFunc("/api/vk/credentials/refresh", authMiddleware(apiVKRefreshCreds))
	mux.HandleFunc("/api/vk/accounts/bulk-add", authMiddleware(apiVKBulkAddTokens))
	mux.HandleFunc("/api/vk/accounts/toggle", authMiddleware(apiVKToggleAccount))
	mux.HandleFunc("/api/vk/pool-status", authMiddleware(apiVKPoolStatus))
	mux.HandleFunc("/api/vk/pool-config", authMiddleware(apiVKPoolConfig))
	mux.HandleFunc("/api/logs", authMiddleware(apiLogs))
	mux.HandleFunc("/api/metrics", authMiddleware(apiMetrics))
	mux.HandleFunc("/api/device-logs", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			apiDeviceLogsPush(w, r) // no auth — devices push logs
		} else {
			authMiddleware(apiDeviceLogsGet)(w, r) // auth required to view
		}
	})

	webContent, _ := fs.Sub(webFS, "web")
	fileServer := http.FileServer(http.FS(webContent))
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if tok := r.URL.Query().Get("token"); tok != "" && cfg.checkPassword(tok) {
			setSessionCookie(w, r)
		}
		fileServer.ServeHTTP(w, r)
	})

	// Security headers middleware
	secureHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		if r.TLS != nil {
			w.Header().Set("Strict-Transport-Security", "max-age=31536000")
		}
		mux.ServeHTTP(w, r)
	})

	server := &http.Server{Addr: *webAddr, Handler: secureHandler}
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
