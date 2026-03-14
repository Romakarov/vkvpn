package main

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"embed"
	"encoding/base64"
	"encoding/json"
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
	"sync"
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
	Clients     []Client `json:"clients"`
	DTLSPort    int      `json:"dtls_port"`
	AdminPass   string   `json:"admin_pass"`
}

type Client struct {
	Name       string `json:"name"`
	PrivateKey string `json:"private_key"`
	PublicKey  string `json:"public_key"`
	IP         string `json:"ip"`
	CreatedAt  string `json:"created_at"`
	Enabled    bool   `json:"enabled"`
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
	c.mu.RLock()
	defer c.mu.RUnlock()
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(c.path, data, 0600)
}

// ─── WireGuard management ───

func wgGenKey() (priv, pub string, err error) {
	out, err := exec.Command("wg", "genkey").Output()
	if err != nil {
		return "", "", fmt.Errorf("wg genkey: %w", err)
	}
	priv = strings.TrimSpace(string(out))

	cmd := exec.Command("wg", "pubkey")
	cmd.Stdin = strings.NewReader(priv)
	out, err = cmd.Output()
	if err != nil {
		return "", "", fmt.Errorf("wg pubkey: %w", err)
	}
	pub = strings.TrimSpace(string(out))
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
	sb.WriteString(fmt.Sprintf("Address = %s/24\n", strings.Replace(c.WGSubnet, ".0/", ".1/", 1)))
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
		lb.entries = lb.entries[1:]
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

// ─── DTLS Server ───

func runDTLSServer(ctx context.Context, listenAddr string, connectAddr string) {
	certificate, err := selfsign.GenerateSelfSigned()
	if err != nil {
		logger.Fatalf("Failed to generate certificate: %s", err)
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

		wg.Add(1)
		go func(conn net.Conn) {
			defer wg.Done()
			defer conn.Close()
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
					conn.SetReadDeadline(time.Now().Add(30 * time.Minute))
					n, err := conn.Read(buf)
					if err != nil {
						logger.Printf("Read error: %s", err)
						return
					}
					serverConn.SetWriteDeadline(time.Now().Add(30 * time.Minute))
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

func authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cfg.mu.RLock()
		pass := cfg.AdminPass
		cfg.mu.RUnlock()

		if pass == "" {
			next(w, r)
			return
		}

		// Check cookie or header
		cookie, err := r.Cookie("admin_token")
		if err == nil && cookie.Value == pass {
			next(w, r)
			return
		}
		if r.Header.Get("X-Admin-Token") == pass {
			next(w, r)
			return
		}

		// Check query param (for initial login)
		if r.URL.Query().Get("token") == pass {
			http.SetCookie(w, &http.Cookie{
				Name:     "admin_token",
				Value:    pass,
				Path:     "/",
				MaxAge:   86400 * 30,
				HttpOnly: true,
			})
			next(w, r)
			return
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

func apiSetLink(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Link string `json:"link"`
		Type string `json:"type"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if req.Type == "" {
		if strings.Contains(req.Link, "vk.com") || strings.Contains(req.Link, "vk.ru") {
			req.Type = "vk"
		} else if strings.Contains(req.Link, "telemost") || strings.Contains(req.Link, "yandex") {
			req.Type = "yandex"
		} else {
			http.Error(w, "cannot detect link type, specify 'type' field", http.StatusBadRequest)
			return
		}
	}

	cfg.mu.Lock()
	cfg.ActiveLink = req.Link
	cfg.LinkType = req.Type
	cfg.mu.Unlock()
	cfg.Save()

	logger.Printf("Link updated: type=%s link=%s", req.Type, req.Link)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
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
	var req struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if req.Name == "" {
		http.Error(w, "name required", http.StatusBadRequest)
		return
	}

	priv, pub, err := wgGenKey()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
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
		PrivateKey: priv,
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

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok", "ip": ip})
}

func apiDeleteClient(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
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
		"server":     cfg.ServerIP,
		"link":       cfg.ActiveLink,
		"provider":   cfg.LinkType,
		"wg_privkey": found.PrivateKey,
		"wg_pubkey":  cfg.ServerPub,
		"wg_address": found.IP,
		"wg_dns":     cfg.DNS,
		"wg_port":    cfg.WGPort,
		"dtls_port":  cfg.DTLSPort,
		"name":       found.Name,
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
	if cfg.AdminPass == "" {
		cfg.AdminPass = generateAdminPass()
		needSave = true
		logger.Printf("Admin password generated: %s", cfg.AdminPass)
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
		logger.Printf("Terminating...")
		cancel()
		<-signalChan
		logger.Fatalf("Exit...")
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
	mux.HandleFunc("/api/status", authMiddleware(apiGetStatus))
	mux.HandleFunc("/api/link", authMiddleware(apiSetLink))
	mux.HandleFunc("/api/clients", authMiddleware(apiListClients))
	mux.HandleFunc("/api/clients/add", authMiddleware(apiAddClient))
	mux.HandleFunc("/api/clients/delete", authMiddleware(apiDeleteClient))
	mux.HandleFunc("/api/clients/toggle", authMiddleware(apiToggleClient))
	mux.HandleFunc("/api/clients/config", authMiddleware(apiClientConfig))
	mux.HandleFunc("/api/clients/appconfig", authMiddleware(apiAppConfig))
	mux.HandleFunc("/api/logs", authMiddleware(apiLogs))

	webContent, _ := fs.Sub(webFS, "web")
	mux.Handle("/", http.FileServer(http.FS(webContent)))

	server := &http.Server{Addr: *webAddr, Handler: mux}
	go func() {
		<-ctx.Done()
		server.Shutdown(context.Background())
	}()

	logger.Printf("Admin panel: http://%s/?token=%s", *webAddr, cfg.AdminPass)
	logger.Printf("DTLS server: %s", *dtlsAddr)

	if err := server.ListenAndServe(); err != http.ErrServerClosed {
		logger.Fatalf("Web server error: %s", err)
	}
}
