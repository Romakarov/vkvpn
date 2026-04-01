// Package tunnel provides a WireGuard VPN tunneled through TURN servers for Android.
//
// Architecture:
//   Android VpnService creates TUN fd → wireguard-go encrypts packets →
//   DTLS+TURN tunnel forwards encrypted WG packets through VK/Yandex TURN → VPS
package tunnel

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/pion/dtls/v3"
	"github.com/pion/dtls/v3/pkg/crypto/selfsign"
	"github.com/pion/logging"
	"github.com/pion/turn/v5"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"

	"github.com/Romakarov/vkvpn/pkg/telemost"
	"github.com/Romakarov/vkvpn/pkg/vp8tunnel"

	_ "golang.org/x/mobile/bind" // required by gomobile
)

// State holds the running tunnel state
var (
	tunnelCtx    context.Context
	tunnelCancel context.CancelFunc
	tunnelMu     sync.Mutex
	running      bool
	logCallback  func(string)
	wgDevice     *device.Device
	wgCloseOnce  sync.Once
)

// clientSessionID is a 16-byte UUID generated once per tunnel start.
// All DTLS connections send it so the server groups them into one WG session.
var clientSessionID [16]byte

func init() {
	cryptoRand := make([]byte, 16)
	if _, err := rand.Read(cryptoRand); err != nil {
		// Fallback: use time-based seed (not cryptographically secure, but functional)
		for i := range cryptoRand {
			cryptoRand[i] = byte(time.Now().UnixNano() >> (i * 8))
		}
	}
	copy(clientSessionID[:], cryptoRand)
}

// LogHandler is an interface for receiving log messages (gomobile-compatible)
type LogHandler interface {
	OnLog(msg string)
}

// ─── Remote Logging ───

type remoteLogger struct {
	mu       sync.Mutex
	entries  []logEntry
	serverURL string
	device    string
	ctx       context.Context
	cancel    context.CancelFunc
}

type logEntry struct {
	Time    string `json:"time"`
	Message string `json:"message"`
	Level   string `json:"level"`
}

var rlog = &remoteLogger{}

// setLogCallback sets a callback for log messages (internal use)
func setLogCallback(cb func(string)) {
	logCallback = cb
}

// SetLogHandler sets a gomobile-compatible log handler
func SetLogHandler(h LogHandler) {
	if h != nil {
		logCallback = h.OnLog
	}
}

// SetRemoteLog configures remote log shipping to VPS.
// Call from Android: tunnel.SetRemoteLog("https://VPS:8080", "device_name")
func SetRemoteLog(serverURL, deviceName string) {
	rlog.mu.Lock()
	defer rlog.mu.Unlock()
	if rlog.cancel != nil {
		rlog.cancel()
	}
	rlog.serverURL = strings.TrimRight(serverURL, "/")
	rlog.device = deviceName
	rlog.ctx, rlog.cancel = context.WithCancel(context.Background())
	// Start periodic flush goroutine
	go func() {
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-rlog.ctx.Done():
				rlog.flush() // final flush
				return
			case <-ticker.C:
				rlog.flush()
			}
		}
	}()
}

// GetLogs returns all buffered logs as JSON string (for Android UI)
func GetLogs() string {
	rlog.mu.Lock()
	defer rlog.mu.Unlock()
	b, _ := json.Marshal(rlog.entries)
	return string(b)
}

// ClearLogs clears the log buffer
func ClearLogs() {
	rlog.mu.Lock()
	defer rlog.mu.Unlock()
	rlog.entries = nil
}

func (r *remoteLogger) add(level, msg string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	entry := logEntry{
		Time:    time.Now().Format("15:04:05.000"),
		Message: msg,
		Level:   level,
	}
	r.entries = append(r.entries, entry)
	// Keep max 500 entries in memory
	if len(r.entries) > 500 {
		r.entries = r.entries[len(r.entries)-500:]
	}
}

func (r *remoteLogger) flush() {
	r.mu.Lock()
	if len(r.entries) == 0 || r.serverURL == "" {
		r.mu.Unlock()
		return
	}
	// Copy and clear
	toSend := make([]logEntry, len(r.entries))
	copy(toSend, r.entries)
	device := r.device
	url := r.serverURL + "/api/device-logs"
	r.mu.Unlock()

	payload, _ := json.Marshal(map[string]interface{}{
		"device":  device,
		"entries": toSend,
	})

	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
	}
	resp, err := client.Post(url, "application/json", bytes.NewReader(payload))
	if err == nil {
		resp.Body.Close()
		if resp.StatusCode == 200 {
			// Successfully sent — clear sent entries
			r.mu.Lock()
			if len(r.entries) >= len(toSend) {
				r.entries = r.entries[len(toSend):]
			}
			r.mu.Unlock()
		}
	}
}

func logMsg(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	log.Print(msg)
	rlog.add("info", msg)
	if logCallback != nil {
		logCallback(msg)
	}
}

func logErr(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	log.Print("ERROR: " + msg)
	rlog.add("error", msg)
	if logCallback != nil {
		logCallback("ERROR: " + msg)
	}
}

// ─── Android TUN device for wireguard-go ───

type androidTUN struct {
	file      *os.File
	mtu       int
	events    chan tun.Event
	closeOnce sync.Once
}

func newAndroidTUN(fd int, mtu int) *androidTUN {
	t := &androidTUN{
		file:   os.NewFile(uintptr(fd), "/dev/tun"),
		mtu:    mtu,
		events: make(chan tun.Event, 1),
	}
	t.events <- tun.EventUp
	return t
}

func (t *androidTUN) File() *os.File            { return t.file }
func (t *androidTUN) Name() (string, error)     { return "tun0", nil }
func (t *androidTUN) MTU() (int, error)         { return t.mtu, nil }
func (t *androidTUN) Events() <-chan tun.Event   { return t.events }
func (t *androidTUN) BatchSize() int             { return 1 }

func (t *androidTUN) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	n, err := t.file.Read(bufs[0][offset:])
	if err != nil {
		return 0, err
	}
	sizes[0] = n
	return 1, nil
}

func (t *androidTUN) Write(bufs [][]byte, offset int) (int, error) {
	for i, buf := range bufs {
		if offset <= len(buf) {
			_, err := t.file.Write(buf[offset:])
			if err != nil {
				return i, err
			}
		}
	}
	return len(bufs), nil
}

func (t *androidTUN) Close() error {
	var err error
	t.closeOnce.Do(func() {
		close(t.events)
		err = t.file.Close()
	})
	return err
}

// ─── Public API ───

// Start starts the tunnel.
// tunFd: TUN file descriptor from Android VpnService (via detachFd)
// peerAddr: VPS DTLS address "host:port" (e.g. "1.2.3.4:56000")
// vkLink: VK call invite link (or empty)
// yandexLink: Yandex Telemost link (or empty)
// connections: number of parallel TURN connections (0 = auto)
// wgPrivKey: WireGuard client private key (base64)
// serverPubKey: WireGuard server public key (base64)
// StartWithCreds starts the tunnel using pre-supplied TURN credentials from the server.
// If turnUser is non-empty, the TURN credential extraction is bypassed.
// telemostLink is an optional Telemost conference link for VP8 fallback transport.
func StartWithCreds(tunFd int, peerAddr, vkLink, yandexLink string, connections int, wgPrivKey, serverPubKey, dtlsFingerprint, turnUser, turnPass, turnAddr, telemostLink string) error {
	// Store server-provided credentials for use in oneTurnConnection
	if turnUser != "" {
		serverTurnCreds.user = turnUser
		serverTurnCreds.pass = turnPass
		serverTurnCreds.addr = turnAddr
	} else {
		serverTurnCreds.user = ""
		serverTurnCreds.pass = ""
		serverTurnCreds.addr = ""
	}
	// Store Telemost link for VP8 fallback
	vp8FallbackLink = telemostLink
	return Start(tunFd, peerAddr, vkLink, yandexLink, connections, wgPrivKey, serverPubKey, dtlsFingerprint)
}

// vp8FallbackLink stores the Telemost conference link for VP8 transport fallback.
var vp8FallbackLink string

// StartVP8 starts VP8 tunnel through Telemost conference.
// tunFd: TUN fd from Android VpnService
// telemostLink: Telemost conference URL
// wgPrivKey/serverPubKey: WireGuard keys (base64)
func StartVP8(tunFd int, telemostLink, wgPrivKey, serverPubKey, wgAddress, wgDNS string) error {
	tunnelMu.Lock()
	if running {
		tunnelMu.Unlock()
		return fmt.Errorf("tunnel already running")
	}
	running = true
	tunnelMu.Unlock()

	resetRunning := func() { tunnelMu.Lock(); running = false; tunnelMu.Unlock() }

	if telemostLink == "" {
		resetRunning()
		return fmt.Errorf("telemost link required for VP8 mode")
	}

	logMsg("[VP8] Starting VP8/Telemost tunnel...")

	ctx, cancel := context.WithCancel(context.Background())
	tunnelCtx = ctx
	tunnelCancel = cancel

	go func() {
		defer resetRunning()
		defer cancel()

		err := runVP8Tunnel(ctx, tunFd, telemostLink, wgPrivKey, serverPubKey, wgAddress, wgDNS)
		if err != nil && ctx.Err() == nil {
			logMsg("[VP8] Tunnel error: %s", err)
		}
	}()

	return nil
}

// runVP8Tunnel runs the VP8/Telemost tunnel loop.
func runVP8Tunnel(ctx context.Context, tunFd int, telemostLink, wgPrivKey, serverPubKey, wgAddress, wgDNS string) error {
	// Use Android-specific TUN wrapper (same as TURN mode) — tun.CreateTUNFromFile
	// does not work on Android because it expects Linux TUN semantics.
	//
	// MTU=1000: VP8 tunnel limits payloads to 1100 bytes (MaxPayloadSize).
	// WireGuard adds 48 bytes overhead, so inner IP MTU must be ≤1052.
	// Using 1000 gives headroom: WG packet = 1048 bytes ≤ 1100.
	tunDev := newAndroidTUN(tunFd, 1000)

	// Listen on local UDP for WireGuard
	listenConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		return fmt.Errorf("listen UDP: %w", err)
	}
	defer listenConn.Close()

	localAddr := listenConn.LocalAddr().String()
	logMsg("[VP8] WireGuard endpoint: %s", localAddr)

	// Decode keys
	privBytes, err := base64.StdEncoding.DecodeString(wgPrivKey)
	if err != nil || len(privBytes) != 32 {
		return fmt.Errorf("invalid WG private key")
	}
	pubBytes, err := base64.StdEncoding.DecodeString(serverPubKey)
	if err != nil || len(pubBytes) != 32 {
		return fmt.Errorf("invalid WG public key")
	}

	wgConf := fmt.Sprintf(
		"private_key=%s\npublic_key=%s\nendpoint=%s\nallowed_ip=0.0.0.0/0\npersistent_keepalive_interval=25\n",
		hex.EncodeToString(privBytes), hex.EncodeToString(pubBytes), localAddr,
	)

	dev := device.NewDevice(tunDev, conn.NewDefaultBind(), device.NewLogger(device.LogLevelError, "wg-vp8: "))
	if err := dev.IpcSet(wgConf); err != nil {
		dev.Close()
		return fmt.Errorf("WG config: %w", err)
	}
	if err := dev.Up(); err != nil {
		dev.Close()
		return fmt.Errorf("WG up: %w", err)
	}
	defer dev.Close()
	logMsg("[VP8] WireGuard device up")

	// Loop: connect to Telemost, bridge VP8↔WireGuard, reconnect on failure
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		client := telemost.NewClient(log.Default())
		tunnelReady := make(chan *vp8tunnel.Tunnel, 1)
		client.OnTunnel = func(t *vp8tunnel.Tunnel) {
			tunnelReady <- t
		}

		callDone := make(chan error, 1)
		go func() {
			callDone <- client.JoinCall(ctx, telemostLink)
		}()

		select {
		case tunnel := <-tunnelReady:
			logMsg("[VP8] Telemost tunnel established — bridging to WireGuard")
			bridgeVP8ToLocal(ctx, listenConn, tunnel)
			logMsg("[VP8] Bridge ended")

		case err := <-callDone:
			if ctx.Err() != nil {
				return ctx.Err()
			}
			logMsg("[VP8] Telemost failed: %v", err)
		}

		client.Close()
		if ctx.Err() != nil {
			return ctx.Err()
		}
		logMsg("[VP8] Reconnecting in 5s...")
		select {
		case <-time.After(5 * time.Second):
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

// bridgeVP8ToLocal forwards packets between local WireGuard UDP and VP8 tunnel.
func bridgeVP8ToLocal(ctx context.Context, localConn net.PacketConn, tunnel *vp8tunnel.Tunnel) {
	pconn := vp8tunnel.NewPacketConn(tunnel)
	var wgClientAddr atomic.Value // stores *net.Addr of WG client

	ctx2, cancel := context.WithCancel(ctx)
	defer cancel()

	var wg sync.WaitGroup
	wg.Add(2)

	// Local WG → VP8
	go func() {
		defer wg.Done()
		defer cancel()
		buf := make([]byte, 1600)
		for {
			n, addr, err := localConn.ReadFrom(buf)
			if err != nil || ctx2.Err() != nil {
				return
			}
			wgClientAddr.Store(&addr)
			if _, err := pconn.WriteTo(buf[:n], nil); err != nil {
				return
			}
		}
	}()

	// VP8 → Local WG
	go func() {
		defer wg.Done()
		defer cancel()
		buf := make([]byte, 1600)
		for {
			n, _, err := pconn.ReadFrom(buf)
			if err != nil || ctx2.Err() != nil {
				return
			}
			addrPtr := wgClientAddr.Load()
			if addrPtr == nil {
				continue
			}
			addr := *addrPtr.(*net.Addr)
			if _, err := localConn.WriteTo(buf[:n], addr); err != nil {
				return
			}
		}
	}()

	// Wait for tunnel to close or context cancel
	select {
	case <-tunnel.Done():
	case <-ctx2.Done():
	}
	cancel()
	wg.Wait()
}


// hexKey converts base64 WG key to hex for wireguard IPC
func hexKey(b64 string) string {
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return ""
	}
	return hex.EncodeToString(raw)
}

// serverTurnCreds holds pre-supplied TURN credentials from the VPN server
var serverTurnCreds struct {
	user string
	pass string
	addr string
}

// serverInfo holds the VPS server URL and client name for runtime credential refresh.
var serverInfo struct {
	url  string // e.g. "https://1.2.3.4:8080"
	name string // client name (e.g. "Alex")
}

// SetServerInfo configures the server URL and client name for runtime TURN credential refresh.
// Call from Android before StartWithCreds().
func SetServerInfo(serverURL, clientName string) {
	serverInfo.url = strings.TrimRight(serverURL, "/")
	serverInfo.name = clientName
	logMsg("Server info set: url=%s name=%s", serverInfo.url, clientName)
}

// fetchFreshCreds fetches fresh TURN credentials from the VPS server.
// Updates serverTurnCreds in place. Called before connecting and on reconnect.
func fetchFreshCreds() error {
	if serverInfo.url == "" || serverInfo.name == "" {
		return fmt.Errorf("server info not set")
	}
	url := fmt.Sprintf("%s/api/turn-creds?name=%s", serverInfo.url, serverInfo.name)
	logMsg("[TURN] Fetching fresh credentials from %s", url)

	client := &http.Client{
		Timeout:   15 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			DialContext:     androidDNSDialer().DialContext,
		},
	}
	resp, err := client.Get(url)
	if err != nil {
		return fmt.Errorf("HTTP request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("server returned %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var creds struct {
		User string `json:"turn_username"`
		Pass string `json:"turn_password"`
		Addr string `json:"turn_address"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&creds); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}
	if creds.User == "" || creds.Addr == "" {
		return fmt.Errorf("empty credentials in response")
	}

	serverTurnCreds.user = creds.User
	serverTurnCreds.pass = creds.Pass
	serverTurnCreds.addr = creds.Addr
	logMsg("[TURN] Fetched fresh credentials: user=%s addr=%s", creds.User, creds.Addr)
	return nil
}

func Start(tunFd int, peerAddr, vkLink, yandexLink string, connections int, wgPrivKey, serverPubKey, dtlsFingerprint string) error {
	tunnelMu.Lock()
	if running {
		tunnelMu.Unlock()
		return fmt.Errorf("tunnel already running")
	}
	running = true // set immediately to prevent TOCTOU race
	tunnelMu.Unlock()

	resetRunning := func() { tunnelMu.Lock(); running = false; tunnelMu.Unlock() }

	if peerAddr == "" {
		resetRunning()
		return fmt.Errorf("peer address required")
	}
	if vkLink == "" && yandexLink == "" && serverTurnCreds.user == "" {
		resetRunning()
		return fmt.Errorf("VK or Yandex link required (or server-provided TURN credentials)")
	}
	if wgPrivKey == "" || serverPubKey == "" {
		resetRunning()
		return fmt.Errorf("WireGuard keys required")
	}

	tunnelDTLSFingerprint = strings.ToLower(dtlsFingerprint)

	peer, err := net.ResolveUDPAddr("udp", peerAddr)
	if err != nil {
		return fmt.Errorf("invalid peer: %s", err)
	}

	// Decode WG keys from base64 to hex (wireguard-go IPC format)
	privBytes, err := base64.StdEncoding.DecodeString(wgPrivKey)
	if err != nil || len(privBytes) != 32 {
		resetRunning()
		return fmt.Errorf("invalid WG private key")
	}
	pubBytes, err := base64.StdEncoding.DecodeString(serverPubKey)
	if err != nil || len(pubBytes) != 32 {
		resetRunning()
		return fmt.Errorf("invalid WG public key")
	}

	// If server info is set, fetch fresh TURN credentials before connecting.
	// This ensures we always have a valid TURN allocation (VK kills idle calls).
	if serverInfo.url != "" && serverInfo.name != "" {
		if err := fetchFreshCreds(); err != nil {
			logErr("[TURN] Fresh credential fetch failed: %s (using cached)", err)
			// Continue with cached creds — they might still work
		}
	}

	var link string
	var getCreds func(string) (string, string, string, error)
	if serverTurnCreds.user != "" {
		// Server-provided credentials — link is optional, getCreds won't be called
		link = "server-provided"
		getCreds = func(string) (string, string, string, error) {
			return serverTurnCreds.user, serverTurnCreds.pass, serverTurnCreds.addr, nil
		}
		if connections <= 0 {
			// Use 2 connections: one active + one hot standby.
			// More connections all use the same TURN credentials, adding unnecessary
			// load on the TURN server without reliability benefit.
			connections = 2
		}
	} else if vkLink != "" {
		parts := strings.Split(vkLink, "join/")
		link = parts[len(parts)-1]
		getCreds = getVkCreds
		if connections <= 0 {
			connections = 16
		}
	} else {
		return fmt.Errorf("Yandex Telemost TURN is no longer available (blocked relay to external IPs, March 2026). Use VK link or server-provided credentials")
	}
	if idx := strings.IndexAny(link, "/?#"); idx != -1 {
		link = link[:idx]
	}

	ctx, cancel := context.WithCancel(context.Background())

	// Internal UDP listener: wireguard-go sends encrypted packets here,
	// DTLS+TURN tunnel picks them up and forwards to server
	listenConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		cancel()
		return fmt.Errorf("listen: %s", err)
	}
	internalPort := listenConn.LocalAddr().(*net.UDPAddr).Port
	context.AfterFunc(ctx, func() { listenConn.Close() })

	// Create wireguard-go device with Android TUN fd
	tunDev := newAndroidTUN(tunFd, 1280)
	wgBind := conn.NewDefaultBind()
	wgLogger := device.NewLogger(device.LogLevelError, "wg: ")
	dev := device.NewDevice(tunDev, wgBind, wgLogger)

	ipcConfig := fmt.Sprintf(
		"private_key=%s\npublic_key=%s\nendpoint=127.0.0.1:%d\nallowed_ip=0.0.0.0/0\npersistent_keepalive_interval=25\n",
		hex.EncodeToString(privBytes),
		hex.EncodeToString(pubBytes),
		internalPort,
	)
	if err := dev.IpcSet(ipcConfig); err != nil {
		cancel()
		dev.Close()
		return fmt.Errorf("WireGuard config: %s", err)
	}
	if err := dev.Up(); err != nil {
		cancel()
		dev.Close()
		return fmt.Errorf("WireGuard up: %s", err)
	}

	wgCloseOnce = sync.Once{} // reset for new tunnel
	tunnelMu.Lock()
	tunnelCtx = ctx
	tunnelCancel = cancel
	wgDevice = dev
	tunnelMu.Unlock()

	logMsg("Tunnel starting: peer=%s connections=%d wg_internal_port=%d", peerAddr, connections, internalPort)

	params := &turnParams{
		link:     link,
		getCreds: getCreds,
	}

	// Feed listenConn to DTLS connection loops
	listenConnChan := make(chan net.PacketConn)
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case listenConnChan <- listenConn:
			}
		}
	}()

	// Start DTLS+TURN connection goroutines
	go func() {
		var wg sync.WaitGroup
		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()
		t := ticker.C

		okchan := make(chan struct{})
		connchan := make(chan net.PacketConn)

		wg.Add(2)
		go func() {
			defer wg.Done()
			oneDtlsConnectionLoop(ctx, peer, listenConnChan, connchan, okchan)
		}()
		go func() {
			defer wg.Done()
			oneTurnConnectionLoop(ctx, params, peer, connchan, t)
		}()

		select {
		case <-okchan:
			logMsg("First DTLS connection established")
		case <-ctx.Done():
		}

		for i := 0; i < connections-1; i++ {
			cc := make(chan net.PacketConn)
			wg.Add(2)
			go func() {
				defer wg.Done()
				oneDtlsConnectionLoop(ctx, peer, listenConnChan, cc, nil)
			}()
			go func() {
				defer wg.Done()
				oneTurnConnectionLoop(ctx, params, peer, cc, t)
			}()
		}

		wg.Wait()
		wgCloseOnce.Do(func() { dev.Close() })
		tunnelMu.Lock()
		running = false
		wgDevice = nil
		tunnelMu.Unlock()
		logMsg("Tunnel stopped")
	}()

	return nil
}

// Stop stops the tunnel and waits for goroutines to exit (up to 5 seconds).
func Stop() {
	tunnelMu.Lock()
	if running && tunnelCancel != nil {
		tunnelCancel()
	}
	tunnelMu.Unlock()

	wgCloseOnce.Do(func() {
		tunnelMu.Lock()
		dev := wgDevice
		wgDevice = nil
		tunnelMu.Unlock()
		if dev != nil {
			dev.Close()
		}
	})

	// Wait for goroutines to set running=false (max 5 seconds)
	for i := 0; i < 50; i++ {
		tunnelMu.Lock()
		r := running
		tunnelMu.Unlock()
		if !r {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	// Force reset if goroutines are stuck
	tunnelMu.Lock()
	running = false
	tunnelMu.Unlock()
	logMsg("Stop: forced running=false after timeout")
}

// IsRunning returns true if tunnel is active
func IsRunning() bool {
	tunnelMu.Lock()
	defer tunnelMu.Unlock()
	return running
}

// ─── Packet pipe (inline, no external dep) ───

type packet struct {
	data []byte
	addr net.Addr
}

type pipeConn struct {
	ch     chan packet
	peer   *pipeConn
	mu     sync.Mutex
	closed bool
}

type pipeAddr struct{}

func (pipeAddr) Network() string { return "pipe" }
func (pipeAddr) String() string  { return "pipe" }

func asyncPacketPipe() (net.PacketConn, net.PacketConn) {
	c1 := &pipeConn{ch: make(chan packet, 256)}
	c2 := &pipeConn{ch: make(chan packet, 256)}
	c1.peer = c2
	c2.peer = c1
	return c1, c2
}

func (c *pipeConn) ReadFrom(p []byte) (int, net.Addr, error) {
	pkt, ok := <-c.ch
	if !ok {
		return 0, nil, net.ErrClosed
	}
	return copy(p, pkt.data), pkt.addr, nil
}

func (c *pipeConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return 0, net.ErrClosed
	}
	c.mu.Unlock()
	c.peer.mu.Lock()
	if c.peer.closed {
		c.peer.mu.Unlock()
		return 0, net.ErrClosed
	}
	c.peer.mu.Unlock()
	buf := make([]byte, len(p))
	copy(buf, p)
	defer func() { recover() }()
	c.peer.ch <- packet{data: buf, addr: addr}
	return len(p), nil
}

func (c *pipeConn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.closed {
		c.closed = true
		close(c.ch)
	}
	return nil
}

func (c *pipeConn) LocalAddr() net.Addr                { return pipeAddr{} }
func (c *pipeConn) SetDeadline(_ time.Time) error      { return nil }
func (c *pipeConn) SetReadDeadline(_ time.Time) error  { return nil }
func (c *pipeConn) SetWriteDeadline(_ time.Time) error { return nil }

// ─── TURN credential functions ───

// fallbackDNSServers for Android DNS resolution.
var fallbackDNSServers = []string{
	"77.88.8.8:53", // Yandex DNS — whitelisted by Russian ISPs
	"77.88.8.1:53", // Yandex DNS secondary
	"8.8.8.8:53",   // Google DNS
	"1.1.1.1:53",   // Cloudflare DNS
}

func androidDNSDialer() *net.Dialer {
	return &net.Dialer{
		Timeout:   10 * time.Second,
		KeepAlive: 30 * time.Second,
		Resolver: &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				d := net.Dialer{Timeout: 3 * time.Second}
				for _, dns := range fallbackDNSServers {
					conn, err := d.DialContext(ctx, "udp", dns)
					if err == nil {
						return conn, nil
					}
				}
				return d.DialContext(ctx, network, address)
			},
		},
	}
}

// safeGetStr navigates nested JSON maps safely (no panics).
func safeGetStr(m map[string]interface{}, keys ...string) (string, error) {
	var current interface{} = m
	for _, k := range keys {
		cm, ok := current.(map[string]interface{})
		if !ok {
			return "", fmt.Errorf("expected map at key %q, got %T", k, current)
		}
		current = cm[k]
	}
	s, ok := current.(string)
	if !ok {
		return "", fmt.Errorf("expected string, got %T: %v", current, current)
	}
	return s, nil
}

func getVkCreds(link string) (user, pass, addr string, err error) {
	dialer := androidDNSDialer()
	transport := &http.Transport{
		DialContext:         dialer.DialContext,
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 100,
		IdleConnTimeout:     90 * time.Second,
	}

	doRequest := func(data string, url string) (map[string]interface{}, error) {
		client := &http.Client{Timeout: 30 * time.Second, Transport: transport}
		req, err := http.NewRequest("POST", url, bytes.NewBuffer([]byte(data)))
		if err != nil {
			return nil, err
		}
		req.Header.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:144.0) Gecko/20100101 Firefox/144.0")
		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		httpResp, err := client.Do(req)
		if err != nil {
			return nil, err
		}
		defer httpResp.Body.Close()
		body, err := io.ReadAll(httpResp.Body)
		if err != nil {
			return nil, err
		}
		var resp map[string]interface{}
		if err := json.Unmarshal(body, &resp); err != nil {
			return nil, fmt.Errorf("JSON decode: %s (body: %s)", err, string(body))
		}
		return resp, nil
	}

	getStr := safeGetStr

	// Step 1: Get anonymous token
	resp, err := doRequest("client_secret=QbYic1K3lEV5kTGiqlq2&client_id=6287487&scopes=audio_anonymous%2Cvideo_anonymous%2Cphotos_anonymous%2Cprofile_anonymous&isApiOauthAnonymEnabled=false&version=1&app_id=6287487",
		"https://login.vk.ru/?act=get_anonym_token")
	if err != nil {
		return "", "", "", err
	}
	token1, err := getStr(resp, "data", "access_token")
	if err != nil {
		return "", "", "", fmt.Errorf("step 1 parse: %w", err)
	}

	// Step 2: Get anonymous access token payload
	resp, err = doRequest(fmt.Sprintf("access_token=%s", token1),
		"https://api.vk.ru/method/calls.getAnonymousAccessTokenPayload?v=5.274&client_id=6287487")
	if err != nil {
		return "", "", "", err
	}
	token2, err := getStr(resp, "response", "payload")
	if err != nil {
		return "", "", "", fmt.Errorf("step 2 parse: %w", err)
	}

	// Step 3: Get messages token
	resp, err = doRequest(fmt.Sprintf("client_id=6287487&token_type=messages&payload=%s&client_secret=QbYic1K3lEV5kTGiqlq2&version=1&app_id=6287487", token2),
		"https://login.vk.ru/?act=get_anonym_token")
	if err != nil {
		return "", "", "", err
	}
	token3, err := getStr(resp, "data", "access_token")
	if err != nil {
		return "", "", "", fmt.Errorf("step 3 parse: %w", err)
	}

	// Step 4: Get anonymous call token
	resp, err = doRequest(fmt.Sprintf("vk_join_link=https://vk.com/call/join/%s&name=123&access_token=%s", link, token3),
		"https://api.vk.ru/method/calls.getAnonymousToken?v=5.274")
	if err != nil {
		return "", "", "", err
	}
	token4, err := getStr(resp, "response", "token")
	if err != nil {
		return "", "", "", fmt.Errorf("step 4 parse: %w", err)
	}

	// Step 5: OK.ru anonymous login
	resp, err = doRequest(fmt.Sprintf("%s%s%s", "session_data=%7B%22version%22%3A2%2C%22device_id%22%3A%22", uuid.New(), "%22%2C%22client_version%22%3A1.1%2C%22client_type%22%3A%22SDK_JS%22%7D&method=auth.anonymLogin&format=JSON&application_key=CGMMEJLGDIHBABABA"),
		"https://calls.okcdn.ru/fb.do")
	if err != nil {
		return "", "", "", err
	}
	token5, err := getStr(resp, "session_key")
	if err != nil {
		return "", "", "", fmt.Errorf("step 5 parse: %w", err)
	}

	// Step 6: Join conversation and get TURN credentials
	resp, err = doRequest(fmt.Sprintf("joinLink=%s&isVideo=false&protocolVersion=5&anonymToken=%s&method=vchat.joinConversationByLink&format=JSON&application_key=CGMMEJLGDIHBABABA&session_key=%s", link, token4, token5),
		"https://calls.okcdn.ru/fb.do")
	if err != nil {
		return "", "", "", err
	}

	user, err = getStr(resp, "turn_server", "username")
	if err != nil {
		return "", "", "", fmt.Errorf("parse username: %w", err)
	}
	pass, err = getStr(resp, "turn_server", "credential")
	if err != nil {
		return "", "", "", fmt.Errorf("parse credential: %w", err)
	}

	turnServer, ok := resp["turn_server"].(map[string]interface{})
	if !ok {
		return "", "", "", fmt.Errorf("missing turn_server in response")
	}
	urls, ok := turnServer["urls"].([]interface{})
	if !ok || len(urls) == 0 {
		return "", "", "", fmt.Errorf("missing turn_server urls")
	}
	turnURL, ok := urls[0].(string)
	if !ok {
		return "", "", "", fmt.Errorf("invalid turn URL type")
	}
	clean := strings.Split(turnURL, "?")[0]
	addr = strings.TrimPrefix(strings.TrimPrefix(clean, "turn:"), "turns:")
	logMsg("VK creds OK: turn=%s", addr)
	return user, pass, addr, nil
}

// getYandexCreds is deprecated — Yandex Telemost blocked TURN relay to external IPs.
func getYandexCreds(link string) (string, string, string, error) {
	return "", "", "", fmt.Errorf("Yandex Telemost TURN is no longer available (blocked relay to external IPs)")
}

// ─── DTLS + TURN functions ───

type turnParams struct {
	host     string
	port     string
	link     string
	udp      bool
	getCreds func(string) (string, string, string, error)
}

type connectedUDPConn struct{ *net.UDPConn }

func (c *connectedUDPConn) WriteTo(p []byte, _ net.Addr) (int, error) { return c.Write(p) }

var tunnelDTLSFingerprint string

func dtlsFunc(ctx context.Context, pktConn net.PacketConn, peer *net.UDPAddr) (net.Conn, error) {
	cert, err := selfsign.GenerateSelfSigned()
	if err != nil {
		return nil, err
	}
	cfg := &dtls.Config{
		Certificates:          []tls.Certificate{cert},
		InsecureSkipVerify:    true,
		ExtendedMasterSecret:  dtls.RequireExtendedMasterSecret,
		CipherSuites:          []dtls.CipherSuiteID{dtls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
		ConnectionIDGenerator: dtls.OnlySendCIDGenerator(),
		VerifyConnection: func(state *dtls.State) error {
			if tunnelDTLSFingerprint == "" {
				logMsg("WARNING: DTLS fingerprint pinning disabled — vulnerable to MITM")
				return nil
			}
			certs := state.PeerCertificates
			if len(certs) == 0 {
				return fmt.Errorf("no server certificate received")
			}
			hash := sha256.Sum256(certs[0])
			got := hex.EncodeToString(hash[:])
			if got != tunnelDTLSFingerprint {
				return fmt.Errorf("DTLS fingerprint mismatch: got %s, want %s", got, tunnelDTLSFingerprint)
			}
			logMsg("DTLS certificate fingerprint verified: %s", got)
			return nil
		},
	}
	ctx1, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	dtlsConn, err := dtls.Client(pktConn, peer, cfg)
	if err != nil {
		return nil, err
	}
	if err := dtlsConn.HandshakeContext(ctx1); err != nil {
		return nil, err
	}
	return dtlsConn, nil
}

func oneDtlsConnection(ctx context.Context, peer *net.UDPAddr, listenConn net.PacketConn, connchan chan<- net.PacketConn, okchan chan<- struct{}, c chan<- error) {
	var err error
	defer func() { c <- err }()
	dtlsctx, dtlscancel := context.WithCancel(ctx)
	defer dtlscancel()

	// Reset any deadline left by a previous connection on the shared listenConn.
	// If a previous pair set deadline=now (via AfterFunc), this unblocks new readers.
	listenConn.SetDeadline(time.Time{})
	conn1, conn2 := asyncPacketPipe()
	go func() {
		for {
			select {
			case <-dtlsctx.Done():
				return
			case connchan <- conn2:
			}
		}
	}()
	logMsg("[DTLS] Connecting to peer %s...", peer)
	dtlsConn, err1 := dtlsFunc(dtlsctx, conn1, peer)
	if err1 != nil {
		err = fmt.Errorf("DTLS connect: %s", err1)
		logErr("[DTLS] Handshake FAILED: %s", err1)
		return
	}
	defer dtlsConn.Close()
	logMsg("[DTLS] Connected to %s! Handshake OK", peer)

	// Send session handshake: magic byte 0x00 + 16-byte Session UUID
	handshake := make([]byte, 1+len(clientSessionID))
	handshake[0] = 0x00
	copy(handshake[1:], clientSessionID[:])
	if _, err1 = dtlsConn.Write(handshake); err1 != nil {
		err = fmt.Errorf("failed to send session handshake: %s", err1)
		return
	}
	logMsg("[DTLS] Session ID sent: %x", clientSessionID[:4])

	if okchan != nil {
		go func() {
			for {
				select {
				case <-dtlsctx.Done():
					return
				case okchan <- struct{}{}:
				}
			}
		}()
	}

	var wg sync.WaitGroup
	wg.Add(2)
	context.AfterFunc(dtlsctx, func() {
		// Only set deadline on THIS connection's dtlsConn — NOT on the shared listenConn.
		// Setting deadline on the shared listenConn would cascade-kill all other pairs.
		// The listenConn reader goroutine will exit on its next iteration via dtlsctx.Done().
		dtlsConn.SetDeadline(time.Now())
	})
	var addr atomic.Value
	go func() {
		defer wg.Done()
		defer dtlscancel()
		buf := make([]byte, 1600)
		for {
			select {
			case <-dtlsctx.Done():
				return
			default:
			}
			n, a, e := listenConn.ReadFrom(buf)
			if e != nil {
				return
			}
			addr.Store(a)
			if _, e = dtlsConn.Write(buf[:n]); e != nil {
				return
			}
		}
	}()
	go func() {
		defer wg.Done()
		defer dtlscancel()
		buf := make([]byte, 1600)
		for {
			select {
			case <-dtlsctx.Done():
				return
			default:
			}
			n, e := dtlsConn.Read(buf)
			if e != nil {
				return
			}
			a, ok := addr.Load().(net.Addr)
			if !ok {
				return
			}
			if _, e = listenConn.WriteTo(buf[:n], a); e != nil {
				return
			}
		}
	}()
	wg.Wait()
}

func oneTurnConnection(ctx context.Context, params *turnParams, peer *net.UDPAddr, conn2 net.PacketConn, c chan<- error) {
	var err error
	defer func() { c <- err }()

	var user, pass, url string
	if serverTurnCreds.user != "" {
		// Use server-provided TURN credentials — skip VK/Yandex API calls
		user = serverTurnCreds.user
		pass = serverTurnCreds.pass
		url = serverTurnCreds.addr
		logMsg("[TURN] Using server-provided credentials: user=%s, turn_addr=%s", user, url)
	} else {
		logMsg("[TURN] Getting credentials for link=%s", params.link)
		var err1 error
		user, pass, url, err1 = params.getCreds(params.link)
		if err1 != nil {
			err = fmt.Errorf("TURN creds: %s", err1)
			logErr("[TURN] Credential fetch FAILED: %s", err1)
			return
		}
		logMsg("[TURN] Credentials OK: user=%s, turn_addr=%s", user, url)
	}
	urlhost, urlport, err1 := net.SplitHostPort(url)
	if err1 != nil {
		err = fmt.Errorf("TURN address parse: %s (url=%s)", err1, url)
		logErr("[TURN] Address parse FAILED: %s", err1)
		return
	}
	if params.host != "" {
		urlhost = params.host
	}
	if params.port != "" {
		urlport = params.port
	}
	turnAddr := net.JoinHostPort(urlhost, urlport)
	turnUDP, err1 := net.ResolveUDPAddr("udp", turnAddr)
	if err1 != nil {
		err = fmt.Errorf("TURN resolve: %s", err1)
		logErr("[TURN] DNS resolve FAILED: %s", err1)
		return
	}
	turnAddr = turnUDP.String()
	logMsg("[TURN] Resolved: %s → %s", url, turnAddr)

	var turnConn net.PacketConn
	var d net.Dialer
	ctx1, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	transport := "TCP"
	if params.udp {
		transport = "UDP"
		udpConn, err2 := net.DialUDP("udp", nil, turnUDP)
		if err2 != nil {
			err = fmt.Errorf("TURN UDP connect: %s", err2)
			logErr("[TURN] UDP dial FAILED: %s", err2)
			return
		}
		defer udpConn.Close()
		turnConn = &connectedUDPConn{udpConn}
	} else {
		logMsg("[TURN] Connecting TCP to %s...", turnAddr)
		tcpConn, err2 := d.DialContext(ctx1, "tcp", turnAddr)
		if err2 != nil {
			err = fmt.Errorf("TURN connect: %s", err2)
			logErr("[TURN] TCP dial FAILED: %s", err2)
			return
		}
		defer tcpConn.Close()
		turnConn = turn.NewSTUNConn(tcpConn)
	}
	logMsg("[TURN] Connected via %s to %s", transport, turnAddr)

	var af turn.RequestedAddressFamily
	if peer.IP.To4() != nil {
		af = turn.RequestedAddressFamilyIPv4
	} else {
		af = turn.RequestedAddressFamilyIPv6
	}
	logMsg("[TURN] Creating TURN client (user=%s, peer=%s)...", user, peer)
	tc, err1 := turn.NewClient(&turn.ClientConfig{
		STUNServerAddr: turnAddr, TURNServerAddr: turnAddr,
		Conn: turnConn, Username: user, Password: pass,
		RequestedAddressFamily: af,
		LoggerFactory:          logging.NewDefaultLoggerFactory(),
	})
	if err1 != nil {
		err = fmt.Errorf("TURN client: %s", err1)
		logErr("[TURN] Client create FAILED: %s", err1)
		return
	}
	defer tc.Close()
	logMsg("[TURN] Client created, calling Listen()...")
	tc.Listen()
	logMsg("[TURN] Listen OK, calling Allocate()...")
	relay, err1 := tc.Allocate()
	if err1 != nil {
		err = fmt.Errorf("TURN allocate: %s", err1)
		logErr("[TURN] Allocate FAILED: %s", err1)
		return
	}
	defer relay.Close()
	logMsg("[TURN] Allocate OK! Relay address: %s → sending to peer %s", relay.LocalAddr(), peer)

	var wg sync.WaitGroup
	wg.Add(2)
	tctx, tcancel := context.WithCancel(ctx)
	context.AfterFunc(tctx, func() {
		relay.SetDeadline(time.Now())
		conn2.SetDeadline(time.Now())
	})
	var relayAddr atomic.Value
	go func() {
		defer wg.Done()
		defer tcancel()
		buf := make([]byte, 1600)
		for {
			select {
			case <-tctx.Done():
				return
			default:
			}
			n, a, e := conn2.ReadFrom(buf)
			if e != nil {
				return
			}
			relayAddr.Store(a)
			if _, e = relay.WriteTo(buf[:n], peer); e != nil {
				return
			}
		}
	}()
	go func() {
		defer wg.Done()
		defer tcancel()
		buf := make([]byte, 1600)
		for {
			select {
			case <-tctx.Done():
				return
			default:
			}
			n, _, e := relay.ReadFrom(buf)
			if e != nil {
				return
			}
			a, ok := relayAddr.Load().(net.Addr)
			if !ok {
				return
			}
			if _, e = conn2.WriteTo(buf[:n], a); e != nil {
				return
			}
		}
	}()
	wg.Wait()
}

func oneDtlsConnectionLoop(ctx context.Context, peer *net.UDPAddr, lch <-chan net.PacketConn, cch chan<- net.PacketConn, okchan chan<- struct{}) {
	for {
		select {
		case <-ctx.Done():
			return
		case lc := <-lch:
			c := make(chan error)
			go oneDtlsConnection(ctx, peer, lc, cch, okchan, c)
			if err := <-c; err != nil {
				logMsg("%s", err)
			}
		}
	}
}

func oneTurnConnectionLoop(ctx context.Context, params *turnParams, peer *net.UDPAddr, cch <-chan net.PacketConn, t <-chan time.Time) {
	backoff := time.Second
	for {
		select {
		case <-ctx.Done():
			return
		case c2 := <-cch:
			// Rate-limit: wait for ticker before creating TURN connection
			select {
			case <-t:
			case <-ctx.Done():
				return
			}
			c := make(chan error)
			go oneTurnConnection(ctx, params, peer, c2, c)
			if err := <-c; err != nil {
				logMsg("TURN error (retry in %v): %s", backoff, err)
				// Fetch fresh credentials on failure — old allocation may be dead
				if serverInfo.url != "" && serverInfo.name != "" {
					if err2 := fetchFreshCreds(); err2 != nil {
						logErr("[TURN] Credential refresh failed: %s", err2)
					}
				}
				// Exponential backoff on failure, max 30s
				select {
				case <-time.After(backoff):
				case <-ctx.Done():
					return
				}
				if backoff < 30*time.Second {
					backoff *= 2
				}
			} else {
				backoff = time.Second // reset on success
			}
		}
	}
}
