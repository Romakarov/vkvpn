// Package tunnel provides a combined WireGuard+TURN tunnel for Android.
// It is designed to be called from Android VpnService via gomobile.
//
// Architecture:
//   Android VpnService creates TUN fd → this library reads/writes packets →
//   WireGuard encrypts → TURN client sends through VK/Yandex → VPS
package tunnel

import (
	"bytes"
	"context"
	"crypto/tls"
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
	"github.com/gorilla/websocket"
	"github.com/pion/dtls/v3"
	"github.com/pion/dtls/v3/pkg/crypto/selfsign"
	"github.com/pion/logging"
	"github.com/pion/turn/v5"
)

// State holds the running tunnel state
var (
	tunnelCtx    context.Context
	tunnelCancel context.CancelFunc
	tunnelMu     sync.Mutex
	running      bool
	logCallback  func(string)
)

// SetLogCallback sets a callback for log messages (called from Android)
func SetLogCallback(cb func(string)) {
	logCallback = cb
}

func logMsg(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	log.Print(msg)
	if logCallback != nil {
		logCallback(msg)
	}
}

// Start starts the tunnel.
// tunFd: file descriptor from Android VpnService
// peerAddr: VPS address "host:port" (e.g. "144.124.247.27:56000")
// vkLink: VK call invite link (or empty)
// yandexLink: Yandex Telemost link (or empty)
// connections: number of parallel TURN connections (0 = auto)
// localWgPort: local WireGuard UDP port to listen on (e.g. 9000)
func Start(peerAddr, vkLink, yandexLink string, connections int, localWgPort int) error {
	tunnelMu.Lock()
	if running {
		tunnelMu.Unlock()
		return fmt.Errorf("tunnel already running")
	}
	tunnelMu.Unlock()

	if peerAddr == "" {
		return fmt.Errorf("peer address required")
	}
	if vkLink == "" && yandexLink == "" {
		return fmt.Errorf("VK or Yandex link required")
	}

	peer, err := net.ResolveUDPAddr("udp", peerAddr)
	if err != nil {
		return fmt.Errorf("invalid peer: %s", err)
	}

	var link string
	var getCreds func(string) (string, string, string, error)
	if vkLink != "" {
		parts := strings.Split(vkLink, "join/")
		link = parts[len(parts)-1]
		getCreds = getVkCreds
		if connections <= 0 {
			connections = 16
		}
	} else {
		parts := strings.Split(yandexLink, "j/")
		link = parts[len(parts)-1]
		getCreds = getYandexCreds
		if connections <= 0 {
			connections = 1
		}
	}
	if idx := strings.IndexAny(link, "/?#"); idx != -1 {
		link = link[:idx]
	}

	ctx, cancel := context.WithCancel(context.Background())

	listenAddr := fmt.Sprintf("127.0.0.1:%d", localWgPort)
	listenConn, err := net.ListenPacket("udp", listenAddr)
	if err != nil {
		cancel()
		return fmt.Errorf("listen %s: %s", listenAddr, err)
	}
	context.AfterFunc(ctx, func() { listenConn.Close() })

	tunnelMu.Lock()
	running = true
	tunnelCtx = ctx
	tunnelCancel = cancel
	tunnelMu.Unlock()

	logMsg("Tunnel starting: peer=%s connections=%d listen=%s", peerAddr, connections, listenAddr)

	params := &turnParams{
		link:     link,
		getCreds: getCreds,
	}

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

	go func() {
		var wg sync.WaitGroup
		t := time.Tick(100 * time.Millisecond)

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
		tunnelMu.Lock()
		running = false
		tunnelMu.Unlock()
		logMsg("Tunnel stopped")
	}()

	return nil
}

// Stop stops the tunnel
func Stop() {
	tunnelMu.Lock()
	defer tunnelMu.Unlock()
	if running && tunnelCancel != nil {
		tunnelCancel()
	}
}

// IsRunning returns true if tunnel is active
func IsRunning() bool {
	tunnelMu.Lock()
	defer tunnelMu.Unlock()
	return running
}

// GetLocalEndpoint returns the local WireGuard endpoint
func GetLocalEndpoint(port int) string {
	return fmt.Sprintf("127.0.0.1:%d", port)
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
	select {
	case c.peer.ch <- packet{data: buf, addr: addr}:
	default:
	}
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

func getVkCreds(link string) (string, string, string, error) {
	doRequest := func(data string, url string) (resp map[string]interface{}, err error) {
		client := &http.Client{
			Timeout:   20 * time.Second,
			Transport: &http.Transport{MaxIdleConns: 100, MaxIdleConnsPerHost: 100, IdleConnTimeout: 90 * time.Second},
		}
		defer client.CloseIdleConnections()
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
		return resp, json.Unmarshal(body, &resp)
	}

	var resp map[string]interface{}
	defer func() {
		if r := recover(); r != nil {
			logMsg("get TURN creds error: %v", resp)
		}
	}()

	resp, err := doRequest("client_secret=QbYic1K3lEV5kTGiqlq2&client_id=6287487&scopes=audio_anonymous%2Cvideo_anonymous%2Cphotos_anonymous%2Cprofile_anonymous&isApiOauthAnonymEnabled=false&version=1&app_id=6287487",
		"https://login.vk.ru/?act=get_anonym_token")
	if err != nil {
		return "", "", "", err
	}
	token1 := resp["data"].(map[string]interface{})["access_token"].(string)

	resp, err = doRequest(fmt.Sprintf("access_token=%s", token1),
		"https://api.vk.ru/method/calls.getAnonymousAccessTokenPayload?v=5.264&client_id=6287487")
	if err != nil {
		return "", "", "", err
	}
	token2 := resp["response"].(map[string]interface{})["payload"].(string)

	resp, err = doRequest(fmt.Sprintf("client_id=6287487&token_type=messages&payload=%s&client_secret=QbYic1K3lEV5kTGiqlq2&version=1&app_id=6287487", token2),
		"https://login.vk.ru/?act=get_anonym_token")
	if err != nil {
		return "", "", "", err
	}
	token3 := resp["data"].(map[string]interface{})["access_token"].(string)

	resp, err = doRequest(fmt.Sprintf("vk_join_link=https://vk.com/call/join/%s&name=123&access_token=%s", link, token3),
		"https://api.vk.ru/method/calls.getAnonymousToken?v=5.264")
	if err != nil {
		return "", "", "", err
	}
	token4 := resp["response"].(map[string]interface{})["token"].(string)

	resp, err = doRequest(fmt.Sprintf("%s%s%s", "session_data=%%7B%%22version%%22%%3A2%%2C%%22device_id%%22%%3A%%22", uuid.New(), "%%22%%2C%%22client_version%%22%%3A1.1%%2C%%22client_type%%22%%3A%%22SDK_JS%%22%%7D&method=auth.anonymLogin&format=JSON&application_key=CGMMEJLGDIHBABABA"),
		"https://calls.okcdn.ru/fb.do")
	if err != nil {
		return "", "", "", err
	}
	token5 := resp["session_key"].(string)

	resp, err = doRequest(fmt.Sprintf("joinLink=%s&isVideo=false&protocolVersion=5&anonymToken=%s&method=vchat.joinConversationByLink&format=JSON&application_key=CGMMEJLGDIHBABABA&session_key=%s", link, token4, token5),
		"https://calls.okcdn.ru/fb.do")
	if err != nil {
		return "", "", "", err
	}

	user := resp["turn_server"].(map[string]interface{})["username"].(string)
	pass := resp["turn_server"].(map[string]interface{})["credential"].(string)
	turnURL := resp["turn_server"].(map[string]interface{})["urls"].([]interface{})[0].(string)
	clean := strings.Split(turnURL, "?")[0]
	address := strings.TrimPrefix(strings.TrimPrefix(clean, "turn:"), "turns:")
	return user, pass, address, nil
}

func getYandexCreds(link string) (string, string, string, error) {
	const telemostConfHost = "cloud-api.yandex.ru"
	telemostConfPath := fmt.Sprintf("/telemost_front/v2/telemost/conferences/https%%3A%%2F%%2Ftelemost.yandex.ru%%2Fj%%2F%s/connection?next_gen_media_platform_allowed=false", link)
	const userAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:144.0) Gecko/20100101 Firefox/144.0"

	type ConfResp struct {
		RoomID string `json:"room_id"`
		PeerID string `json:"peer_id"`
		CC     struct {
			MSURL string `json:"media_server_url"`
		} `json:"client_configuration"`
		Credentials string `json:"credentials"`
	}

	client := &http.Client{Timeout: 20 * time.Second}
	defer client.CloseIdleConnections()
	req, err := http.NewRequest("GET", "https://"+telemostConfHost+telemostConfPath, nil)
	if err != nil {
		return "", "", "", err
	}
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Referer", "https://telemost.yandex.ru/")
	req.Header.Set("Origin", "https://telemost.yandex.ru")
	req.Header.Set("Client-Instance-Id", uuid.New().String())

	resp, err := client.Do(req)
	if err != nil {
		return "", "", "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return "", "", "", fmt.Errorf("status=%d body=%s", resp.StatusCode, body)
	}

	var cr ConfResp
	json.NewDecoder(resp.Body).Decode(&cr)

	h := http.Header{}
	h.Set("Origin", "https://telemost.yandex.ru")
	h.Set("User-Agent", userAgent)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	conn, _, err := (&websocket.Dialer{}).DialContext(ctx, cr.CC.MSURL, h)
	if err != nil {
		return "", "", "", err
	}
	defer conn.Close()

	hello := map[string]interface{}{
		"uid": uuid.New().String(),
		"hello": map[string]interface{}{
			"participantMeta":       map[string]interface{}{"name": "Guest", "role": "SPEAKER", "sendAudio": false, "sendVideo": false},
			"participantAttributes": map[string]interface{}{"name": "Guest", "role": "SPEAKER"},
			"sendAudio": false, "sendVideo": false, "sendSharing": false,
			"participantId": cr.PeerID, "roomId": cr.RoomID,
			"serviceName": "telemost", "credentials": cr.Credentials,
			"sdkInfo":             map[string]interface{}{"implementation": "browser", "version": "5.15.0", "userAgent": userAgent, "hwConcurrency": 4},
			"sdkInitializationId": uuid.New().String(),
			"capabilitiesOffer": map[string]interface{}{
				"offerAnswerMode": []string{"SEPARATE"}, "initialSubscriberOffer": []string{"ON_HELLO"},
				"slotsMode": []string{"FROM_CONTROLLER"}, "simulcastMode": []string{"DISABLED"},
			},
		},
	}
	conn.WriteJSON(hello)
	conn.SetReadDeadline(time.Now().Add(15 * time.Second))

	type IceServer struct {
		Urls       []string `json:"urls"`
		Username   string   `json:"username"`
		Credential string   `json:"credential"`
	}
	type SH struct {
		ServerHello struct {
			RtcConfig struct {
				IceServers []IceServer `json:"iceServers"`
			} `json:"rtcConfiguration"`
		} `json:"serverHello"`
	}

	for {
		_, msg, err := conn.ReadMessage()
		if err != nil {
			return "", "", "", err
		}
		var sh SH
		json.Unmarshal(msg, &sh)
		for _, s := range sh.ServerHello.RtcConfig.IceServers {
			for _, u := range s.Urls {
				if strings.HasPrefix(u, "turn:") && !strings.Contains(u, "transport=tcp") {
					clean := strings.Split(u, "?")[0]
					addr := strings.TrimPrefix(clean, "turn:")
					return s.Username, s.Credential, addr, nil
				}
			}
		}
	}
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

func dtlsFunc(ctx context.Context, conn net.PacketConn, peer *net.UDPAddr) (net.Conn, error) {
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
	}
	ctx1, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	dtlsConn, err := dtls.Client(conn, peer, cfg)
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
	dtlsConn, err1 := dtlsFunc(dtlsctx, conn1, peer)
	if err1 != nil {
		err = fmt.Errorf("DTLS connect: %s", err1)
		return
	}
	defer dtlsConn.Close()
	logMsg("DTLS connected")
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
		listenConn.SetDeadline(time.Now())
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
	user, pass, url, err1 := params.getCreds(params.link)
	if err1 != nil {
		err = fmt.Errorf("TURN creds: %s", err1)
		return
	}
	urlhost, urlport, _ := net.SplitHostPort(url)
	if params.host != "" {
		urlhost = params.host
	}
	if params.port != "" {
		urlport = params.port
	}
	turnAddr := net.JoinHostPort(urlhost, urlport)
	turnUDP, _ := net.ResolveUDPAddr("udp", turnAddr)
	turnAddr = turnUDP.String()
	logMsg("TURN server: %s", turnUDP.IP)

	var d net.Dialer
	ctx1, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	tcpConn, err1 := d.DialContext(ctx1, "tcp", turnAddr)
	if err1 != nil {
		err = fmt.Errorf("TURN connect: %s", err1)
		return
	}
	defer tcpConn.Close()
	turnConn := turn.NewSTUNConn(tcpConn)

	var af turn.RequestedAddressFamily
	if peer.IP.To4() != nil {
		af = turn.RequestedAddressFamilyIPv4
	} else {
		af = turn.RequestedAddressFamilyIPv6
	}
	tc, err1 := turn.NewClient(&turn.ClientConfig{
		STUNServerAddr: turnAddr, TURNServerAddr: turnAddr,
		Conn: turnConn, Username: user, Password: pass,
		RequestedAddressFamily: af,
		LoggerFactory:          logging.NewDefaultLoggerFactory(),
	})
	if err1 != nil {
		err = fmt.Errorf("TURN client: %s", err1)
		return
	}
	defer tc.Close()
	tc.Listen()
	relay, err1 := tc.Allocate()
	if err1 != nil {
		err = fmt.Errorf("TURN allocate: %s", err1)
		return
	}
	defer relay.Close()
	logMsg("Relay: %s", relay.LocalAddr())

	var wg sync.WaitGroup
	wg.Add(2)
	tctx, tcancel := context.WithCancel(ctx)
	context.AfterFunc(tctx, func() {
		relay.SetDeadline(time.Now())
		conn2.SetDeadline(time.Now())
	})
	var addr atomic.Value
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
			addr.Store(a)
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
			a, ok := addr.Load().(net.Addr)
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
	for {
		select {
		case <-ctx.Done():
			return
		case c2 := <-cch:
			select {
			case <-t:
				c := make(chan error)
				go oneTurnConnection(ctx, params, peer, c2, c)
				if err := <-c; err != nil {
					logMsg("%s", err)
				}
			default:
			}
		}
	}
}

// Ensure we don't import os for Android compatibility
var _ = os.Stderr
