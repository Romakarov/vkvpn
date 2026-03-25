// Package tunnel provides a WireGuard VPN tunneled through TURN servers for Android.
//
// Architecture:
//   Android VpnService creates TUN fd → wireguard-go encrypts packets →
//   DTLS+TURN tunnel forwards encrypted WG packets through VK/Yandex TURN → VPS
package tunnel

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Romakarov/vkvpn/pkg/turnauth"
	"github.com/pion/dtls/v3"
	"github.com/pion/dtls/v3/pkg/crypto/selfsign"
	"github.com/pion/logging"
	"github.com/pion/turn/v5"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
)

// State holds the running tunnel state
var (
	tunnelCtx    context.Context
	tunnelCancel context.CancelFunc
	tunnelMu     sync.Mutex
	running      bool
	logCallback  func(string)
	wgDevice     *device.Device
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
func Start(tunFd int, peerAddr, vkLink, yandexLink string, connections int, wgPrivKey, serverPubKey string) error {
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
	if wgPrivKey == "" || serverPubKey == "" {
		return fmt.Errorf("WireGuard keys required")
	}

	peer, err := net.ResolveUDPAddr("udp", peerAddr)
	if err != nil {
		return fmt.Errorf("invalid peer: %s", err)
	}

	// Decode WG keys from base64 to hex (wireguard-go IPC format)
	privBytes, err := base64.StdEncoding.DecodeString(wgPrivKey)
	if err != nil || len(privBytes) != 32 {
		return fmt.Errorf("invalid WG private key")
	}
	pubBytes, err := base64.StdEncoding.DecodeString(serverPubKey)
	if err != nil || len(pubBytes) != 32 {
		return fmt.Errorf("invalid WG public key")
	}

	var link string
	var getCreds func(string) (string, string, string, error)
	if vkLink != "" {
		link = vkLink
		getCreds = getVkCredsShared
		if connections <= 0 {
			connections = 16
		}
	} else {
		link = yandexLink
		getCreds = getYandexCredsShared
		if connections <= 0 {
			connections = 1
		}
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

	tunnelMu.Lock()
	running = true
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
		dev.Close()
		tunnelMu.Lock()
		running = false
		wgDevice = nil
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
	if wgDevice != nil {
		wgDevice.Close()
		wgDevice = nil
	}
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

// ─── TURN credential wrappers (using pkg/turnauth) ───

func getVkCredsShared(link string) (string, string, string, error) {
	creds, err := turnauth.GetVKCredentials(link)
	if err != nil {
		return "", "", "", err
	}
	logMsg("VK creds OK: turn=%s", creds.Address)
	return creds.Username, creds.Password, creds.Address, nil
}

func getYandexCredsShared(link string) (string, string, string, error) {
	creds, err := turnauth.GetYandexCredentials(link)
	if err != nil {
		return "", "", "", err
	}
	logMsg("Yandex creds OK: turn=%s", creds.Address)
	return creds.Username, creds.Password, creds.Address, nil
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
	urlhost, urlport, err1 := net.SplitHostPort(url)
	if err1 != nil {
		err = fmt.Errorf("TURN address parse: %s (url=%s)", err1, url)
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
		return
	}
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

func backoffSleep(ctx context.Context, attempt int) {
	delay := time.Duration(1<<uint(attempt)) * time.Second
	if delay > 30*time.Second {
		delay = 30 * time.Second
	}
	logMsg("Reconnecting in %v (attempt %d)...", delay, attempt+1)
	select {
	case <-time.After(delay):
	case <-ctx.Done():
	}
}

func oneDtlsConnectionLoop(ctx context.Context, peer *net.UDPAddr, lch <-chan net.PacketConn, cch chan<- net.PacketConn, okchan chan<- struct{}) {
	attempt := 0
	for {
		select {
		case <-ctx.Done():
			return
		case lc := <-lch:
			c := make(chan error)
			go oneDtlsConnection(ctx, peer, lc, cch, okchan, c)
			if err := <-c; err != nil {
				logMsg("DTLS error: %s", err)
				backoffSleep(ctx, attempt)
				attempt++
			} else {
				attempt = 0
			}
		}
	}
}

func oneTurnConnectionLoop(ctx context.Context, params *turnParams, peer *net.UDPAddr, cch <-chan net.PacketConn, t <-chan time.Time) {
	attempt := 0
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
				logMsg("TURN error: %s", err)
				backoffSleep(ctx, attempt)
				attempt++
			} else {
				attempt = 0
			}
		}
	}
}
