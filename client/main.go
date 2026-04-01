// SPDX-License-Identifier: GPL-3.0
// vkvpn client — tunnels WireGuard through VK/Yandex TURN servers

package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/Romakarov/vkvpn/pkg/packetpipe"
	"github.com/Romakarov/vkvpn/pkg/telemost"
	"github.com/Romakarov/vkvpn/pkg/turnauth"
	"github.com/Romakarov/vkvpn/pkg/vkcall"
	"github.com/Romakarov/vkvpn/pkg/vp8tunnel"
	"github.com/pion/dtls/v3"
	"github.com/pion/dtls/v3/pkg/crypto/selfsign"
	"github.com/pion/logging"
	"github.com/pion/turn/v5"
)

// sessionID is a 16-byte UUID generated once per client start.
// All DTLS connections from this client send it as the first packet
// so the server can group them into one WireGuard session.
var sessionID [16]byte

func init() {
	rand.Read(sessionID[:])
}

// ─── Credential functions ───

type getCredsFunc func(string) (string, string, string, error)

func getVkCreds(link string) (string, string, string, error) {
	creds, err := turnauth.GetVKCredentials(link)
	if err != nil {
		return "", "", "", err
	}
	return creds.Username, creds.Password, creds.Address, nil
}

func getYandexCreds(link string) (string, string, string, error) {
	creds, err := turnauth.GetYandexCredentials(link)
	if err != nil {
		return "", "", "", err
	}
	return creds.Username, creds.Password, creds.Address, nil
}


// ─── DTLS ───

var expectedFingerprint string

func dtlsFunc(ctx context.Context, conn net.PacketConn, peer *net.UDPAddr) (net.Conn, error) {
	certificate, err := selfsign.GenerateSelfSigned()
	if err != nil {
		return nil, err
	}
	config := &dtls.Config{
		Certificates:          []tls.Certificate{certificate},
		InsecureSkipVerify:    true,
		ExtendedMasterSecret:  dtls.RequireExtendedMasterSecret,
		CipherSuites:          []dtls.CipherSuiteID{dtls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
		ConnectionIDGenerator: dtls.OnlySendCIDGenerator(),
		VerifyConnection: func(state *dtls.State) error {
			if expectedFingerprint == "" {
				log.Println("WARNING: DTLS fingerprint pinning disabled — vulnerable to MITM")
				return nil
			}
			certs := state.PeerCertificates
			if len(certs) == 0 {
				return fmt.Errorf("no server certificate received")
			}
			hash := sha256.Sum256(certs[0])
			got := hex.EncodeToString(hash[:])
			if got != expectedFingerprint {
				return fmt.Errorf("DTLS certificate fingerprint mismatch: got %s, want %s", got, expectedFingerprint)
			}
			log.Printf("DTLS certificate fingerprint verified: %s", got)
			return nil
		},
	}
	ctx1, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	dtlsConn, err := dtls.Client(conn, peer, config)
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
	conn1, conn2 := packetpipe.AsyncPacketPipe()
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
		err = fmt.Errorf("failed to connect DTLS: %s", err1)
		return
	}
	defer func() {
		if closeErr := dtlsConn.Close(); closeErr != nil {
			err = fmt.Errorf("failed to close DTLS connection: %s", closeErr)
			return
		}
		log.Printf("Closed DTLS connection\n")
	}()
	log.Printf("Established DTLS connection!\n")

	// Send session handshake: magic byte 0x00 + 16-byte Session UUID.
	// This lets the server distinguish new clients from legacy ones
	// (WireGuard message types start with bytes 1-4, never 0x00).
	handshake := make([]byte, 1+len(sessionID))
	handshake[0] = 0x00 // magic byte
	copy(handshake[1:], sessionID[:])
	if _, err1 = dtlsConn.Write(handshake); err1 != nil {
		err = fmt.Errorf("failed to send session handshake: %s", err1)
		return
	}
	log.Printf("Session ID sent: %x\n", sessionID[:4])

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

	wg := sync.WaitGroup{}
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
			n, addr1, err1 := listenConn.ReadFrom(buf)
			if err1 != nil {
				log.Printf("Failed: %s", err1)
				return
			}
			addr.Store(addr1)
			_, err1 = dtlsConn.Write(buf[:n])
			if err1 != nil {
				log.Printf("Failed: %s", err1)
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
			n, err1 := dtlsConn.Read(buf)
			if err1 != nil {
				log.Printf("Failed: %s", err1)
				return
			}
			addr1, ok := addr.Load().(net.Addr)
			if !ok {
				log.Printf("Failed: no listener ip")
				return
			}
			_, err1 = listenConn.WriteTo(buf[:n], addr1)
			if err1 != nil {
				log.Printf("Failed: %s", err1)
				return
			}
		}
	}()
	wg.Wait()
	listenConn.SetDeadline(time.Time{})
	dtlsConn.SetDeadline(time.Time{})
}

// ─── TURN ───

type connectedUDPConn struct {
	*net.UDPConn
}

func (c *connectedUDPConn) WriteTo(p []byte, _ net.Addr) (int, error) {
	return c.Write(p)
}

type turnParams struct {
	host     string
	port     string
	link     string
	udp      bool
	getCreds getCredsFunc
}

func oneTurnConnection(ctx context.Context, params *turnParams, peer *net.UDPAddr, conn2 net.PacketConn, c chan<- error) {
	var err error
	defer func() { c <- err }()
	user, pass, url, err1 := params.getCreds(params.link)
	if err1 != nil {
		err = fmt.Errorf("failed to get TURN credentials: %s", err1)
		return
	}
	urlhost, urlport, err1 := net.SplitHostPort(url)
	if err1 != nil {
		err = fmt.Errorf("failed to parse TURN server address: %s", err1)
		return
	}
	if params.host != "" {
		urlhost = params.host
	}
	if params.port != "" {
		urlport = params.port
	}
	turnServerAddr := net.JoinHostPort(urlhost, urlport)
	turnServerUdpAddr, err1 := net.ResolveUDPAddr("udp", turnServerAddr)
	if err1 != nil {
		err = fmt.Errorf("failed to resolve TURN server address: %s", err1)
		return
	}
	turnServerAddr = turnServerUdpAddr.String()
	fmt.Println(turnServerUdpAddr.IP)

	var cfg *turn.ClientConfig
	var turnConn net.PacketConn
	var d net.Dialer
	ctx1, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if params.udp {
		conn, err2 := net.DialUDP("udp", nil, turnServerUdpAddr)
		if err2 != nil {
			err = fmt.Errorf("failed to connect to TURN server: %s", err2)
			return
		}
		defer func() {
			if err1 = conn.Close(); err1 != nil {
				err = fmt.Errorf("failed to close TURN server connection: %s", err1)
			}
		}()
		turnConn = &connectedUDPConn{conn}
	} else {
		conn, err2 := d.DialContext(ctx1, "tcp", turnServerAddr)
		if err2 != nil {
			err = fmt.Errorf("failed to connect to TURN server: %s", err2)
			return
		}
		defer func() {
			if err1 = conn.Close(); err1 != nil {
				err = fmt.Errorf("failed to close TURN server connection: %s", err1)
			}
		}()
		turnConn = turn.NewSTUNConn(conn)
	}
	var addrFamily turn.RequestedAddressFamily
	if peer.IP.To4() != nil {
		addrFamily = turn.RequestedAddressFamilyIPv4
	} else {
		addrFamily = turn.RequestedAddressFamilyIPv6
	}
	cfg = &turn.ClientConfig{
		STUNServerAddr:         turnServerAddr,
		TURNServerAddr:         turnServerAddr,
		Conn:                   turnConn,
		Username:               user,
		Password:               pass,
		RequestedAddressFamily: addrFamily,
		LoggerFactory:          logging.NewDefaultLoggerFactory(),
	}

	client, err1 := turn.NewClient(cfg)
	if err1 != nil {
		err = fmt.Errorf("failed to create TURN client: %s", err1)
		return
	}
	defer client.Close()

	err1 = client.Listen()
	if err1 != nil {
		err = fmt.Errorf("failed to listen: %s", err1)
		return
	}

	relayConn, err1 := client.Allocate()
	if err1 != nil {
		err = fmt.Errorf("failed to allocate: %s", err1)
		return
	}
	defer func() {
		if err1 := relayConn.Close(); err1 != nil {
			err = fmt.Errorf("failed to close TURN allocated connection: %s", err1)
		}
	}()

	log.Printf("relayed-address=%s", relayConn.LocalAddr().String())

	wg := sync.WaitGroup{}
	wg.Add(2)
	turnctx, turncancel := context.WithCancel(ctx)
	context.AfterFunc(turnctx, func() {
		relayConn.SetDeadline(time.Now())
		conn2.SetDeadline(time.Now())
	})
	var addr atomic.Value
	go func() {
		defer wg.Done()
		defer turncancel()
		buf := make([]byte, 1600)
		for {
			select {
			case <-turnctx.Done():
				return
			default:
			}
			n, addr1, err1 := conn2.ReadFrom(buf)
			if err1 != nil {
				log.Printf("Failed: %s", err1)
				return
			}
			addr.Store(addr1)
			_, err1 = relayConn.WriteTo(buf[:n], peer)
			if err1 != nil {
				log.Printf("Failed: %s", err1)
				return
			}
		}
	}()
	go func() {
		defer wg.Done()
		defer turncancel()
		buf := make([]byte, 1600)
		for {
			select {
			case <-turnctx.Done():
				return
			default:
			}
			n, _, err1 := relayConn.ReadFrom(buf)
			if err1 != nil {
				log.Printf("Failed: %s", err1)
				return
			}
			addr1, ok := addr.Load().(net.Addr)
			if !ok {
				log.Printf("Failed: no listener ip")
				return
			}
			_, err1 = conn2.WriteTo(buf[:n], addr1)
			if err1 != nil {
				log.Printf("Failed: %s", err1)
				return
			}
		}
	}()
	wg.Wait()
	relayConn.SetDeadline(time.Time{})
	conn2.SetDeadline(time.Time{})
}

func oneDtlsConnectionLoop(ctx context.Context, peer *net.UDPAddr, listenConnChan <-chan net.PacketConn, connchan chan<- net.PacketConn, okchan chan<- struct{}) {
	for {
		select {
		case <-ctx.Done():
			return
		case listenConn := <-listenConnChan:
			c := make(chan error)
			go oneDtlsConnection(ctx, peer, listenConn, connchan, okchan, c)
			if err := <-c; err != nil {
				log.Printf("%s", err)
			}
		}
	}
}

func oneTurnConnectionLoop(ctx context.Context, params *turnParams, peer *net.UDPAddr, connchan <-chan net.PacketConn, t <-chan time.Time) {
	for {
		select {
		case <-ctx.Done():
			return
		case conn2 := <-connchan:
			// Rate-limit: wait for ticker before creating TURN connection
			select {
			case <-t:
			case <-ctx.Done():
				return
			}
			c := make(chan error)
			go oneTurnConnection(ctx, params, peer, conn2, c)
			if err := <-c; err != nil {
				log.Printf("%s", err)
			}
		}
	}
}

// ─── Main ───

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		<-signalChan
		log.Printf("Terminating...\n")
		cancel()
		select {
		case <-signalChan:
		case <-time.After(5 * time.Second):
		}
		log.Fatalf("Exit...\n")
	}()

	host := flag.String("turn", "", "override TURN server ip")
	port := flag.String("port", "", "override TURN port")
	listen := flag.String("listen", "127.0.0.1:9000", "listen on ip:port")
	vklink := flag.String("vk-link", "", "VK calls invite link \"https://vk.com/call/join/...\"")
	yalink := flag.String("yandex-link", "", "Yandex telemost invite link \"https://telemost.yandex.ru/j/...\"")
	vp8mode := flag.Bool("vp8", false, "use VP8 transport (data inside video stream) instead of TURN")
	telemostLink := flag.String("telemost-link", "", "Telemost conference link for VP8 transport")
	peerAddr := flag.String("peer", "", "peer server address (host:port)")
	dtlsFingerprint := flag.String("dtls-fingerprint", "", "expected DTLS server certificate SHA-256 fingerprint (hex)")
	n := flag.Int("n", 0, "connections to TURN (default 16 for VK, 1 for Yandex)")
	udp := flag.Bool("udp", false, "connect to TURN with UDP")
	direct := flag.Bool("no-dtls", false, "connect without obfuscation. DO NOT USE")
	turnUser := flag.String("turn-user", "", "TURN username (server-provided, skips VK/Yandex auth)")
	turnPass := flag.String("turn-pass", "", "TURN password (server-provided)")
	turnAddr := flag.String("turn-addr", "", "TURN server address host:port (server-provided)")
	flag.Parse()
	if *dtlsFingerprint != "" {
		expectedFingerprint = strings.ToLower(*dtlsFingerprint)
	}
	// VP8 mode — tunnel data through video stream (Telemost or VK Call)
	if *vp8mode {
		if *telemostLink != "" {
			log.Printf("VP8 transport mode: data inside Telemost video stream")
			runVP8TelemostClient(ctx, *listen, *telemostLink)
			return
		}
		if *vklink != "" {
			log.Printf("VP8 transport mode: data inside VK Call video stream")
			runVP8Client(ctx, *listen, *vklink)
			return
		}
		log.Fatalf("VP8 mode requires --telemost-link or -vk-link")
	}

	if *peerAddr == "" {
		log.Panicf("Need peer address!")
	}
	peer, err := net.ResolveUDPAddr("udp", *peerAddr)
	if err != nil {
		panic(err)
	}
	var link string
	var getCreds getCredsFunc

	if *turnUser != "" && *turnPass != "" && *turnAddr != "" {
		// Server-provided TURN credentials — skip VK/Yandex auth
		log.Printf("Using server-provided TURN credentials: user=%s addr=%s", *turnUser, *turnAddr)
		fixedUser, fixedPass, fixedAddr := *turnUser, *turnPass, *turnAddr
		link = "server-provided"
		getCreds = func(string) (string, string, string, error) {
			return fixedUser, fixedPass, fixedAddr, nil
		}
		if *n <= 0 {
			*n = 16
		}
	} else {
		if *vklink == "" && *yalink == "" {
			log.Panicf("Need -vk-link (or --turn-user/--turn-pass/--turn-addr, or -vp8 -vk-link)!")
		}
		if *vklink != "" {
			parts := strings.Split(*vklink, "join/")
			link = parts[len(parts)-1]
			getCreds = getVkCreds
			if *n <= 0 {
				*n = 16
			}
		} else {
			log.Fatalf("Yandex Telemost TURN is no longer available. Use -vk-link or --telemost-link instead.")
		}
		if idx := strings.IndexAny(link, "/?#"); idx != -1 {
			link = link[:idx]
		}
	}

	// Store VK link for potential VP8 fallback
	vp8Fallback := *vklink
	params := &turnParams{
		*host,
		*port,
		link,
		*udp,
		getCreds,
	}

	listenConnChan := make(chan net.PacketConn)
	listenConn, err := net.ListenPacket("udp", *listen)
	if err != nil {
		log.Panicf("Failed to listen: %s", err)
	}
	context.AfterFunc(ctx, func() {
		if closeErr := listenConn.Close(); closeErr != nil {
			log.Panicf("Failed to close local connection: %s", closeErr)
		}
	})
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case listenConnChan <- listenConn:
			}
		}
	}()

	wg1 := sync.WaitGroup{}
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	t := ticker.C
	if *direct {
		for i := 0; i < *n; i++ {
			wg1.Add(1)
			go func() {
				defer wg1.Done()
				oneTurnConnectionLoop(ctx, params, peer, listenConnChan, t)
			}()
		}
	} else {
		okchan := make(chan struct{})
		connchan := make(chan net.PacketConn)

		wg1.Add(2)
		go func() {
			defer wg1.Done()
			oneDtlsConnectionLoop(ctx, peer, listenConnChan, connchan, okchan)
		}()
		go func() {
			defer wg1.Done()
			oneTurnConnectionLoop(ctx, params, peer, connchan, t)
		}()

		select {
		case <-okchan:
		case <-ctx.Done():
		}
		for i := 0; i < *n-1; i++ {
			cc := make(chan net.PacketConn)
			wg1.Add(2)
			go func() {
				defer wg1.Done()
				oneDtlsConnectionLoop(ctx, peer, listenConnChan, cc, nil)
			}()
			go func() {
				defer wg1.Done()
				oneTurnConnectionLoop(ctx, params, peer, cc, t)
			}()
		}
	}

	wg1.Wait()

	// If TURN transport ended and VP8 fallback is configured, switch to it
	if vp8Fallback != "" && ctx.Err() == nil {
		log.Printf("TURN transport ended — falling back to VP8 via Telemost: %s", vp8Fallback)
		runVP8Client(ctx, *listen, vp8Fallback)
	}
}

// ─── VP8/Telemost Transport ───

// runVP8Client joins a VK call via VP8 tunnel and bridges WireGuard packets
// through the video stream. This is the fallback transport when TURN relay
// is blocked. The VK join link is used to connect to the same call as the server.
func runVP8Client(ctx context.Context, listenAddr string, vkLink string) {
	// Listen for WireGuard packets on local UDP
	listenUDP, err := net.ResolveUDPAddr("udp", listenAddr)
	if err != nil {
		log.Fatalf("Resolve listen addr: %s", err)
	}
	wgConn, err := net.ListenUDP("udp", listenUDP)
	if err != nil {
		log.Fatalf("Listen UDP: %s", err)
	}
	defer wgConn.Close()
	log.Printf("VP8 client listening on %s for WireGuard", listenAddr)

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		client := vkcall.NewClient(log.Default())
		tunnelReady := make(chan *vp8tunnel.Tunnel, 1)
		client.OnTunnel = func(t *vp8tunnel.Tunnel) {
			tunnelReady <- t
		}

		// Join VK call in background
		callDone := make(chan error, 1)
		go func() {
			callDone <- client.JoinLink(ctx, vkLink)
		}()

		// Wait for tunnel or call failure
		select {
		case tunnel := <-tunnelReady:
			log.Printf("VP8 tunnel ready — bridging WireGuard")
			pconn := vp8tunnel.NewPacketConn(tunnel)
			bridgeVP8(ctx, wgConn, pconn, tunnel.Done())
			log.Printf("VP8 bridge ended")

		case err := <-callDone:
			if ctx.Err() != nil {
				return
			}
			log.Printf("VP8 call failed: %v", err)
		}

		client.Close()
		if ctx.Err() != nil {
			return
		}
		log.Printf("Reconnecting VP8 in 5s...")
		time.Sleep(5 * time.Second)
	}
}

// runVP8TelemostClient tunnels WireGuard through Yandex Telemost DataChannel.
func runVP8TelemostClient(ctx context.Context, listenAddr string, confLink string) {
	listenUDP, err := net.ResolveUDPAddr("udp", listenAddr)
	if err != nil {
		log.Fatalf("Resolve listen addr: %s", err)
	}
	wgConn, err := net.ListenUDP("udp", listenUDP)
	if err != nil {
		log.Fatalf("Listen UDP: %s", err)
	}
	defer wgConn.Close()
	log.Printf("DC/Telemost client listening on %s for WireGuard", listenAddr)

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		client := telemost.NewClient(log.Default())
		dcReady := make(chan *telemost.DCPacketConn, 1)
		client.OnDC = func(pconn *telemost.DCPacketConn) {
			dcReady <- pconn
		}

		callDone := make(chan error, 1)
		go func() {
			callDone <- client.JoinCall(ctx, confLink)
		}()

		select {
		case pconn := <-dcReady:
			log.Printf("DC/Telemost tunnel ready — bridging WireGuard")
			bridgeVP8(ctx, wgConn, pconn, client.Done())
			log.Printf("DC/Telemost bridge ended")

		case err := <-callDone:
			if ctx.Err() != nil {
				return
			}
			log.Printf("DC/Telemost call failed: %v", err)
		}

		client.Close()
		if ctx.Err() != nil {
			return
		}
		log.Printf("Reconnecting DC/Telemost in 5s...")
		time.Sleep(5 * time.Second)
	}
}

// bridgeVP8 forwards packets between local WireGuard UDP and VP8 tunnel.
func bridgeVP8(ctx context.Context, wgConn *net.UDPConn, pconn net.PacketConn, tunnelDone <-chan struct{}) {
	ctx2, cancel := context.WithCancel(ctx)
	defer cancel()

	var wgAddr atomic.Value // stores the WG client's address

	// WG → VP8
	go func() {
		defer cancel()
		buf := make([]byte, 1600)
		for {
			select {
			case <-ctx2.Done():
				return
			case <-tunnelDone:
				return
			default:
			}
			wgConn.SetReadDeadline(time.Now().Add(5 * time.Minute))
			n, addr, err := wgConn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			wgAddr.Store(addr)
			if _, err := pconn.WriteTo(buf[:n], nil); err != nil {
				return
			}
		}
	}()

	// VP8 → WG
	buf := make([]byte, 1600)
	for {
		select {
		case <-ctx2.Done():
			return
		case <-tunnelDone:
			return
		default:
		}
		n, _, err := pconn.ReadFrom(buf)
		if err != nil {
			return
		}
		addr, _ := wgAddr.Load().(*net.UDPAddr)
		if addr != nil {
			wgConn.WriteToUDP(buf[:n], addr)
		}
	}
}
