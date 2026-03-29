package sessionmux

import (
	"log"
	"net"
	"os"
	"testing"
	"time"
)

func testLogger() *log.Logger {
	return log.New(os.Stderr, "test: ", log.LstdFlags)
}

func TestSessionIDString(t *testing.T) {
	var id SessionID
	copy(id[:], []byte{0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c})
	s := id.String()
	if s != "deadbeef" {
		t.Errorf("expected 'deadbeef', got %q", s)
	}
}

func TestSessionAddRemoveConn(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	s := &Session{
		done: make(chan struct{}),
	}

	s.AddConn(c1)
	if s.ConnCount() != 1 {
		t.Fatalf("expected 1 conn, got %d", s.ConnCount())
	}

	s.AddConn(c2)
	if s.ConnCount() != 2 {
		t.Fatalf("expected 2 conns, got %d", s.ConnCount())
	}

	got1 := s.NextConn()
	got2 := s.NextConn()
	if got1 == nil || got2 == nil {
		t.Fatal("NextConn returned nil")
	}

	s.RemoveConn(c1)
	if s.ConnCount() != 1 {
		t.Fatalf("expected 1 conn after remove, got %d", s.ConnCount())
	}
}

func TestMuxGetOrCreateSession(t *testing.T) {
	wgAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	wgConn, err := net.ListenUDP("udp", wgAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer wgConn.Close()

	mux := NewMux(wgConn.LocalAddr().String(), testLogger())
	defer mux.Stop()

	var id SessionID
	copy(id[:], []byte("session-id-test!"))

	s1, err := mux.GetOrCreateSession(id)
	if err != nil {
		t.Fatal(err)
	}

	s2, err := mux.GetOrCreateSession(id)
	if err != nil {
		t.Fatal(err)
	}
	if s1 != s2 {
		t.Error("expected same session for same ID")
	}

	if mux.SessionCount() != 1 {
		t.Errorf("expected 1 session, got %d", mux.SessionCount())
	}

	var id2 SessionID
	copy(id2[:], []byte("session-id-two!!"))
	s3, err := mux.GetOrCreateSession(id2)
	if err != nil {
		t.Fatal(err)
	}
	if s3 == s1 {
		t.Error("expected different session for different ID")
	}
	if mux.SessionCount() != 2 {
		t.Errorf("expected 2 sessions, got %d", mux.SessionCount())
	}

	mux.RemoveSession(id)
	if mux.SessionCount() != 1 {
		t.Errorf("expected 1 session after remove, got %d", mux.SessionCount())
	}
	mux.RemoveSession(id2)
}

func TestReadSessionHandshake_NewClient(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	// Writer sends magic byte + 16-byte session ID
	go func() {
		pkt := make([]byte, SessionHandshakeLen)
		pkt[0] = MagicByte
		copy(pkt[1:], []byte("0123456789abcdef"))
		c2.Write(pkt)
	}()

	id, isSession, _, err := ReadSessionHandshake(c1)
	if err != nil {
		t.Fatal(err)
	}
	if !isSession {
		t.Fatal("expected isSession=true for magic byte handshake")
	}
	expectedID := "30313233"
	if id.String() != expectedID {
		t.Errorf("expected ID %s, got %s", expectedID, id.String())
	}
}

func TestReadSessionHandshake_LegacyClient(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	// Legacy WireGuard handshake initiation (type 1)
	go func() {
		pkt := make([]byte, 148) // WG handshake initiation size
		pkt[0] = 0x01            // WG message type 1 (handshake initiation)
		pkt[1] = 0x00
		pkt[2] = 0x00
		pkt[3] = 0x00
		for i := 4; i < 148; i++ {
			pkt[i] = byte(i)
		}
		c2.Write(pkt)
	}()

	id, isSession, firstPkt, err := ReadSessionHandshake(c1)
	if err != nil {
		t.Fatal(err)
	}
	if isSession {
		t.Fatal("expected isSession=false for WG packet")
	}
	if id != (SessionID{}) {
		t.Error("expected zero session ID for legacy client")
	}
	if len(firstPkt) != 148 {
		t.Errorf("expected firstPkt len=148, got %d", len(firstPkt))
	}
	if firstPkt[0] != 0x01 {
		t.Errorf("expected first byte 0x01 (WG type), got 0x%02x", firstPkt[0])
	}
}

func TestReadSessionHandshake_TooShort(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	// Magic byte but too short for full session ID
	go func() {
		c2.Write([]byte{MagicByte, 0x01, 0x02}) // only 3 bytes after magic
	}()

	_, _, _, err := ReadSessionHandshake(c1)
	if err == nil {
		t.Fatal("expected error for short session handshake")
	}
}

func TestSessionRoundRobin(t *testing.T) {
	s := &Session{done: make(chan struct{})}

	conns := make([]net.Conn, 4)
	for i := range conns {
		c1, c2 := net.Pipe()
		defer c2.Close()
		conns[i] = c1
		s.AddConn(c1)
	}

	counts := make(map[net.Conn]int)
	for i := 0; i < 100; i++ {
		c := s.NextConn()
		counts[c]++
	}

	for _, c := range conns {
		got := counts[c]
		if got < 20 || got > 30 {
			t.Errorf("expected ~25, got %d", got)
		}
	}
}

func TestSessionClose(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c2.Close()

	s := &Session{
		WGConn: c1,
		done:   make(chan struct{}),
	}

	s.Close()
	s.Close() // double close should be safe

	select {
	case <-s.done:
	case <-time.After(100 * time.Millisecond):
		t.Fatal("done channel not closed")
	}
}

func TestStartWGBridgeOnce(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c2.Close()

	s := &Session{
		WGConn: c1,
		done:   make(chan struct{}),
	}

	// Call StartWGBridge multiple times — should only start one goroutine
	s.StartWGBridge()
	s.StartWGBridge()
	s.StartWGBridge()

	// Close to stop the goroutine
	s.Close()
}

func TestTouchLastPkt(t *testing.T) {
	s := &Session{done: make(chan struct{})}
	s.touchLastPkt()

	ts := s.LastPacketTime()
	if time.Since(ts) > 1*time.Second {
		t.Errorf("lastPkt too old: %v", ts)
	}
}
