// Package sessionmux provides Session ID multiplexing for DTLS connections.
//
// Problem: When a client opens N DTLS connections through N TURN relays,
// each connection arrives at the server with a different source address.
// Without multiplexing, each DTLS connection gets its own UDP socket to
// WireGuard, causing "endpoint thrashing" — WireGuard constantly switches
// the peer's endpoint, dropping packets.
//
// Solution: The client sends a magic byte (0x00) followed by a 16-byte
// Session UUID as the very first packet on each DTLS connection. The server
// reads the first byte: if 0x00, it's a session handshake; if 1-4, it's a
// legacy WireGuard packet (WG message types are 1-4). The server groups
// connections by Session ID and routes all packets from one session through
// a single UDP socket to WireGuard.
package sessionmux

import (
	"fmt"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

const (
	// MagicByte is sent before the Session ID to distinguish from WireGuard packets.
	// WireGuard message types are 1-4, so 0x00 is safe.
	MagicByte = 0x00

	// SessionIDLen is the number of bytes in a session identifier.
	SessionIDLen = 16

	// SessionHandshakeLen is MagicByte + SessionID.
	SessionHandshakeLen = 1 + SessionIDLen

	// MaxPacketSize is the buffer size for packet reads.
	MaxPacketSize = 1600

	// SessionTimeout is how long a session stays alive without traffic.
	SessionTimeout = 10 * time.Minute

	// cleanupInterval is how often we check for stale sessions.
	cleanupInterval = 1 * time.Minute
)

// SessionID is a 16-byte unique identifier for a client session.
type SessionID [SessionIDLen]byte

func (s SessionID) String() string {
	return fmt.Sprintf("%x", s[:4]) // short representation for logs
}

// Session represents a group of DTLS connections from one client.
type Session struct {
	ID       SessionID
	WGConn   net.Conn // single UDP socket to WireGuard
	mu       sync.RWMutex
	conns    []net.Conn // DTLS connections in this session
	rrIndex  uint32     // round-robin counter for outgoing packets
	lastPkt  atomic.Int64
	done     chan struct{}
	closed   bool
	wgOnce   sync.Once // ensures BridgeWGToDTLS is started exactly once
}

// touchLastPkt updates the last packet timestamp atomically.
func (s *Session) touchLastPkt() {
	s.lastPkt.Store(time.Now().UnixNano())
}

// LastPacketTime returns the last packet time.
func (s *Session) LastPacketTime() time.Time {
	return time.Unix(0, s.lastPkt.Load())
}

// AddConn adds a DTLS connection to this session.
func (s *Session) AddConn(conn net.Conn) {
	s.mu.Lock()
	s.conns = append(s.conns, conn)
	s.mu.Unlock()
}

// RemoveConn removes a DTLS connection from this session.
func (s *Session) RemoveConn(conn net.Conn) {
	s.mu.Lock()
	for i, c := range s.conns {
		if c == conn {
			s.conns = append(s.conns[:i], s.conns[i+1:]...)
			break
		}
	}
	empty := len(s.conns) == 0
	s.mu.Unlock()

	if empty {
		s.Close()
	}
}

// NextConn returns the next DTLS connection in round-robin order.
// Returns nil if no connections are available.
func (s *Session) NextConn() net.Conn {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if len(s.conns) == 0 {
		return nil
	}
	idx := atomic.AddUint32(&s.rrIndex, 1) % uint32(len(s.conns))
	return s.conns[idx]
}

// ConnCount returns the number of active DTLS connections.
func (s *Session) ConnCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.conns)
}

// Close closes the WireGuard socket and marks the session as done.
func (s *Session) Close() {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.closed = true
	s.mu.Unlock()
	close(s.done)
	s.WGConn.Close()
}

// StartWGBridge ensures the WG→DTLS bridge goroutine is started exactly once.
func (s *Session) StartWGBridge() {
	s.wgOnce.Do(func() {
		go BridgeWGToDTLS(s)
	})
}

// Mux manages multiple sessions, grouping DTLS connections by Session ID.
type Mux struct {
	mu       sync.RWMutex
	sessions map[SessionID]*Session
	wgAddr   string // WireGuard address (e.g. "127.0.0.1:51820")
	logger   *log.Logger
	stopCh   chan struct{}
}

// NewMux creates a new session multiplexer and starts cleanup goroutine.
func NewMux(wgAddr string, logger *log.Logger) *Mux {
	m := &Mux{
		sessions: make(map[SessionID]*Session),
		wgAddr:   wgAddr,
		logger:   logger,
		stopCh:   make(chan struct{}),
	}
	go m.cleanupLoop()
	return m
}

// Stop stops the cleanup goroutine.
func (m *Mux) Stop() {
	close(m.stopCh)
}

// cleanupLoop periodically removes stale sessions.
func (m *Mux) cleanupLoop() {
	ticker := time.NewTicker(cleanupInterval)
	defer ticker.Stop()
	for {
		select {
		case <-m.stopCh:
			return
		case <-ticker.C:
			m.cleanupStaleSessions()
		}
	}
}

func (m *Mux) cleanupStaleSessions() {
	now := time.Now()
	var toRemove []SessionID

	m.mu.RLock()
	for id, s := range m.sessions {
		if s.ConnCount() == 0 && now.Sub(s.LastPacketTime()) > SessionTimeout {
			toRemove = append(toRemove, id)
		}
	}
	m.mu.RUnlock()

	for _, id := range toRemove {
		m.RemoveSession(id)
	}
}

// GetOrCreateSession returns existing session or creates a new one.
func (m *Mux) GetOrCreateSession(id SessionID) (*Session, error) {
	m.mu.RLock()
	s, ok := m.sessions[id]
	m.mu.RUnlock()
	if ok {
		return s, nil
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	// Double-check after acquiring write lock
	if s, ok = m.sessions[id]; ok {
		return s, nil
	}

	wgConn, err := net.Dial("udp", m.wgAddr)
	if err != nil {
		return nil, fmt.Errorf("dial WG: %w", err)
	}

	s = &Session{
		ID:     id,
		WGConn: wgConn,
		done:   make(chan struct{}),
	}
	s.touchLastPkt()
	m.sessions[id] = s
	m.logger.Printf("Session %s created (WG endpoint: %s)", id, wgConn.LocalAddr())

	return s, nil
}

// RemoveSession removes and closes a session.
func (m *Mux) RemoveSession(id SessionID) {
	m.mu.Lock()
	s, ok := m.sessions[id]
	if ok {
		delete(m.sessions, id)
	}
	m.mu.Unlock()

	if ok {
		s.Close()
		m.logger.Printf("Session %s removed", id)
	}
}

// SessionCount returns the total number of active sessions.
func (m *Mux) SessionCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.sessions)
}

// ReadSessionHandshake reads the first packet from a DTLS connection.
// Returns (sessionID, true, nil) if it's a session handshake (magic byte + UUID).
// Returns (zero, false, nil) with firstPacket containing the full WG data if
// the first byte is a WG message type (1-4) — legacy client.
// The firstPacket is returned so it can be forwarded.
func ReadSessionHandshake(conn net.Conn) (id SessionID, isSession bool, firstPacket []byte, err error) {
	buf := make([]byte, MaxPacketSize)
	conn.SetReadDeadline(time.Now().Add(30 * time.Second))
	n, err := conn.Read(buf)
	if err != nil {
		return SessionID{}, false, nil, err
	}
	if n == 0 {
		return SessionID{}, false, nil, fmt.Errorf("empty first packet")
	}

	// Check magic byte: 0x00 = session handshake, 1-4 = WG message types
	if buf[0] != MagicByte {
		// Legacy WG packet — return full packet for forwarding
		pkt := make([]byte, n)
		copy(pkt, buf[:n])
		return SessionID{}, false, pkt, nil
	}

	// Session handshake: 0x00 + 16 bytes UUID
	if n < SessionHandshakeLen {
		return SessionID{}, false, nil, fmt.Errorf("session handshake too short: %d bytes (need %d)", n, SessionHandshakeLen)
	}

	copy(id[:], buf[1:SessionHandshakeLen])
	return id, true, nil, nil
}

// BridgeDTLSToWG reads packets from DTLS and forwards to WireGuard.
func BridgeDTLSToWG(sess *Session, conn net.Conn) {
	buf := make([]byte, MaxPacketSize)
	for {
		select {
		case <-sess.done:
			return
		default:
		}
		conn.SetReadDeadline(time.Now().Add(5 * time.Minute))
		n, err := conn.Read(buf)
		if err != nil {
			return
		}
		sess.WGConn.SetWriteDeadline(time.Now().Add(5 * time.Minute))
		if _, err = sess.WGConn.Write(buf[:n]); err != nil {
			return
		}
		sess.touchLastPkt()
	}
}

// BridgeWGToDTLS reads packets from WireGuard and distributes them
// round-robin across the session's DTLS connections.
func BridgeWGToDTLS(sess *Session) {
	buf := make([]byte, MaxPacketSize)
	for {
		select {
		case <-sess.done:
			return
		default:
		}
		sess.WGConn.SetReadDeadline(time.Now().Add(30 * time.Minute))
		n, err := sess.WGConn.Read(buf)
		if err != nil {
			return
		}
		conn := sess.NextConn()
		if conn == nil {
			return
		}
		conn.SetWriteDeadline(time.Now().Add(30 * time.Minute))
		if _, err = conn.Write(buf[:n]); err != nil {
			// This specific connection failed; session continues with others
			continue
		}
	}
}
