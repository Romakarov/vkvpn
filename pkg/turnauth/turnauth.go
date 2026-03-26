// Package turnauth extracts TURN credentials from VK Calls and Yandex Telemost.
package turnauth

import "io"

// Credentials holds TURN server authentication data.
type Credentials struct {
	Username string
	Password string
	Address  string // host:port of the TURN server
}

// Session represents an active conference session that keeps credentials alive.
// Call Close() when done to leave the conference cleanly.
type Session interface {
	io.Closer
	Credentials() *Credentials
}
