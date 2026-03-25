// Package turnauth extracts TURN credentials from VK Calls and Yandex Telemost.
package turnauth

// Credentials holds TURN server authentication data.
type Credentials struct {
	Username string
	Password string
	Address  string // host:port of the TURN server
}
