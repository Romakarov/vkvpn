// Package turnauth extracts TURN credentials from VK Calls and Yandex Telemost.
package turnauth

import (
	"errors"
	"fmt"
	"io"
)

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

// VKAPIError represents a structured error from the VK API.
type VKAPIError struct {
	Code    int
	Message string
}

func (e *VKAPIError) Error() string {
	return fmt.Sprintf("VK API error %d: %s", e.Code, e.Message)
}

// NewVKAPIError creates a VKAPIError from a VK API error response object.
func NewVKAPIError(errObj map[string]interface{}) *VKAPIError {
	code := 0
	if c, ok := errObj["error_code"].(float64); ok {
		code = int(c)
	}
	msg := ""
	if m, ok := errObj["error_msg"].(string); ok {
		msg = m
	}
	return &VKAPIError{Code: code, Message: msg}
}

// IsRateLimited returns true if the error is a VK rate limit (error 29).
func IsRateLimited(err error) bool {
	var vkErr *VKAPIError
	return errors.As(err, &vkErr) && vkErr.Code == 29
}

// IsTokenExpired returns true if the error indicates an expired/invalid token (error 5 or 15).
func IsTokenExpired(err error) bool {
	var vkErr *VKAPIError
	return errors.As(err, &vkErr) && (vkErr.Code == 5 || vkErr.Code == 15)
}

// IsBanned returns true if the error indicates the account is banned (error 17 or 18).
func IsBanned(err error) bool {
	var vkErr *VKAPIError
	return errors.As(err, &vkErr) && (vkErr.Code == 17 || vkErr.Code == 18)
}
