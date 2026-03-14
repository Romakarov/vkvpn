package main

import (
	"testing"
)

func TestLogBuffer(t *testing.T) {
	lb := NewLogBuffer(5)

	// Write entries
	lb.Write([]byte("msg 1"))
	lb.Write([]byte("msg 2"))
	lb.Write([]byte("msg 3"))

	entries := lb.Entries(0)
	if len(entries) != 3 {
		t.Fatalf("expected 3, got %d", len(entries))
	}
	if entries[0].Message != "msg 1" {
		t.Fatalf("expected 'msg 1', got %q", entries[0].Message)
	}

	// Test afterID filtering
	entries = lb.Entries(1)
	if len(entries) != 2 {
		t.Fatalf("expected 2 after id 1, got %d", len(entries))
	}

	// Test overflow
	lb.Write([]byte("msg 4"))
	lb.Write([]byte("msg 5"))
	lb.Write([]byte("msg 6")) // should push out msg 1

	entries = lb.Entries(0)
	if len(entries) != 5 {
		t.Fatalf("expected 5 (max), got %d", len(entries))
	}
	if entries[0].Message != "msg 2" {
		t.Fatalf("expected 'msg 2' after overflow, got %q", entries[0].Message)
	}
}

func TestLogBufferEmpty(t *testing.T) {
	lb := NewLogBuffer(10)
	entries := lb.Entries(0)
	if len(entries) != 0 {
		t.Fatalf("expected 0, got %d", len(entries))
	}
	entries = lb.Entries(999)
	if entries != nil {
		t.Fatalf("expected nil for future ID, got %d entries", len(entries))
	}
}
