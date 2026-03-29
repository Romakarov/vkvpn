package turnauth

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestGetYandexCredentialsDeprecated(t *testing.T) {
	_, err := GetYandexCredentials("https://telemost.yandex.ru/j/12345")
	if err == nil {
		t.Fatal("expected error from deprecated GetYandexCredentials")
	}
	if !errors.Is(err, ErrYandexDeprecated) {
		t.Errorf("expected ErrYandexDeprecated, got: %v", err)
	}
}

func TestGetYandexCredentialsWithKeepaliveDeprecated(t *testing.T) {
	_, err := GetYandexCredentialsWithKeepalive("https://telemost.yandex.ru/j/12345")
	if err == nil {
		t.Fatal("expected error from deprecated GetYandexCredentialsWithKeepalive")
	}
	if !errors.Is(err, ErrYandexDeprecated) {
		t.Errorf("expected ErrYandexDeprecated, got: %v", err)
	}
}

func TestGetYandexCredentialsLinkParsing(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"12345", "12345"},
		{"https://telemost.yandex.ru/j/12345", "12345"},
		{"https://telemost.yandex.ru/j/12345?key=val", "12345"},
	}
	for _, tt := range tests {
		link := tt.input
		if strings.Contains(link, "j/") {
			parts := strings.Split(link, "j/")
			link = parts[len(parts)-1]
		}
		if idx := strings.IndexAny(link, "/?#"); idx != -1 {
			link = link[:idx]
		}
		if link != tt.want {
			t.Errorf("input=%q: got %q, want %q", tt.input, link, tt.want)
		}
	}
}

func TestFlexUrls(t *testing.T) {
	var f flexUrls
	if err := json.Unmarshal([]byte(`"turn:example.com:3478"`), &f); err != nil {
		t.Fatal(err)
	}
	if len(f) != 1 || f[0] != "turn:example.com:3478" {
		t.Errorf("single string: got %v", f)
	}

	var f2 flexUrls
	if err := json.Unmarshal([]byte(`["turn:a:3478","turn:b:3478"]`), &f2); err != nil {
		t.Fatal(err)
	}
	if len(f2) != 2 {
		t.Errorf("array: got %v", f2)
	}
}

func TestBuildHelloRequest(t *testing.T) {
	req := buildHelloRequest("peer1", "room1", "cred1", "ua")
	hello, ok := req["hello"].(map[string]interface{})
	if !ok {
		t.Fatal("hello not a map")
	}
	if hello["participantId"] != "peer1" {
		t.Errorf("expected peer1, got %v", hello["participantId"])
	}
	if hello["roomId"] != "room1" {
		t.Errorf("expected room1, got %v", hello["roomId"])
	}
	if hello["credentials"] != "cred1" {
		t.Errorf("expected cred1, got %v", hello["credentials"])
	}
}
