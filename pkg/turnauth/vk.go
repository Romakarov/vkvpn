package turnauth

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
)

// vkBaseURLs holds the base URLs for VK API calls. Overridable for testing.
var vkBaseURLs = struct {
	LoginVK string
	ApiVK   string
	OkCDN   string
}{
	LoginVK: "https://login.vk.ru",
	ApiVK:   "https://api.vk.ru",
	OkCDN:   "https://calls.okcdn.ru",
}

// GetVKCredentials extracts TURN credentials from a VK Calls join link.
// The link should be the join hash (e.g. "ABC123") or full URL.
func GetVKCredentials(link string) (*Credentials, error) {
	// Extract just the join hash if full URL provided
	if strings.Contains(link, "join/") {
		parts := strings.Split(link, "join/")
		link = parts[len(parts)-1]
	}
	if idx := strings.IndexAny(link, "/?#"); idx != -1 {
		link = link[:idx]
	}

	doRequest := func(data string, url string) (map[string]interface{}, error) {
		client := &http.Client{
			Timeout: 20 * time.Second,
			Transport: &http.Transport{
				MaxIdleConns:        100,
				MaxIdleConnsPerHost: 100,
				IdleConnTimeout:     90 * time.Second,
			},
		}
		defer client.CloseIdleConnections()
		req, err := http.NewRequest("POST", url, bytes.NewBuffer([]byte(data)))
		if err != nil {
			return nil, err
		}
		req.Header.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:144.0) Gecko/20100101 Firefox/144.0")
		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		resp, err := client.Do(req)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, err
		}
		var result map[string]interface{}
		if err = json.Unmarshal(body, &result); err != nil {
			return nil, fmt.Errorf("JSON decode: %s (body: %s)", err, string(body))
		}
		return result, nil
	}

	// Helper to safely navigate nested JSON
	getStr := func(m map[string]interface{}, keys ...string) (string, error) {
		var current interface{} = m
		for _, k := range keys {
			cm, ok := current.(map[string]interface{})
			if !ok {
				return "", fmt.Errorf("expected map at key %q, got %T", k, current)
			}
			current = cm[k]
		}
		s, ok := current.(string)
		if !ok {
			return "", fmt.Errorf("expected string, got %T: %v", current, current)
		}
		return s, nil
	}

	// Step 1: Get anonymous token
	data := "client_secret=QbYic1K3lEV5kTGiqlq2&client_id=6287487&scopes=audio_anonymous%2Cvideo_anonymous%2Cphotos_anonymous%2Cprofile_anonymous&isApiOauthAnonymEnabled=false&version=1&app_id=6287487"
	resp, err := doRequest(data, vkBaseURLs.LoginVK+"/?act=get_anonym_token")
	if err != nil {
		return nil, fmt.Errorf("step 1: %w", err)
	}
	token1, err := getStr(resp, "data", "access_token")
	if err != nil {
		return nil, fmt.Errorf("step 1 parse: %w", err)
	}

	// Step 2: Get anonymous access token payload
	data = fmt.Sprintf("access_token=%s", token1)
	resp, err = doRequest(data, vkBaseURLs.ApiVK+"/method/calls.getAnonymousAccessTokenPayload?v=5.264&client_id=6287487")
	if err != nil {
		return nil, fmt.Errorf("step 2: %w", err)
	}
	token2, err := getStr(resp, "response", "payload")
	if err != nil {
		return nil, fmt.Errorf("step 2 parse: %w", err)
	}

	// Step 3: Get messages token
	data = fmt.Sprintf("client_id=6287487&token_type=messages&payload=%s&client_secret=QbYic1K3lEV5kTGiqlq2&version=1&app_id=6287487", token2)
	resp, err = doRequest(data, vkBaseURLs.LoginVK+"/?act=get_anonym_token")
	if err != nil {
		return nil, fmt.Errorf("step 3: %w", err)
	}
	token3, err := getStr(resp, "data", "access_token")
	if err != nil {
		return nil, fmt.Errorf("step 3 parse: %w", err)
	}

	// Step 4: Get anonymous call token
	data = fmt.Sprintf("vk_join_link=https://vk.com/call/join/%s&name=123&access_token=%s", link, token3)
	resp, err = doRequest(data, vkBaseURLs.ApiVK+"/method/calls.getAnonymousToken?v=5.264")
	if err != nil {
		return nil, fmt.Errorf("step 4: %w", err)
	}
	token4, err := getStr(resp, "response", "token")
	if err != nil {
		return nil, fmt.Errorf("step 4 parse: %w", err)
	}

	// Step 5: OK.ru anonymous login
	data = fmt.Sprintf("%s%s%s", "session_data=%7B%22version%22%3A2%2C%22device_id%22%3A%22", uuid.New(), "%22%2C%22client_version%22%3A1.1%2C%22client_type%22%3A%22SDK_JS%22%7D&method=auth.anonymLogin&format=JSON&application_key=CGMMEJLGDIHBABABA")
	resp, err = doRequest(data, vkBaseURLs.OkCDN+"/fb.do")
	if err != nil {
		return nil, fmt.Errorf("step 5: %w", err)
	}
	token5, err := getStr(resp, "session_key")
	if err != nil {
		return nil, fmt.Errorf("step 5 parse: %w", err)
	}

	// Step 6: Join conversation and get TURN credentials
	data = fmt.Sprintf("joinLink=%s&isVideo=false&protocolVersion=5&anonymToken=%s&method=vchat.joinConversationByLink&format=JSON&application_key=CGMMEJLGDIHBABABA&session_key=%s", link, token4, token5)
	resp, err = doRequest(data, vkBaseURLs.OkCDN+"/fb.do")
	if err != nil {
		return nil, fmt.Errorf("step 6: %w", err)
	}

	user, err := getStr(resp, "turn_server", "username")
	if err != nil {
		return nil, fmt.Errorf("step 6 parse username: %w", err)
	}
	pass, err := getStr(resp, "turn_server", "credential")
	if err != nil {
		return nil, fmt.Errorf("step 6 parse credential: %w", err)
	}

	// Get TURN server URL
	turnServer, ok := resp["turn_server"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("missing turn_server in response")
	}
	urls, ok := turnServer["urls"].([]interface{})
	if !ok || len(urls) == 0 {
		return nil, fmt.Errorf("missing turn_server urls")
	}
	turnURL, ok := urls[0].(string)
	if !ok {
		return nil, fmt.Errorf("invalid turn URL type")
	}
	clean := strings.Split(turnURL, "?")[0]
	addr := strings.TrimPrefix(strings.TrimPrefix(clean, "turn:"), "turns:")

	return &Credentials{Username: user, Password: pass, Address: addr}, nil
}

// GetVKCredentialsWithToken extracts TURN credentials using a VK user access token.
//
// Discovered flow (March 2026):
//   1. calls.start (user token) → creates call, returns ok_join_link
//   2. get_anonym_token (no auth) → anonymous token (step 1 of original flow, still works)
//   3. calls.getAnonymousToken (anon token + join_link) → call-specific anonymToken
//   4. OK.ru anonymLogin → session_key
//   5. vchat.joinConversationByLink (anonymToken + session_key) → TURN credentials
//
// This bypasses the broken step 2 (calls.getAnonymousAccessTokenPayload) entirely.
func GetVKCredentialsWithToken(link string, userAccessToken string) (*Credentials, error) {
	doRequest := func(data string, url string) (map[string]interface{}, error) {
		client := &http.Client{
			Timeout: 20 * time.Second,
			Transport: &http.Transport{
				MaxIdleConns:        100,
				MaxIdleConnsPerHost: 100,
				IdleConnTimeout:     90 * time.Second,
			},
		}
		defer client.CloseIdleConnections()
		req, err := http.NewRequest("POST", url, bytes.NewBuffer([]byte(data)))
		if err != nil {
			return nil, err
		}
		req.Header.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:144.0) Gecko/20100101 Firefox/144.0")
		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		resp, err := client.Do(req)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, err
		}
		var result map[string]interface{}
		if err = json.Unmarshal(body, &result); err != nil {
			return nil, fmt.Errorf("JSON decode: %s (body: %s)", err, string(body))
		}
		return result, nil
	}

	getStr := func(m map[string]interface{}, keys ...string) (string, error) {
		var current interface{} = m
		for _, k := range keys {
			cm, ok := current.(map[string]interface{})
			if !ok {
				return "", fmt.Errorf("expected map at key %q, got %T", k, current)
			}
			current = cm[k]
		}
		s, ok := current.(string)
		if !ok {
			return "", fmt.Errorf("expected string, got %T: %v", current, current)
		}
		return s, nil
	}

	// Step 1: Create a call using user token → get join link
	data := fmt.Sprintf("access_token=%s", userAccessToken)
	resp, err := doRequest(data, vkBaseURLs.ApiVK+"/method/calls.start?v=5.264")
	if err != nil {
		return nil, fmt.Errorf("calls.start: %w", err)
	}
	if errObj, ok := resp["error"].(map[string]interface{}); ok {
		return nil, fmt.Errorf("calls.start error %v: %v", errObj["error_code"], errObj["error_msg"])
	}
	joinLink, err := getStr(resp, "response", "ok_join_link")
	if err != nil {
		return nil, fmt.Errorf("calls.start parse: %w", err)
	}

	// Step 2: Get anonymous token (original step 1 — still works, no rate limit)
	data = "client_secret=QbYic1K3lEV5kTGiqlq2&client_id=6287487&scopes=audio_anonymous%2Cvideo_anonymous%2Cphotos_anonymous%2Cprofile_anonymous&isApiOauthAnonymEnabled=false&version=1&app_id=6287487"
	resp, err = doRequest(data, vkBaseURLs.LoginVK+"/?act=get_anonym_token")
	if err != nil {
		return nil, fmt.Errorf("get_anonym_token: %w", err)
	}
	anonToken, err := getStr(resp, "data", "access_token")
	if err != nil {
		return nil, fmt.Errorf("get_anonym_token parse: %w", err)
	}

	// Step 3: Get call-specific anonymous token
	data = fmt.Sprintf("vk_join_link=https://vk.com/call/join/%s&name=vkvpn&access_token=%s", joinLink, anonToken)
	resp, err = doRequest(data, vkBaseURLs.ApiVK+"/method/calls.getAnonymousToken?v=5.264")
	if err != nil {
		return nil, fmt.Errorf("getAnonymousToken: %w", err)
	}
	if errObj, ok := resp["error"].(map[string]interface{}); ok {
		return nil, fmt.Errorf("getAnonymousToken error %v: %v", errObj["error_code"], errObj["error_msg"])
	}
	callToken, err := getStr(resp, "response", "token")
	if err != nil {
		return nil, fmt.Errorf("getAnonymousToken parse: %w", err)
	}

	// Step 4: OK.ru anonymous login
	data = fmt.Sprintf("%s%s%s", "session_data=%7B%22version%22%3A2%2C%22device_id%22%3A%22", uuid.New(), "%22%2C%22client_version%22%3A1.1%2C%22client_type%22%3A%22SDK_JS%22%7D&method=auth.anonymLogin&format=JSON&application_key=CGMMEJLGDIHBABABA")
	resp, err = doRequest(data, vkBaseURLs.OkCDN+"/fb.do")
	if err != nil {
		return nil, fmt.Errorf("okru login: %w", err)
	}
	sessionKey, err := getStr(resp, "session_key")
	if err != nil {
		return nil, fmt.Errorf("okru login parse: %w", err)
	}

	// Step 5: Join conversation and get TURN credentials
	data = fmt.Sprintf("joinLink=%s&isVideo=false&protocolVersion=5&anonymToken=%s&method=vchat.joinConversationByLink&format=JSON&application_key=CGMMEJLGDIHBABABA&session_key=%s", joinLink, callToken, sessionKey)
	resp, err = doRequest(data, vkBaseURLs.OkCDN+"/fb.do")
	if err != nil {
		return nil, fmt.Errorf("join call: %w", err)
	}

	return parseTurnCredentials(resp)
}

// parseTurnCredentials extracts TURN credentials from an OK.ru API response
func parseTurnCredentials(resp map[string]interface{}) (*Credentials, error) {
	getStr := func(m map[string]interface{}, keys ...string) (string, error) {
		var current interface{} = m
		for _, k := range keys {
			cm, ok := current.(map[string]interface{})
			if !ok {
				return "", fmt.Errorf("expected map at key %q, got %T", k, current)
			}
			current = cm[k]
		}
		s, ok := current.(string)
		if !ok {
			return "", fmt.Errorf("expected string, got %T: %v", current, current)
		}
		return s, nil
	}

	user, err := getStr(resp, "turn_server", "username")
	if err != nil {
		return nil, fmt.Errorf("parse username: %w", err)
	}
	pass, err := getStr(resp, "turn_server", "credential")
	if err != nil {
		return nil, fmt.Errorf("parse credential: %w", err)
	}

	turnServer, ok := resp["turn_server"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("missing turn_server in response")
	}
	urls, ok := turnServer["urls"].([]interface{})
	if !ok || len(urls) == 0 {
		return nil, fmt.Errorf("missing turn_server urls")
	}
	turnURL, ok := urls[0].(string)
	if !ok {
		return nil, fmt.Errorf("invalid turn URL type")
	}
	clean := strings.Split(turnURL, "?")[0]
	addr := strings.TrimPrefix(strings.TrimPrefix(clean, "turn:"), "turns:")

	return &Credentials{Username: user, Password: pass, Address: addr}, nil
}
