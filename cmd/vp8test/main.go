// Command vp8test is a diagnostic tool for testing the VP8/Telemost transport
// step by step. It checks each stage of the connection and reports results.
//
// Usage:
//
//	go run ./cmd/vp8test/ --telemost-link "https://telemost.yandex.ru/j/XXXXX"
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"time"

	"github.com/Romakarov/vkvpn/pkg/telemost"
	"github.com/Romakarov/vkvpn/pkg/vp8tunnel"
)

func main() {
	telemostLink := flag.String("telemost-link", "", "Telemost conference link (required)")
	timeout := flag.Duration("timeout", 60*time.Second, "Overall timeout")
	flag.Parse()

	if *telemostLink == "" {
		fmt.Fprintln(os.Stderr, "Usage: vp8test --telemost-link https://telemost.yandex.ru/j/XXXXX")
		os.Exit(1)
	}

	logger := log.New(os.Stdout, "", log.LstdFlags|log.Lmicroseconds)

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	// Handle Ctrl+C
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt)
	go func() {
		<-sigCh
		logger.Println("[vp8test] Interrupted, shutting down...")
		cancel()
	}()

	logger.Println("=== VP8/Telemost Diagnostic Tool ===")
	logger.Printf("Link: %s", *telemostLink)
	logger.Printf("Timeout: %s", *timeout)
	logger.Println()

	// Create Telemost client
	client := telemost.NewClient(logger)

	tunnelReady := make(chan *vp8tunnel.Tunnel, 1)
	client.OnTunnel = func(t *vp8tunnel.Tunnel) {
		logger.Println("[vp8test] === TUNNEL ESTABLISHED ===")
		tunnelReady <- t
	}

	// Join call in background
	errCh := make(chan error, 1)
	go func() {
		errCh <- client.JoinCall(ctx, *telemostLink)
	}()

	// Wait for tunnel or error
	select {
	case t := <-tunnelReady:
		logger.Println("[vp8test] VP8 tunnel is ready for data!")
		logger.Println("[vp8test] Sending test data frame...")

		testData := []byte("VP8_TEST_PING_" + time.Now().Format("15:04:05"))
		if err := t.Send(testData); err != nil {
			logger.Printf("[vp8test] Send error: %s", err)
		} else {
			logger.Printf("[vp8test] Sent %d bytes: %q", len(testData), testData)
		}

		// Wait for incoming data (from second participant or echo)
		logger.Println("[vp8test] Waiting 15s for incoming data...")
		recvCtx, recvCancel := context.WithTimeout(ctx, 15*time.Second)
		defer recvCancel()

		go func() {
			data, err := t.Recv()
			if err != nil {
				logger.Printf("[vp8test] Recv error: %s", err)
				return
			}
			logger.Printf("[vp8test] === RECEIVED DATA: %d bytes: %q ===", len(data), data)
		}()

		select {
		case <-recvCtx.Done():
			logger.Println("[vp8test] No data received (expected if only 1 participant)")
		case err := <-errCh:
			logger.Printf("[vp8test] Call ended: %v", err)
		}

	case err := <-errCh:
		logger.Printf("[vp8test] === FAILED: %v ===", err)
		logger.Println()
		logger.Println("Troubleshooting:")
		logger.Println("  - Check if Telemost link is valid and conference is active")
		logger.Println("  - Check if conference API requires authentication now")
		logger.Println("  - Look at logs above for the exact failure point")
		os.Exit(1)

	case <-ctx.Done():
		logger.Println("[vp8test] Timeout reached")
	}

	client.Close()
	logger.Println("[vp8test] Done")
}
