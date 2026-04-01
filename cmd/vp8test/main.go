// Command vp8test is a diagnostic tool for testing the Telemost DataChannel transport.
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

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt)
	go func() {
		<-sigCh
		logger.Println("[dctest] Interrupted, shutting down...")
		cancel()
	}()

	logger.Println("=== Telemost DataChannel Diagnostic Tool ===")
	logger.Printf("Link: %s", *telemostLink)
	logger.Printf("Timeout: %s", *timeout)
	logger.Println()

	client := telemost.NewClient(logger)

	dcReady := make(chan *telemost.DCPacketConn, 1)
	client.OnDC = func(pconn *telemost.DCPacketConn) {
		logger.Println("[dctest] === DC TUNNEL READY ===")
		dcReady <- pconn
	}

	errCh := make(chan error, 1)
	go func() {
		errCh <- client.JoinCall(ctx, *telemostLink)
	}()

	select {
	case pconn := <-dcReady:
		logger.Println("[dctest] DataChannel tunnel is ready!")
		logger.Println("[dctest] Sending test packet...")

		testData := []byte("DC_TEST_PING_" + time.Now().Format("15:04:05"))
		if _, err := pconn.WriteTo(testData, nil); err != nil {
			logger.Printf("[dctest] Write error: %s", err)
		} else {
			logger.Printf("[dctest] Sent %d bytes: %q", len(testData), testData)
		}

		logger.Println("[dctest] Waiting 15s for incoming data...")
		recvCtx, recvCancel := context.WithTimeout(ctx, 15*time.Second)
		defer recvCancel()

		go func() {
			buf := make([]byte, 1600)
			n, _, err := pconn.ReadFrom(buf)
			if err != nil {
				logger.Printf("[dctest] Read error: %s", err)
				return
			}
			logger.Printf("[dctest] === RECEIVED DATA: %d bytes: %q ===", n, buf[:n])
		}()

		select {
		case <-recvCtx.Done():
			logger.Println("[dctest] Timeout (expected if only 1 participant in conference)")
		case err := <-errCh:
			logger.Printf("[dctest] Call ended: %v", err)
		}

	case err := <-errCh:
		logger.Printf("[dctest] === FAILED: %v ===", err)
		os.Exit(1)

	case <-ctx.Done():
		logger.Println("[dctest] Timeout reached")
	}

	client.Close()
	logger.Println("[dctest] Done")
}
