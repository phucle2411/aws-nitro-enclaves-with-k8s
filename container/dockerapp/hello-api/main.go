package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"time"

	"github.com/mdlayher/vsock"
)

func printHelloPeriodically() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			log.Println("hello from enclave")
		}
	}
}

// vsockListener creates a net.Listener using VSOCK
func vsockListener(port uint32) (net.Listener, error) {
	return vsock.Listen(port, nil)
}

// NewVSOCKHTTPClient creates an HTTP client that routes through VSOCK proxy
func NewVSOCKHTTPClient(parentCID, parentPort uint32) *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return vsock.Dial(parentCID, parentPort, nil)
			},
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, // Proxy handles TLS verification
			},
		},
	}
}

func makeKMSRequest(client *http.Client) (string, error) {
	resp, err := client.Get("https://kms.ap-southeast-1.amazonaws.com")
	if err != nil {
		return "", fmt.Errorf("KMS request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response body: %w", err)
	}

	return fmt.Sprintf("KMS Response - Status: %s, Body: %s", resp.Status, string(body)), nil
}

func main() {
	// Start the periodic hello message in a goroutine
	go printHelloPeriodically()

	// Create HTTP client for KMS via VSOCK proxy
	kmsClient := NewVSOCKHTTPClient(3, 8000) // Parent CID 3, port 8000

	// Define the route and handler
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			// Make request to KMS through VSOCK proxy
			result, err := makeKMSRequest(kmsClient)
			if err != nil {
				log.Printf("KMS request error: %v", err)
				http.Error(w, fmt.Sprintf("KMS request failed: %v", err), http.StatusInternalServerError)
				return
			}

			// Print result to server logs
			log.Println(result)

			// Return simplified response to client
			fmt.Fprint(w, "OK (KMS request completed - check server logs for details)")
		} else {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	})

	// Create VSOCK listener
	port := uint32(8080) // VSOCK port
	listener, err := vsockListener(port)
	if err != nil {
		log.Fatalf("Failed to create VSOCK listener: %v", err)
	}
	defer listener.Close()

	log.Printf("Server starting on VSOCK port %d...", port)
	log.Printf("VSOCK proxy configured to parent CID 3 port 8000")

	// Start HTTP server with our VSOCK listener
	if err := http.Serve(listener, nil); err != nil {
		log.Fatalf("Server failed to start: %v", err)
	}
}
