package main

import (
	"fmt"
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

func main() {
	// Start the periodic hello message in a goroutine
	go printHelloPeriodically()

	// Define the route and handler
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			fmt.Fprint(w, "OK")
		} else {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	})

	// Create VSOCK listener instead of TCP
	port := uint32(8080) // VSOCK port
	listener, err := vsockListener(port)
	if err != nil {
		log.Fatalf("Failed to create VSOCK listener: %v", err)
	}
	defer listener.Close()

	log.Printf("Server starting on VSOCK port %d...", port)

	// Start HTTP server with our VSOCK listener
	if err := http.Serve(listener, nil); err != nil {
		log.Fatalf("Server failed to start: %v", err)
	}
}
