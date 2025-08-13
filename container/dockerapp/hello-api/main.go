package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"time"

	"github.com/mdlayher/vsock"
)

// KMS request/response structures
type KMSDecryptRequest struct {
	CiphertextBlob string                 `json:"CiphertextBlob"`
	KeyId          string                 `json:"KeyId,omitempty"`
	Recipient      map[string]interface{} `json:"Recipient,omitempty"`
}

type KMSEncryptRequest struct {
	KeyId     string                 `json:"KeyId"`
	Plaintext string                 `json:"Plaintext"`
	Recipient map[string]interface{} `json:"Recipient,omitempty"`
}

type KMSResponse struct {
	Plaintext      string `json:"Plaintext,omitempty"`
	CiphertextBlob string `json:"CiphertextBlob,omitempty"`
	KeyId          string `json:"KeyId,omitempty"`
}

// VSockDialer creates a custom dialer that uses VSOCK to connect to parent
type VSockDialer struct {
	ParentCID  uint32
	ParentPort uint32
}

func (d *VSockDialer) Dial(network, addr string) (net.Conn, error) {
	// Always connect to parent via VSOCK, ignoring the actual address
	return vsock.Dial(d.ParentCID, d.ParentPort, nil)
}

// KMSClient handles KMS operations through VSOCK proxy
type KMSClient struct {
	httpClient *http.Client
	region     string
	keyID      string
}

// NewKMSClient creates a new KMS client that uses VSOCK
func NewKMSClient(region, keyID string) *KMSClient {
	// Create custom transport that uses VSOCK
	vsockDialer := &VSockDialer{
		ParentCID:  3,    // Parent CID (usually 3)
		ParentPort: 8000, // VSOCK port where proxy listens for KMS
	}

	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return vsockDialer.Dial(network, addr)
		},
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true, // For demo; use proper certs in production
		},
	}

	return &KMSClient{
		httpClient: &http.Client{
			Transport: transport,
			Timeout:   30 * time.Second,
		},
		region: region,
		keyID:  keyID,
	}
}

// getAttestationDocument gets the attestation document from the Nitro Secure Module
func getAttestationDocument() (string, error) {
	// In production, this would use the actual NSM interface
	// For now, we'll simulate it
	cmd := exec.Command("/app/get-attestation-document")
	output, err := cmd.Output()
	if err != nil {
		// Return empty for testing
		log.Printf("Warning: Could not get attestation document: %v", err)
		return "", nil
	}
	return base64.StdEncoding.EncodeToString(output), nil
}

// Encrypt encrypts plaintext using KMS
func (c *KMSClient) Encrypt(plaintext string) (string, error) {
	attestation, _ := getAttestationDocument()

	request := KMSEncryptRequest{
		KeyId:     c.keyID,
		Plaintext: base64.StdEncoding.EncodeToString([]byte(plaintext)),
	}

	if attestation != "" {
		request.Recipient = map[string]interface{}{
			"AttestationDocument": attestation,
		}
	}

	body, err := json.Marshal(request)
	if err != nil {
		return "", fmt.Errorf("failed to marshal request: %w", err)
	}

	req, err := http.NewRequest("POST", fmt.Sprintf("https://kms.%s.amazonaws.com/", c.region), bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-amz-json-1.1")
	req.Header.Set("X-Amz-Target", "TrentService.Encrypt")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("KMS error: %s - %s", resp.Status, string(body))
	}

	var kmsResp KMSResponse
	if err := json.NewDecoder(resp.Body).Decode(&kmsResp); err != nil {
		return "", fmt.Errorf("failed to decode response: %w", err)
	}

	return kmsResp.CiphertextBlob, nil
}

// Decrypt decrypts ciphertext using KMS
func (c *KMSClient) Decrypt(ciphertextBlob string) (string, error) {
	attestation, _ := getAttestationDocument()

	request := KMSDecryptRequest{
		CiphertextBlob: ciphertextBlob,
		KeyId:          c.keyID,
	}

	if attestation != "" {
		request.Recipient = map[string]interface{}{
			"AttestationDocument": attestation,
		}
	}

	body, err := json.Marshal(request)
	if err != nil {
		return "", fmt.Errorf("failed to marshal request: %w", err)
	}

	req, err := http.NewRequest("POST", fmt.Sprintf("https://kms.%s.amazonaws.com/", c.region), bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-amz-json-1.1")
	req.Header.Set("X-Amz-Target", "TrentService.Decrypt")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("KMS error: %s - %s", resp.Status, string(body))
	}

	var kmsResp KMSResponse
	if err := json.NewDecoder(resp.Body).Decode(&kmsResp); err != nil {
		return "", fmt.Errorf("failed to decode response: %w", err)
	}

	plaintext, err := base64.StdEncoding.DecodeString(kmsResp.Plaintext)
	if err != nil {
		return "", fmt.Errorf("failed to decode plaintext: %w", err)
	}

	return string(plaintext), nil
}

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
	// Get configuration from environment
	region := os.Getenv("AWS_REGION")
	if region == "" {
		region = "ap-southeast-1"
	}

	keyID := os.Getenv("KMS_KEY_ID")
	if keyID == "" {
		log.Fatal("KMS_KEY_ID environment variable is required")
	}

	// Initialize KMS client
	kmsClient := NewKMSClient(region, keyID)

	// Start the periodic hello message in a goroutine
	go printHelloPeriodically()

	// Health check endpoint
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			fmt.Fprint(w, "OK")
		} else {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	})

	// Encrypt endpoint
	http.HandleFunc("/encrypt", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var req struct {
			Plaintext string `json:"plaintext"`
		}

		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}

		ciphertext, err := kmsClient.Encrypt(req.Plaintext)
		if err != nil {
			log.Printf("Encryption error: %v", err)
			http.Error(w, fmt.Sprintf("Encryption failed: %v", err), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"ciphertext": ciphertext,
		})
	})

	// Decrypt endpoint
	http.HandleFunc("/decrypt", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var req struct {
			Ciphertext string `json:"ciphertext"`
		}

		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}

		plaintext, err := kmsClient.Decrypt(req.Ciphertext)
		if err != nil {
			log.Printf("Decryption error: %v", err)
			http.Error(w, fmt.Sprintf("Decryption failed: %v", err), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"plaintext": plaintext,
		})
	})

	// Create VSOCK listener for incoming connections
	port := uint32(8080) // VSOCK port
	listener, err := vsockListener(port)
	if err != nil {
		log.Fatalf("Failed to create VSOCK listener: %v", err)
	}
	defer listener.Close()

	log.Printf("Server starting on VSOCK port %d...", port)
	log.Printf("Using KMS in region: %s", region)
	log.Printf("Endpoints available:")
	log.Printf("  GET  / - Health check")
	log.Printf("  POST /encrypt - Encrypt plaintext")
	log.Printf("  POST /decrypt - Decrypt ciphertext")

	// Start HTTP server with our VSOCK listener
	if err := http.Serve(listener, nil); err != nil {
		log.Fatalf("Server failed to start: %v", err)
	}
}
