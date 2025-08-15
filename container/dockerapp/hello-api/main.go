package main

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"log"
	"net"
	"net/http"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
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
				InsecureSkipVerify: true,
			},
		},
	}
}

// KMSService encapsulates KMS operations
type KMSService struct {
	client *kms.Client
	keyID  string
}

// NewKMSService creates a new KMS service instance
func NewKMSService(httpClient *http.Client, region, keyID string) (*KMSService, error) {
	cfg, err := config.LoadDefaultConfig(context.TODO(),
		config.WithRegion(region),
		config.WithHTTPClient(httpClient),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config: %w", err)
	}

	return &KMSService{
		client: kms.NewFromConfig(cfg),
		keyID:  keyID,
	}, nil
}

// EncryptText encrypts plaintext using KMS
func (s *KMSService) EncryptText(ctx context.Context, plaintext string) (string, error) {
	input := &kms.EncryptInput{
		KeyId:     aws.String(s.keyID),
		Plaintext: []byte(plaintext),
	}

	result, err := s.client.Encrypt(ctx, input)
	if err != nil {
		return "", fmt.Errorf("encryption failed: %w", err)
	}

	return base64.StdEncoding.EncodeToString(result.CiphertextBlob), nil
}

func main() {
	// Configuration
	region := "ap-southeast-1"      // Change to your region
	keyID := "alias/your-key-alias" // Change to your KMS key ID or alias

	// Start the periodic hello message
	go printHelloPeriodically()

	// Create HTTP client for VSOCK proxy
	httpClient := NewVSOCKHTTPClient(3, 8000)

	// Initialize KMS service
	kmsService, err := NewKMSService(httpClient, region, keyID)
	if err != nil {
		log.Fatalf("Failed to create KMS service: %v", err)
	}

	// Define routes
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			fmt.Fprint(w, "KMS Enclave Service is running")
		} else {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	})

	http.HandleFunc("/encrypt", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		plaintext := r.FormValue("text")
		if plaintext == "" {
			http.Error(w, "Missing 'text' parameter", http.StatusBadRequest)
			return
		}

		ciphertext, err := kmsService.EncryptText(r.Context(), plaintext)
		if err != nil {
			log.Printf("Encryption error: %v", err)
			http.Error(w, fmt.Sprintf("Encryption failed: %v", err), http.StatusInternalServerError)
			return
		}

		log.Printf("Successfully encrypted text (length: %d)", len(plaintext))
		fmt.Fprintf(w, "Ciphertext: %s", ciphertext)
	})

	// Create VSOCK listener
	port := uint32(8080)
	listener, err := vsockListener(port)
	if err != nil {
		log.Fatalf("Failed to create VSOCK listener: %v", err)
	}
	defer listener.Close()

	log.Printf("Server starting on VSOCK port %d...", port)
	log.Printf("KMS Key ID: %s", keyID)
	log.Printf("Available endpoints:")
	log.Printf("  GET  / - Health check")
	log.Printf("  POST /encrypt?text=<text> - Encrypt text")

	if err := http.Serve(listener, nil); err != nil {
		log.Fatalf("Server failed to start: %v", err)
	}
}
