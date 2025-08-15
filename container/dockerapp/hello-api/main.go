package main

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
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

func vsockListener(port uint32) (net.Listener, error) {
	return vsock.Listen(port, nil)
}

// NewProxyHTTPClient creates an HTTP client that routes through VSOCK proxy
func NewProxyHTTPClient(parentCID, parentPort uint32) *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return vsock.Dial(parentCID, parentPort, nil)
			},
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
		Timeout: 30 * time.Second,
	}
}

type KMSService struct {
	client *kms.Client
	keyID  string
}

func NewKMSService(kmsClient *http.Client, imdsClient *http.Client, region, keyID string) (*KMSService, error) {
	// Custom credential provider for enclaves
	credProvider := aws.CredentialsProviderFunc(func(ctx context.Context) (aws.Credentials, error) {
		return getEnclaveCredentials(imdsClient)
	})

	cfg, err := config.LoadDefaultConfig(context.TODO(),
		config.WithRegion(region),
		config.WithHTTPClient(kmsClient),
		config.WithCredentialsProvider(aws.NewCredentialsCache(credProvider)),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config: %w", err)
	}

	return &KMSService{
		client: kms.NewFromConfig(cfg),
		keyID:  keyID,
	}, nil
}

func getEnclaveCredentials(client *http.Client) (aws.Credentials, error) {
	// Get IAM role name
	resp, err := client.Get("http://169.254.169.254/latest/meta-data/iam/security-credentials/")
	if err != nil {
		return aws.Credentials{}, fmt.Errorf("failed to get IAM role: %w", err)
	}
	defer resp.Body.Close()

	roleName, err := io.ReadAll(resp.Body)
	if err != nil {
		return aws.Credentials{}, fmt.Errorf("failed to read role name: %w", err)
	}

	// Get temporary credentials
	credsResp, err := client.Get(fmt.Sprintf("http://169.254.169.254/latest/meta-data/iam/security-credentials/%s", string(roleName)))
	if err != nil {
		return aws.Credentials{}, fmt.Errorf("failed to get credentials: %w", err)
	}
	defer credsResp.Body.Close()

	var creds struct {
		AccessKeyID     string `json:"AccessKeyId"`
		SecretAccessKey string `json:"SecretAccessKey"`
		Token           string `json:"Token"`
		Expiration      string `json:"Expiration"`
	}
	if err := json.NewDecoder(credsResp.Body).Decode(&creds); err != nil {
		return aws.Credentials{}, fmt.Errorf("failed to decode credentials: %w", err)
	}

	return aws.Credentials{
		AccessKeyID:     creds.AccessKeyID,
		SecretAccessKey: creds.SecretAccessKey,
		SessionToken:    creds.Token,
		CanExpire:       true,
		Expires:         time.Now().Add(30 * time.Minute), // Approximate expiration
	}, nil
}

func (s *KMSService) EncryptText(ctx context.Context, text string) (string, error) {
	input := &kms.EncryptInput{
		KeyId:     aws.String(s.keyID),
		Plaintext: []byte(text),
	}

	result, err := s.client.Encrypt(ctx, input)
	if err != nil {
		return "", fmt.Errorf("encryption failed: %w", err)
	}

	return base64.StdEncoding.EncodeToString(result.CiphertextBlob), nil
}

func main() {
	// Configuration
	region := "ap-southeast-1"
	keyID := "alias/enclave-tmp" // Replace with your KMS key ID or alias

	// Create clients for different proxies
	kmsClient := NewProxyHTTPClient(3, 8000)  // For KMS traffic (to kms.ap-southeast-1.amazonaws.com)
	imdsClient := NewProxyHTTPClient(3, 8001) // For IMDS traffic (to 169.254.169.254)

	// Initialize KMS service
	kmsService, err := NewKMSService(kmsClient, imdsClient, region, keyID)
	if err != nil {
		log.Fatalf("Failed to create KMS service: %v", err)
	}

	// Start periodic messages
	go printHelloPeriodically()

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

		text := r.FormValue("text")
		if text == "" {
			http.Error(w, "Missing 'text' parameter", http.StatusBadRequest)
			return
		}

		ciphertext, err := kmsService.EncryptText(r.Context(), text)
		if err != nil {
			log.Printf("Encryption error: %v", err)
			http.Error(w, fmt.Sprintf("Encryption failed: %v", err), http.StatusInternalServerError)
			return
		}

		log.Printf("Successfully encrypted text (length: %d)", len(text))
		fmt.Fprintf(w, "Ciphertext: %s", ciphertext)
	})

	// Start VSOCK server
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
