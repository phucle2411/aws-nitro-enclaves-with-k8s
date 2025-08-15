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
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/mdlayher/vsock"
)

// Constants
const (
	ParentCID      = 3
	KMSPort        = 8000
	IMDSPort       = 8001
	EnclavePort    = 8080
	IMDSTokenTTL   = "21600" // 6 hours
	RequestTimeout = 30 * time.Second
)

// Periodic status messages
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

// VSOCK listener setup
func vsockListener(port uint32) (net.Listener, error) {
	return vsock.Listen(port, nil)
}

// HTTP client with VSOCK proxy support
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
		Timeout: RequestTimeout,
	}
}

// IMDSv2 Client implementation
type IMDSv2Client struct {
	client      *http.Client
	token       string
	tokenExpiry time.Time
}

func NewIMDSv2Client(parentCID, parentPort uint32) *IMDSv2Client {
	return &IMDSv2Client{
		client: NewProxyHTTPClient(parentCID, parentPort),
	}
}

func (i *IMDSv2Client) getToken(ctx context.Context) (string, error) {
	if time.Now().Before(i.tokenExpiry) && i.token != "" {
		return i.token, nil
	}

	req, err := http.NewRequest("PUT", "http://169.254.169.254/latest/api/token", nil)
	if err != nil {
		return "", fmt.Errorf("failed to create token request: %w", err)
	}
	req.Header.Add("X-aws-ec2-metadata-token-ttl-seconds", IMDSTokenTTL)

	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	resp, err := i.client.Do(req.WithContext(ctx))
	if err != nil {
		return "", fmt.Errorf("failed to get IMDSv2 token: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	token, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read token: %w", err)
	}

	i.token = string(token)
	i.tokenExpiry = time.Now().Add(6 * time.Hour)
	return i.token, nil
}

func (i *IMDSv2Client) GetWithContext(ctx context.Context, path string) (*http.Response, error) {
	token, err := i.getToken(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get session token: %w", err)
	}

	req, err := http.NewRequest("GET", "http://169.254.169.254"+path, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Add("X-aws-ec2-metadata-token", token)

	return i.client.Do(req.WithContext(ctx))
}

// KMS Service implementation
type KMSService struct {
	client *kms.Client
	keyID  string
}

func NewKMSService(kmsClient *http.Client, imdsClient *IMDSv2Client, region, keyID string) (*KMSService, error) {
	credProvider := aws.CredentialsProviderFunc(func(ctx context.Context) (aws.Credentials, error) {
		return getEnclaveCredentials(ctx, imdsClient)
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

func getEnclaveCredentials(ctx context.Context, imdsClient *IMDSv2Client) (aws.Credentials, error) {
	resp, err := imdsClient.GetWithContext(ctx, "/latest/meta-data/iam/security-credentials/")
	if err != nil {
		return aws.Credentials{}, fmt.Errorf("failed to get IAM role: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return aws.Credentials{}, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	roleName, err := io.ReadAll(resp.Body)
	if err != nil {
		return aws.Credentials{}, fmt.Errorf("failed to read role name: %w", err)
	}

	credsResp, err := imdsClient.GetWithContext(ctx,
		fmt.Sprintf("/latest/meta-data/iam/security-credentials/%s", strings.TrimSpace(string(roleName))))
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

	expiration, err := time.Parse(time.RFC3339, creds.Expiration)
	if err != nil {
		return aws.Credentials{}, fmt.Errorf("failed to parse expiration: %w", err)
	}

	return aws.Credentials{
		AccessKeyID:     creds.AccessKeyID,
		SecretAccessKey: creds.SecretAccessKey,
		SessionToken:    creds.Token,
		CanExpire:       true,
		Expires:         expiration,
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
	keyID := "alias/enclave-tmp" // Replace with your KMS key

	// Create clients
	kmsClient := NewProxyHTTPClient(ParentCID, KMSPort)
	imdsClient := NewIMDSv2Client(ParentCID, IMDSPort)

	// Initialize services
	kmsService, err := NewKMSService(kmsClient, imdsClient, region, keyID)
	if err != nil {
		log.Fatalf("Failed to create KMS service: %v", err)
	}

	// Start background tasks
	go printHelloPeriodically()

	// HTTP endpoints
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			fmt.Fprint(w, "Enclave KMS Service is running")
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

		log.Printf("Successfully encrypted %d bytes", len(text))
		fmt.Fprintf(w, "Ciphertext: %s", ciphertext)
	})

	// Start server
	listener, err := vsockListener(EnclavePort)
	if err != nil {
		log.Fatalf("Failed to create VSOCK listener: %v", err)
	}
	defer listener.Close()

	log.Printf("Server running on VSOCK port %d", EnclavePort)
	log.Printf("KMS Key: %s in %s", keyID, region)
	log.Printf("Endpoints:")
	log.Printf("  GET  / - Health check")
	log.Printf("  POST /encrypt?text=<text> - Encrypt data")

	if err := http.Serve(listener, nil); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}
