package main

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/smithy-go/middleware"
	"github.com/mdlayher/vsock"
)

// Constants for VSOCK CIDs
const (
	// VMADDR_CID_HOST is the parent/host CID (typically 3 for Nitro Enclaves)
	VMADDR_CID_HOST = 3
	// VMADDR_CID_ANY means any CID
	VMADDR_CID_ANY = 0xFFFFFFFF // -1 in uint32
)

// VSockHTTPClient creates an HTTP client that routes through VSOCK
type VSockHTTPClient struct {
	parentCID  uint32
	parentPort uint32
}

// NewVSockHTTPClient creates a new VSOCK-based HTTP client
func NewVSockHTTPClient(parentCID, parentPort uint32) *VSockHTTPClient {
	return &VSockHTTPClient{
		parentCID:  parentCID,
		parentPort: parentPort,
	}
}

// Do implements the HTTPClient interface for AWS SDK
func (c *VSockHTTPClient) Do(req *http.Request) (*http.Response, error) {
	// Connect through VSOCK
	conn, err := vsock.Dial(c.parentCID, c.parentPort, nil)
	if err != nil {
		return nil, fmt.Errorf("vsock dial failed: %w", err)
	}

	// Create a custom transport using the VSOCK connection
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			// Return the existing VSOCK connection
			return conn, nil
		},
		// Skip TLS verification for demo (configure properly in production)
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   30 * time.Second,
	}

	return client.Do(req)
}

// KMSService wraps AWS KMS client with enclave support
type KMSService struct {
	client *kms.Client
	keyID  string
}

// NewKMSService creates a new KMS service with VSOCK support
func NewKMSService(region, keyID string) (*KMSService, error) {
	// Create custom HTTP client that uses VSOCK
	vsockClient := NewVSockHTTPClient(3, 8000) // Parent CID 3, port 8000

	// Load default config with custom HTTP client
	cfg, err := config.LoadDefaultConfig(context.TODO(),
		config.WithRegion(region),
		config.WithHTTPClient(vsockClient),
		// Override the endpoint to go through our proxy
		config.WithEndpointResolverWithOptions(aws.EndpointResolverWithOptionsFunc(
			func(service, region string, options ...interface{}) (aws.Endpoint, error) {
				if service == kms.ServiceID {
					return aws.Endpoint{
						URL: fmt.Sprintf("https://kms.%s.amazonaws.com", region),
					}, nil
				}
				return aws.Endpoint{}, fmt.Errorf("unknown service: %s", service)
			}),
		),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to load config: %w", err)
	}

	// Create KMS client with custom middleware for attestation
	kmsClient := kms.NewFromConfig(cfg, func(o *kms.Options) {
		// Add custom middleware to include attestation
		o.APIOptions = append(o.APIOptions, func(stack *middleware.Stack) error {
			return stack.Initialize.Add(middleware.InitializeMiddlewareFunc(
				"AddAttestation",
				func(ctx context.Context, in middleware.InitializeInput, next middleware.InitializeHandler) (
					out middleware.InitializeOutput, metadata middleware.Metadata, err error) {
					// Add attestation document to the request if available
					if attestation, err := getAttestationDocument(); err == nil && attestation != "" {
						// The attestation would be added to the request context
						// This is simplified - actual implementation would depend on KMS API
						ctx = context.WithValue(ctx, "attestation", attestation)
					}
					return next.HandleInitialize(ctx, in)
				}), middleware.Before)
		})
	})

	return &KMSService{
		client: kmsClient,
		keyID:  keyID,
	}, nil
}

// getAttestationDocument gets the attestation document from the Nitro Secure Module
func getAttestationDocument() (string, error) {
	cmd := exec.Command("/app/get-attestation-document")
	output, err := cmd.Output()
	if err != nil {
		log.Printf("Warning: Could not get attestation document: %v", err)
		return "", nil
	}
	return base64.StdEncoding.EncodeToString(output), nil
}

// Encrypt encrypts plaintext using KMS
func (s *KMSService) Encrypt(ctx context.Context, plaintext string) (string, error) {
	// Get attestation document
	attestation, _ := getAttestationDocument()

	input := &kms.EncryptInput{
		KeyId:     aws.String(s.keyID),
		Plaintext: []byte(plaintext),
	}

	// Add attestation if available
	if attestation != "" {
		input.EncryptionContext = map[string]string{
			"aws:nitro-enclave:attestation": attestation,
		}
		// Note: In production, you'd use the Recipient field with proper attestation structure
		// This is simplified for demonstration
	}

	result, err := s.client.Encrypt(ctx, input)
	if err != nil {
		return "", fmt.Errorf("KMS encrypt failed: %w", err)
	}

	// Return base64 encoded ciphertext
	return base64.StdEncoding.EncodeToString(result.CiphertextBlob), nil
}

// Decrypt decrypts ciphertext using KMS
func (s *KMSService) Decrypt(ctx context.Context, ciphertextBlob string) (string, error) {
	// Decode base64 ciphertext
	ciphertext, err := base64.StdEncoding.DecodeString(ciphertextBlob)
	if err != nil {
		return "", fmt.Errorf("failed to decode ciphertext: %w", err)
	}

	// Get attestation document
	attestation, _ := getAttestationDocument()

	input := &kms.DecryptInput{
		CiphertextBlob: ciphertext,
		KeyId:          aws.String(s.keyID),
	}

	// Add attestation if available
	if attestation != "" {
		input.EncryptionContext = map[string]string{
			"aws:nitro-enclave:attestation": attestation,
		}
		// Note: In production, you'd use the Recipient field with proper attestation structure
	}

	result, err := s.client.Decrypt(ctx, input)
	if err != nil {
		return "", fmt.Errorf("KMS decrypt failed: %w", err)
	}

	return string(result.Plaintext), nil
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

// getLocalCID attempts to get the local CID using system calls
func getLocalCID() (uint32, error) {
	// Try to read from /proc/self/vsock if available
	data, err := os.ReadFile("/proc/self/vsock")
	if err == nil {
		var cid uint32
		_, err = fmt.Sscanf(string(data), "%d", &cid)
		if err == nil {
			return cid, nil
		}
	}

	// Alternative: Try to create a listener and check its address
	// This might not work in all environments
	testListener, err := vsock.Listen(0, nil)
	if err != nil {
		return 0, fmt.Errorf("cannot determine local CID: %v", err)
	}
	defer testListener.Close()

	// Try to extract CID from the listener address
	if addr, ok := testListener.Addr().(*vsock.Addr); ok {
		return addr.ContextID, nil
	}

	return 0, fmt.Errorf("cannot determine local CID from listener")
}

// logVSockInfo logs VSOCK-related information
func logVSockInfo() {
	log.Println("=== VSOCK Information ===")

	// Try to get local CID using our custom function
	localCID, err := getLocalCID()
	if err != nil {
		log.Printf("Could not determine local CID: %v", err)
		log.Printf("Note: The enclave CID will be assigned by the hypervisor")
	} else {
		log.Printf("Local CID (this enclave): %d", localCID)
	}

	// Log parent CID (always 3 for Nitro Enclaves)
	log.Printf("Parent CID (host): %d (standard for Nitro Enclaves)", VMADDR_CID_HOST)

	// Test connectivity to parent
	log.Printf("Testing connection to parent VSOCK proxy...")
	testConn, err := vsock.Dial(VMADDR_CID_HOST, 8000, nil)
	if err != nil {
		log.Printf("⚠️  Cannot connect to parent VSOCK proxy on CID %d port 8000: %v", VMADDR_CID_HOST, err)
		log.Printf("   Make sure the VSOCK proxy is running on the parent instance")
	} else {
		testConn.Close()
		log.Printf("✓ Successfully tested connection to parent VSOCK proxy")
	}

	log.Println("========================")
}

func main() {
	// Initial startup log
	log.Println("=== Enclave Application Starting ===")
	log.Printf("Time: %s", time.Now().Format(time.RFC3339))

	// Log VSOCK information early
	logVSockInfo()

	// Get configuration from environment
	region := os.Getenv("AWS_REGION")
	if region == "" {
		region = "ap-southeast-1"
	}
	log.Printf("AWS Region: %s", region)

	keyID := os.Getenv("KMS_KEY_ID")
	if keyID == "" {
		log.Fatal("KMS_KEY_ID environment variable is required")
	}
	log.Printf("KMS Key ID: %s", keyID)

	// Create VSOCK listener first to ensure VSOCK is working
	port := uint32(8080) // VSOCK port
	log.Printf("Creating VSOCK listener on port %d...", port)

	listener, err := vsockListener(port)
	if err != nil {
		log.Printf("Failed to create VSOCK listener on port %d: %v", port, err)
		log.Printf("Error type: %T", err)

		// Try alternate port
		altPort := uint32(8081)
		log.Printf("Trying alternate port %d...", altPort)
		listener, err = vsockListener(altPort)
		if err != nil {
			log.Fatalf("Failed to create VSOCK listener on alternate port %d: %v", altPort, err)
		}
		port = altPort
	}
	defer listener.Close()

	log.Printf("✓ Successfully created VSOCK listener on port %d", port)

	// Log listener address info
	if addr, ok := listener.Addr().(*vsock.Addr); ok {
		log.Printf("VSOCK Listener Address - CID: %d, Port: %d", addr.ContextID, addr.Port)
	}

	// Initialize KMS service
	log.Println("\nInitializing KMS service...")
	kmsService, err := NewKMSService(region, keyID)
	if err != nil {
		log.Fatalf("Failed to initialize KMS service: %v", err)
	}
	log.Println("✓ KMS service initialized")

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

		ctx := context.Background()
		ciphertext, err := kmsService.Encrypt(ctx, req.Plaintext)
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

		ctx := context.Background()
		plaintext, err := kmsService.Decrypt(ctx, req.Ciphertext)
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

	log.Println("\n=== Server Configuration ===")
	log.Printf("Server starting on VSOCK port %d...", port)
	log.Printf("Using KMS in region: %s", region)
	log.Printf("Parent CID: %d (connect here for KMS proxy)", VMADDR_CID_HOST)
	log.Printf("Endpoints available:")
	log.Printf("  GET  / - Health check")
	log.Printf("  POST /encrypt - Encrypt plaintext")
	log.Printf("  POST /decrypt - Decrypt ciphertext")
	log.Println("===========================\n")

	// Start HTTP server with our VSOCK listener
	log.Println("Starting HTTP server...")
	if err := http.Serve(listener, nil); err != nil {
		log.Fatalf("Server failed to start: %v", err)
	}
}
