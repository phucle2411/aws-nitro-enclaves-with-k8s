package main

import (
	"encoding/base64"
	"encoding/json"
	"log"
	"net/http"
	"os"

	ne "github.com/aws/aws-nitro-enclaves-sdk-go/pkg/aws"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/kms"
)

type encryptRequest struct {
	KeyID     string `json:"key_id"`
	Plaintext string `json:"plaintext"`
}

type encryptResponse struct {
	Ciphertext string `json:"ciphertext"`
}

type decryptRequest struct {
	Ciphertext string `json:"ciphertext"`
}

type decryptResponse struct {
	Plaintext string `json:"plaintext"`
}

var kmsClient *kms.KMS

func encryptHandler(w http.ResponseWriter, r *http.Request) {
	var req encryptRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	input := &kms.EncryptInput{KeyId: aws.String(req.KeyID), Plaintext: []byte(req.Plaintext)}
	output, err := kmsClient.Encrypt(input)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	resp := encryptResponse{Ciphertext: base64.StdEncoding.EncodeToString(output.CiphertextBlob)}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func decryptHandler(w http.ResponseWriter, r *http.Request) {
	var req decryptRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	blob, err := base64.StdEncoding.DecodeString(req.Ciphertext)
	if err != nil {
		http.Error(w, "invalid ciphertext", http.StatusBadRequest)
		return
	}
	output, err := kmsClient.Decrypt(&kms.DecryptInput{CiphertextBlob: blob})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	resp := decryptResponse{Plaintext: string(output.Plaintext)}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func main() {
	region := os.Getenv("AWS_REGION")
	if region == "" {
		log.Fatal("AWS_REGION must be set")
	}
	sess, err := ne.NewSession(&aws.Config{Region: aws.String(region)})
	if err != nil {
		log.Fatalf("failed to create session: %v", err)
	}
	kmsClient = kms.New(sess)

	http.HandleFunc("/api/encrypt", encryptHandler)
	http.HandleFunc("/api/decrypt", decryptHandler)
	log.Printf("listening on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
