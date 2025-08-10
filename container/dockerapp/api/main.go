package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"
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

var gcm cipher.AEAD

func encryptHandler(w http.ResponseWriter, r *http.Request) {
	var req encryptRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		http.Error(w, "failed to generate nonce", http.StatusInternalServerError)
		return
	}
	ciphertext := gcm.Seal(nonce, nonce, []byte(req.Plaintext), nil)
	resp := encryptResponse{Ciphertext: base64.StdEncoding.EncodeToString(ciphertext)}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func decryptHandler(w http.ResponseWriter, r *http.Request) {
	var req decryptRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	data, err := base64.StdEncoding.DecodeString(req.Ciphertext)
	if err != nil {
		http.Error(w, "invalid ciphertext", http.StatusBadRequest)
		return
	}
	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		http.Error(w, "invalid ciphertext", http.StatusBadRequest)
		return
	}
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		http.Error(w, "decryption failed", http.StatusInternalServerError)
		return
	}
	resp := decryptResponse{Plaintext: string(plaintext)}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func main() {
	keyB64 := os.Getenv("API_KEY")
	if keyB64 == "" {
		log.Fatal("API_KEY must be set")
	}
	key, err := base64.StdEncoding.DecodeString(keyB64)
	if err != nil {
		log.Fatalf("invalid API_KEY: %v", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		log.Fatalf("failed to create cipher: %v", err)
	}
	gcm, err = cipher.NewGCM(block)
	if err != nil {
		log.Fatalf("failed to create gcm: %v", err)
	}

	http.HandleFunc("/api/encrypt", encryptHandler)
	http.HandleFunc("/api/decrypt", decryptHandler)
	log.Printf("listening on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
