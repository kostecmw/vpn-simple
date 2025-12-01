package crypto

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"

	"golang.org/x/crypto/chacha20poly1305"
)

// GenerateKey generates a new random 32-byte encryption key suitable for ChaCha20-Poly1305
func GenerateKey() ([]byte, error) {
	key := make([]byte, chacha20poly1305.KeySize)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("failed to generate random key: %w", err)
	}
	return key, nil
}

// ParseKey validates and decodes a hex-encoded encryption key
func ParseKey(hexKey string) ([]byte, error) {
	// Remove any whitespace
	hexKey = strings.TrimSpace(hexKey)

	// Check length (64 hex chars = 32 bytes)
	expectedLen := chacha20poly1305.KeySize * 2 // 2 hex chars per byte
	if len(hexKey) != expectedLen {
		return nil, fmt.Errorf("key must be exactly %d hex characters (%d bytes), got %d characters",
			expectedLen, chacha20poly1305.KeySize, len(hexKey))
	}

	// Decode hex string to bytes
	key, err := hex.DecodeString(hexKey)
	if err != nil {
		return nil, fmt.Errorf("key must be a valid hexadecimal string: %w", err)
	}

	// Double-check length after decoding
	if len(key) != chacha20poly1305.KeySize {
		return nil, fmt.Errorf("decoded key must be %d bytes, got %d bytes",
			chacha20poly1305.KeySize, len(key))
	}

	return key, nil
}

// ValidateKey checks if a key is valid for use with ChaCha20-Poly1305
func ValidateKey(key []byte) error {
	if len(key) != chacha20poly1305.KeySize {
		return fmt.Errorf("key must be %d bytes, got %d bytes",
			chacha20poly1305.KeySize, len(key))
	}
	return nil
}

// KeyToHex converts a key to its hexadecimal string representation
func KeyToHex(key []byte) string {
	return hex.EncodeToString(key)
}
