package crypto

import (
	"crypto/cipher"
	"crypto/rand"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
)

// Engine handles encryption and decryption using ChaCha20-Poly1305 AEAD
type Engine struct {
	aead cipher.AEAD
}

// NewEngine creates a new crypto engine with the given key
func NewEngine(key []byte) (*Engine, error) {
	if len(key) != chacha20poly1305.KeySize {
		return nil, fmt.Errorf("key must be %d bytes, got %d", chacha20poly1305.KeySize, len(key))
	}

	// Create ChaCha20-Poly1305 AEAD cipher
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	return &Engine{
		aead: aead,
	}, nil
}

// Encrypt encrypts plaintext and returns [nonce || ciphertext || tag]
// The nonce is randomly generated for each encryption operation.
func (e *Engine) Encrypt(plaintext []byte) ([]byte, error) {
	// Generate random nonce (12 bytes for ChaCha20-Poly1305)
	nonce := make([]byte, e.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Encrypt and authenticate
	// Seal appends the ciphertext and tag to dst (starting with nonce)
	ciphertext := e.aead.Seal(nonce, nonce, plaintext, nil)

	return ciphertext, nil
}

// Decrypt decrypts ciphertext of format [nonce || ciphertext || tag]
// Returns an error if the message has been tampered with or the key is wrong.
func (e *Engine) Decrypt(data []byte) ([]byte, error) {
	nonceSize := e.aead.NonceSize()

	// Check minimum length: nonce + at least some data + tag
	if len(data) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short: need at least %d bytes for nonce", nonceSize)
	}

	// Extract nonce and ciphertext
	nonce := data[:nonceSize]
	ciphertext := data[nonceSize:]

	// Decrypt and verify
	plaintext, err := e.aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decryption failed (wrong key or corrupted data): %w", err)
	}

	return plaintext, nil
}

// Overhead returns the number of extra bytes added by encryption
// This includes the nonce size and authentication tag size.
func (e *Engine) Overhead() int {
	// Nonce size (12 bytes) + tag size (16 bytes) = 28 bytes total
	return e.aead.NonceSize() + e.aead.Overhead()
}

// NonceSize returns the size of the nonce in bytes
func (e *Engine) NonceSize() int {
	return e.aead.NonceSize()
}

// TagSize returns the size of the authentication tag in bytes
func (e *Engine) TagSize() int {
	return e.aead.Overhead()
}
