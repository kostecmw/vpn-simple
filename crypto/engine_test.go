package crypto

import (
	"bytes"
	"strings"
	"testing"
)

func TestNewEngine(t *testing.T) {
	tests := []struct {
		name    string
		keySize int
		wantErr bool
	}{
		{"Valid 32-byte key", 32, false},
		{"Invalid 16-byte key", 16, true},
		{"Invalid 64-byte key", 64, true},
		{"Invalid 0-byte key", 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key := make([]byte, tt.keySize)
			_, err := NewEngine(key)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewEngine() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestEncryptDecrypt(t *testing.T) {
	key := make([]byte, 32)
	engine, err := NewEngine(key)
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}

	tests := []struct {
		name      string
		plaintext []byte
	}{
		{"Empty message", []byte{}},
		{"Short message", []byte("Hello, World!")},
		{"Long message", []byte(strings.Repeat("The quick brown fox jumps over the lazy dog. ", 100))},
		{"Binary data", []byte{0x00, 0x01, 0x02, 0xFF, 0xFE, 0xFD}},
		{"Unicode", []byte("Hello 世界 🌍")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Encrypt
			ciphertext, err := engine.Encrypt(tt.plaintext)
			if err != nil {
				t.Fatalf("Encrypt() error = %v", err)
			}

			// Check overhead
			expectedLen := len(tt.plaintext) + engine.Overhead()
			if len(ciphertext) != expectedLen {
				t.Errorf("Ciphertext length = %d, want %d", len(ciphertext), expectedLen)
			}

			// Decrypt
			decrypted, err := engine.Decrypt(ciphertext)
			if err != nil {
				t.Fatalf("Decrypt() error = %v", err)
			}

			// Verify
			if !bytes.Equal(decrypted, tt.plaintext) {
				t.Errorf("Decrypted data doesn't match original")
			}
		})
	}
}

func TestEncryptProducesDifferentCiphertexts(t *testing.T) {
	key := make([]byte, 32)
	engine, _ := NewEngine(key)

	plaintext := []byte("Same message")

	ciphertext1, _ := engine.Encrypt(plaintext)
	ciphertext2, _ := engine.Encrypt(plaintext)

	// Ciphertexts should be different due to random nonce
	if bytes.Equal(ciphertext1, ciphertext2) {
		t.Error("Two encryptions of the same plaintext produced identical ciphertexts")
	}
}

func TestDecryptWithWrongKey(t *testing.T) {
	key1 := make([]byte, 32)
	key2 := make([]byte, 32)
	key2[0] = 1 // Make it different

	engine1, _ := NewEngine(key1)
	engine2, _ := NewEngine(key2)

	plaintext := []byte("Secret message")
	ciphertext, _ := engine1.Encrypt(plaintext)

	// Try to decrypt with wrong key
	_, err := engine2.Decrypt(ciphertext)
	if err == nil {
		t.Error("Decrypt with wrong key should have failed")
	}
}

func TestDecryptTamperedData(t *testing.T) {
	key := make([]byte, 32)
	engine, _ := NewEngine(key)

	plaintext := []byte("Original message")
	ciphertext, _ := engine.Encrypt(plaintext)

	// Tamper with the ciphertext
	if len(ciphertext) > 20 {
		ciphertext[20] ^= 0x01
	}

	// Try to decrypt tampered data
	_, err := engine.Decrypt(ciphertext)
	if err == nil {
		t.Error("Decrypt of tampered data should have failed")
	}
}

func TestDecryptInvalidData(t *testing.T) {
	key := make([]byte, 32)
	engine, _ := NewEngine(key)

	tests := []struct {
		name string
		data []byte
	}{
		{"Too short", []byte{0x01, 0x02}},
		{"Empty", []byte{}},
		{"Just nonce size", make([]byte, engine.NonceSize())},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := engine.Decrypt(tt.data)
			if err == nil {
				t.Error("Decrypt of invalid data should have failed")
			}
		})
	}
}

func TestOverhead(t *testing.T) {
	key := make([]byte, 32)
	engine, _ := NewEngine(key)

	// ChaCha20-Poly1305: 12-byte nonce + 16-byte tag = 28 bytes
	expectedOverhead := 28
	if engine.Overhead() != expectedOverhead {
		t.Errorf("Overhead() = %d, want %d", engine.Overhead(), expectedOverhead)
	}

	if engine.NonceSize() != 12 {
		t.Errorf("NonceSize() = %d, want 12", engine.NonceSize())
	}

	if engine.TagSize() != 16 {
		t.Errorf("TagSize() = %d, want 16", engine.TagSize())
	}
}

func BenchmarkEncrypt(b *testing.B) {
	key := make([]byte, 32)
	engine, _ := NewEngine(key)
	plaintext := make([]byte, 1024) // 1KB

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		engine.Encrypt(plaintext)
	}
}

func BenchmarkDecrypt(b *testing.B) {
	key := make([]byte, 32)
	engine, _ := NewEngine(key)
	plaintext := make([]byte, 1024)
	ciphertext, _ := engine.Encrypt(plaintext)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		engine.Decrypt(ciphertext)
	}
}
