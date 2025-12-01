package crypto

import (
	"strings"
	"testing"
)

func TestGenerateKey(t *testing.T) {
	key1, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}

	if len(key1) != 32 {
		t.Errorf("GenerateKey() length = %d, want 32", len(key1))
	}

	// Generate another key - should be different
	key2, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}

	if string(key1) == string(key2) {
		t.Error("Two generated keys should be different")
	}
}

func TestParseKey(t *testing.T) {
	validKey := strings.Repeat("ab", 32) // 64 hex chars

	tests := []struct {
		name    string
		hexKey  string
		wantErr bool
	}{
		{"Valid key", validKey, false},
		{"Valid key with spaces", " " + validKey + " ", false},
		{"Too short", "abc123", true},
		{"Too long", validKey + "00", true},
		{"Invalid hex chars", strings.Repeat("zz", 32), true},
		{"Empty string", "", true},
		{"Odd length", "abc", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := ParseKey(tt.hexKey)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseKey() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && len(key) != 32 {
				t.Errorf("ParseKey() returned key length = %d, want 32", len(key))
			}
		})
	}
}

func TestValidateKey(t *testing.T) {
	tests := []struct {
		name    string
		keySize int
		wantErr bool
	}{
		{"Valid 32-byte key", 32, false},
		{"Invalid 16-byte key", 16, true},
		{"Invalid 64-byte key", 64, true},
		{"Invalid empty key", 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key := make([]byte, tt.keySize)
			err := ValidateKey(key)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateKey() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestKeyToHex(t *testing.T) {
	key := []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef}
	expected := "0123456789abcdef"

	result := KeyToHex(key)
	if result != expected {
		t.Errorf("KeyToHex() = %s, want %s", result, expected)
	}
}

func TestParseKeyRoundTrip(t *testing.T) {
	// Generate a key
	originalKey, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}

	// Convert to hex
	hexKey := KeyToHex(originalKey)

	// Parse back
	parsedKey, err := ParseKey(hexKey)
	if err != nil {
		t.Fatalf("ParseKey() error = %v", err)
	}

	// Should match original
	if string(originalKey) != string(parsedKey) {
		t.Error("Round-trip key conversion failed")
	}
}
