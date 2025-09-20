package pkg

import (
	"bytes"
	"testing"
)

func TestEncryptDecryptAES(t *testing.T) {
	secretKey := []byte("0123456789abcdef") // 16 بایت AES-128
	plaintext := []byte("This is a secret message!")

	ciphertext, err := EncryptAES(secretKey, plaintext)
	if err != nil {
		t.Fatalf("EncryptAES failed: %v", err)
	}

	if bytes.Equal(ciphertext, plaintext) {
		t.Fatalf("Ciphertext should not be equal to plaintext")
	}

	// دیکریپت
	decrypted, err := DecryptAES(secretKey, ciphertext)
	if err != nil {
		t.Fatalf("DecryptAES failed: %v", err)
	}

	if !bytes.Equal(decrypted, plaintext) {
		t.Fatalf("Decrypted text does not match original plaintext.\nGot: %s\nWant: %s", decrypted, plaintext)
	}
}
