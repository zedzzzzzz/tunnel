package pkg

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func TestDeriveSessionAEAD_EncryptDecrypt(t *testing.T) {
	psk := []byte("super-secret-pre-shared-key")
	clientNonce := make([]byte, 16)
	serverNonce := make([]byte, 16)
	_, _ = rand.Read(clientNonce)
	_, _ = rand.Read(serverNonce)
	aead, err := deriveSessionAEAD(psk, clientNonce, serverNonce)
	if err != nil {
		t.Fatalf("deriveSessionAEAD failed: %v", err)
	}
	nonce := make([]byte, aead.NonceSize())
	_, _ = rand.Read(nonce)
	plaintext := []byte("hello faketcp with encryption")
	ciphertext := aead.Seal(nil, nonce, plaintext, nil)
	got, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		t.Fatalf("decrypt failed: %v", err)
	}
	if !bytes.Equal(plaintext, got) {
		t.Fatalf("mismatch: got=%q want=%q", got, plaintext)
	}
}
