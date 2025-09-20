package pkg

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io"

	"golang.org/x/crypto/hkdf"
)

// HMAC_SHA256
func ComputeHMAC(key, data []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write(data)
	return m.Sum(nil)
}

// derive 32-byte AEAD key from psk + clientNonce + serverNonce
func deriveSessionAEAD(psk, clientNonce, serverNonce []byte) (cipher.AEAD, error) {
	ikm := append(psk, clientNonce...)
	ikm = append(ikm, serverNonce...)
	h := hkdf.New(sha256.New, ikm, nil, []byte("faketcp-session"))
	key := make([]byte, 32)
	if _, err := io.ReadFull(h, key); err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// Encrypt: return nonce||ciphertext
func EncryptWithAEAD(aead cipher.AEAD, plain []byte) ([]byte, error) {
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	ct := aead.Seal(nil, nonce, plain, nil)
	return append(nonce, ct...), nil
}

// Decrypt expects nonce||ciphertext
func DecryptWithAEAD(aead cipher.AEAD, in []byte) ([]byte, error) {
	ns := aead.NonceSize()
	if len(in) < ns {
		return nil, errors.New("input too short for nonce")
	}
	nonce := in[:ns]
	ct := in[ns:]
	return aead.Open(nil, nonce, ct, nil)
}

// generateRandomBytes
func RandBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := io.ReadFull(rand.Reader, b)
	return b, err
}
