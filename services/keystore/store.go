package keystore

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io"
	"os"
)

func Encrypt(data []byte) ([]byte, error) {
	raw := os.Getenv("HSM_MASTER_KEY")
	if raw == "" {
		return []byte{}, errors.New("HSM_MASTER_KEY not set")
	}

	key := sha256.Sum256([]byte(raw))
	defer clearKey(key[:])

	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	iv := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}

	return gcm.Seal(iv, iv, data, nil), nil
}

func Decrypt(ciphertext []byte) ([]byte, error) {
	raw := os.Getenv("HSM_MASTER_KEY")
	if raw == "" {
		return []byte{}, errors.New("HSM_MASTER_KEY not set")
	}

	key := sha256.Sum256([]byte(raw))
	defer clearKey(key[:])

	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	if len(ciphertext) < gcm.NonceSize() {
		return nil, errors.New("ciphertext too short")
	}

	iv, ct := ciphertext[:gcm.NonceSize()], ciphertext[gcm.NonceSize():]
	return gcm.Open(nil, iv, ct, nil)
}

func clearKey(key []byte) {
	for i := range key {
		key[i] = 0
	}
}
