package keystore

import (
	"errors"
	"time"
)

type KeyVersion struct {
	PublicKeyPEM string
	CreatedAt    time.Time
	Version      int32
}

type Metadata struct {
	Algorithm string        `json:"algorithm"`
	CreatedAt time.Time     `json:"created_at"`
	UpdatedAt time.Time     `json:"updated_at"`
	Versions  []*KeyVersion `json:"versions"`
}

const ECDSA_P256 = "ECDSA_P256"

var (
	ErrorKeyNotFound       = errors.New("Key Not Found")
	ErrorInvalidKeyVersion = errors.New("Invalid Key Version")
)

type IKeyStoreManager interface {
	Encrypt(plaintext []byte) ([]byte, error)
	Decrypt(ciphertext []byte) ([]byte, error)
}

type SerializedMetadata struct {
	Kid       string              `json:"kid"`
	Algorithm string              `json:"algorithm"`
	Versions  []SerializedVersion `json:"versions"`
}

type SerializedVersion struct {
	Version      int       `json:"version"`
	CreatedAt    time.Time `json:"created_at"`
	PublicKeyPEM string    `json:"public_key_pem"`
}

type SerializedVault struct {
	Kid        string `json:"kid"`
	Version    int32  `json:"version"`
	PrivKeyDER []byte `json:"priv_key_der"`
}

type serializedKeyStore struct {
	Metadata []SerializedMetadata `json:"metadata"`
	Vault    []SerializedVault    `json:"vault"`
}
