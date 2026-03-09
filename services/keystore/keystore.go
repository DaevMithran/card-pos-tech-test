package keystore

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"log"
	"sync"
	"time"

	types "github.com/DaevMithran/mini-hsm/types/hsm/v1"
	"github.com/google/uuid"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type KeyStore struct {
	mu    sync.RWMutex
	keys  map[string]*Metadata
	vault *Vault
}

func NewKeyStore() *KeyStore {
	return &KeyStore{
		keys:  make(map[string]*Metadata),
		vault: &Vault{},
	}
}

func (ks *KeyStore) CreateKey() (*types.KeyMetadata, error) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	// convert pk to der format
	publicKeyDER, err := x509.MarshalPKIXPublicKey(&privKey.PublicKey)
	if err != nil {
		log.Fatal("Failed to marshal public key:", err)
	}

	// convert der to pem
	publicKeyPEM := string(pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyDER,
	}))

	// construct metadata
	createdAt := time.Now().UTC()
	kid := uuid.NewString()
	version := int32(1)

	keyVersion := KeyVersion{
		PublicKeyPEM: publicKeyPEM,
		CreatedAt:    createdAt,
		Version:      version,
	}

	metadata := Metadata{
		Algorithm: ECDSA_P256,
		CreatedAt: time.Now().UTC(),
		Versions:  []*KeyVersion{&keyVersion},
	}

	ks.mu.Lock()
	ks.keys[kid] = &metadata
	ks.vault.Store(kid, version, privKey)
	ks.mu.Unlock()

	return &types.KeyMetadata{
		Kid:       kid,
		Algorithm: metadata.Algorithm,
		CreatedAt: timestamppb.New(createdAt),
		Version:   keyVersion.Version,
	}, nil
}

func (ks *KeyStore) ListKeys() []*types.KeyMetadata {
	ks.mu.RLock()
	defer ks.mu.RUnlock()

	result := []*types.KeyMetadata{}
	for kid, metadata := range ks.keys {
		result = append(result, &types.KeyMetadata{
			Kid:       kid,
			Algorithm: metadata.Algorithm,
			CreatedAt: timestamppb.New(metadata.CreatedAt),
			UpdatedAt: timestamppb.New(metadata.UpdatedAt),
			Version:   int32(len(metadata.Versions)),
		})
	}

	return result
}

func (ks *KeyStore) GetPublicKey(kid string) (string, error) {
	ks.mu.RLock()
	metadata, ok := ks.keys[kid]
	ks.mu.RUnlock()

	if !ok {
		return "", ErrorKeyNotFound
	}

	keyVersion := metadata.Versions[len(metadata.Versions)-1]
	return keyVersion.PublicKeyPEM, nil
}

func (ks *KeyStore) GetPublicKeyVersion(kid string, version int32) (string, error) {
	if version < 1 {
		return "", ErrorInvalidKeyVersion
	}

	ks.mu.RLock()
	metadata, ok := ks.keys[kid]
	ks.mu.RUnlock()

	if version > int32(len(metadata.Versions)) {
		return "", ErrorInvalidKeyVersion
	}

	if !ok {
		return "", ErrorInvalidKeyVersion
	}

	keyVersion := metadata.Versions[version-1]
	return keyVersion.PublicKeyPEM, nil
}

func (ks *KeyStore) RotateKey(kid string) (*types.KeyMetadata, error) {
	ks.mu.Lock()
	defer ks.mu.Unlock()

	metadata, ok := ks.keys[kid]
	if !ok {
		return nil, ErrorKeyNotFound
	}

	version := int32(len(metadata.Versions)) + 1

	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	// convert to der format
	publicKeyDER, err := x509.MarshalPKIXPublicKey(&privKey.PublicKey)
	if err != nil {
		log.Fatal("Failed to marshal public key:", err)
	}

	// convert der to pem
	publicKeyPEM := string(pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyDER,
	}))

	// construct metadata
	createdAt := time.Now().UTC()

	keyVersion := KeyVersion{
		PublicKeyPEM: publicKeyPEM,
		CreatedAt:    createdAt,
		Version:      version,
	}

	metadata.UpdatedAt = createdAt
	metadata.Versions = append(metadata.Versions, &keyVersion)

	// store to the vault
	ks.vault.Store(kid, version, privKey)

	return &types.KeyMetadata{
		Kid:       kid,
		Algorithm: metadata.Algorithm,
		CreatedAt: timestamppb.New(metadata.CreatedAt),
		UpdatedAt: timestamppb.New(metadata.UpdatedAt),
		Version:   keyVersion.Version,
	}, nil
}

// Sign uses the latest keyVersion to create a signature
func (ks *KeyStore) Sign(kid string, data []byte) ([]byte, error) {
	ks.mu.RLock()
	metadata, ok := ks.keys[kid]
	ks.mu.RUnlock()

	if !ok {
		return nil, ErrorKeyNotFound
	}

	sig, err := ks.vault.Sign(kid, ks.GetMetadataVersion(metadata), data)
	return sig, err
}

// Verify signature can verify signature even against a specific key version for backwards compatibility.
func (ks *KeyStore) Verify(kid string, data, sig []byte, version *int) (bool, error) {
	ks.mu.RLock()
	metadata, ok := ks.keys[kid]
	ks.mu.RUnlock()

	if !ok {
		return false, ErrorKeyNotFound
	}

	return ks.vault.Verify(kid, ks.GetMetadataVersion(metadata), data, sig)
}

func (ks *KeyStore) GetMetadataVersion(metadata *Metadata) int32 {
	return int32(len(metadata.Versions))
}

func (ks *KeyStore) Export() ([]byte, error) {
	ks.mu.RLock()
	defer ks.mu.RUnlock()

	sm := make([]SerializedMetadata, 0, len(ks.keys))
	for kid, metadata := range ks.keys {
		ks.mu.RLock()
		versions := make([]SerializedVersion, len(metadata.Versions))
		for i, keyVersion := range metadata.Versions {
			versions[i] = SerializedVersion{
				Version:      i + 1,
				CreatedAt:    keyVersion.CreatedAt,
				PublicKeyPEM: keyVersion.PublicKeyPEM,
			}
		}
		ks.mu.RUnlock()
		sm = append(sm, SerializedMetadata{
			Kid:       kid,
			Algorithm: metadata.Algorithm,
			Versions:  versions,
		})
	}

	keyStore := serializedKeyStore{
		Vault:    ks.vault.Export(),
		Metadata: sm,
	}

	bytes, err := json.Marshal(keyStore)
	if err != nil {
		return nil, err
	}

	return Encrypt(bytes)
}

func (ks *KeyStore) Import(ciphertext []byte) error {
	data, err := Decrypt(ciphertext)
	if err != nil {
		return err
	}

	var sk serializedKeyStore
	if err := json.Unmarshal(data, &sk); err != nil {
		return err
	}

	newKeys := make(map[string]*Metadata)
	for _, e := range sk.Metadata {
		mk := &Metadata{
			Algorithm: e.Algorithm,
			Versions:  make([]*KeyVersion, len(e.Versions)),
		}
		for i, v := range e.Versions {
			mk.Versions[i] = &KeyVersion{
				Version:      int32(i + 1),
				CreatedAt:    v.CreatedAt,
				PublicKeyPEM: v.PublicKeyPEM,
			}
		}
		newKeys[e.Kid] = mk
	}

	ks.mu.Lock()
	ks.keys = newKeys
	ks.vault.Import(sk.Vault)
	ks.mu.Unlock()
	return nil
}
