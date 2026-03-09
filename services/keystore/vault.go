package keystore

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"fmt"
	"strconv"
	"strings"
	"sync"
)

type Vault struct {
	keys sync.Map
}

func NewVault() *Vault {
	return &Vault{}
}

func vaultKey(kid string, version int32) string {
	return fmt.Sprintf("%s:%d", kid, version)
}

func parseVaultKey(key string) (kid string, version int32) {
	res := strings.Split(key, ":")
	kid = res[0]
	v, _ := strconv.ParseInt(res[1], 10, 32)
	version = int32(v)
	return
}

func (v *Vault) Store(kid string, version int32, privKey *ecdsa.PrivateKey) {
	vk := vaultKey(kid, version)
	v.keys.Store(vk, privKey)
}

func (v *Vault) Sign(kid string, version int32, data []byte) ([]byte, error) {
	privKey, ok := v.keys.Load(vaultKey(kid, version))
	if !ok {
		return nil, ErrorKeyNotFound
	}

	digest := sha256.Sum256(data)
	return ecdsa.SignASN1(rand.Reader, privKey.(*ecdsa.PrivateKey), digest[:])
}

func (v *Vault) Verify(kid string, version int32, data, signature []byte) (bool, error) {
	privKey, ok := v.keys.Load(vaultKey(kid, version))
	if !ok {
		return false, ErrorKeyNotFound
	}

	digest := sha256.Sum256(data)
	return ecdsa.VerifyASN1(&(privKey.(*ecdsa.PrivateKey)).PublicKey, digest[:], signature), nil
}

func (v *Vault) Export() []SerializedVault {
	var entries []SerializedVault
	v.keys.Range(func(key, value any) bool {
		privKey := value.(*ecdsa.PrivateKey)
		der, err := x509.MarshalECPrivateKey(privKey)
		if err != nil {
			return false
		}
		k := key.(string)
		kid, version := parseVaultKey(k)
		entries = append(entries, SerializedVault{
			Kid:        kid,
			Version:    version,
			PrivKeyDER: der,
		})
		return true
	})
	return entries
}

func (v *Vault) Import(data []SerializedVault) error {
	for _, e := range data {
		privKey, err := x509.ParseECPrivateKey(e.PrivKeyDER)
		if err != nil {
			return err
		}
		v.keys.Store(vaultKey(e.Kid, e.Version), privKey)
	}
	return nil
}
