package storage

import "errors"

var (
	ErrMasterKeyEmpty = errors.New("Master Key must not be empty")
)

type Storage interface {
	Save(data []byte) error
	Load() ([]byte, error)
}
