package storage

import "os"

type LocalStore struct {
	Path string
}

func (ls *LocalStore) Save(data []byte) error {
	tmp := ls.Path + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return err
	}

	return os.Rename(tmp, ls.Path)
}

func (ls *LocalStore) Load() ([]byte, error) {
	data, err := os.ReadFile(ls.Path)
	if err != nil {
		return nil, err
	}

	return data, nil
}
