package teststore

import (
	"http-rest-api/internal/app/model/files"
	// "http-rest-api/internal/app/store"
)

type FileRepository struct {
	store *Store
	files map[int]*files.File
}

func (rep *FileRepository) Add(f *files.File) error {
	if err := f.Validate(); err != nil {
		return err
	}

	return nil
}
