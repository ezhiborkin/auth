package sqlstore

import (
	"database/sql"

	"http-rest-api/internal/app/model/files"
	"http-rest-api/internal/app/store"
)

type FileRepository struct {
	store *Store
}

func (rep *FileRepository) Add(f *files.File) error {
	if err := f.Validate(); err != nil {
		return err
	}

	return rep.store.db.QueryRow(
		"INSERT INTO files (file_name, file_description, file_path) VALUES ($1, $2, $3) RETURNING id)",
		f.Name,
		f.Description,
		f.Path,
	).Scan(&f.Id)
}

func (rep *FileRepository) Remove(id int) (*files.File, error) {
	f := &files.File{}
	if err := rep.store.db.QueryRow(
		"DELETE FROM files WHERE id = $1",
		id,
	).Err(); err != nil {
		if err == sql.ErrNoRows {
			return nil, store.ErrRecordNotFound
		}

		return nil, err
	}

	return f, nil
}
