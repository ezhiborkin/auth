package sqlstore

import (
	"database/sql"
	"http-rest-api/internal/app/store"

	_ "github.com/lib/pq"
)

type Store struct {
	db             *sql.DB
	userRepository *UserRepository
	roleRepository *RoleRepository
	fileRepository *FileRepository
}

func New(db *sql.DB) *Store {
	return &Store{
		db: db,
	}
}

// File ...
func (s *Store) Files() store.FileRepository {
	if s.fileRepository != nil {
		return s.fileRepository
	}

	s.fileRepository = &FileRepository{
		store: s,
	}

	return s.fileRepository
}

// Role ...
func (s *Store) Roles() store.RoleRepository {
	if s.roleRepository != nil {
		return s.roleRepository
	}

	s.roleRepository = &RoleRepository{
		store: s,
	}

	return s.roleRepository
}

// User ...
func (s *Store) User() store.UserRepository {
	if s.userRepository != nil {
		return s.userRepository
	}

	s.userRepository = &UserRepository{
		store: s,
	}

	return s.userRepository
}
