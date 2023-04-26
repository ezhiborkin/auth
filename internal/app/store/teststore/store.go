package teststore

import (
	"http-rest-api/internal/app/model/files"
	"http-rest-api/internal/app/model/roles"
	model "http-rest-api/internal/app/model/users"
	"http-rest-api/internal/app/store"
)

type Store struct {
	userRepository *UserRepository
	roleRepository *RoleRepository
	fileRepository *FileRepository
}

func New() *Store {
	return &Store{}
}

// User ...
func (s *Store) User() store.UserRepository {
	if s.userRepository != nil {
		return s.userRepository
	}

	s.userRepository = &UserRepository{
		store: s,
		users: make(map[int]*model.User),
	}

	return s.userRepository
}

func (s *Store) Roles() store.RoleRepository {
	if s.roleRepository != nil {
		return s.roleRepository
	}

	s.roleRepository = &RoleRepository{
		store: s,
		roles: make(map[int]*roles.Role),
	}

	return s.roleRepository
}

func (s *Store) Files() store.FileRepository {
	if s.fileRepository != nil {
		return s.fileRepository
	}

	s.fileRepository = &FileRepository{
		store: s,
		files: make(map[int]*files.File),
	}

	return s.fileRepository
}
