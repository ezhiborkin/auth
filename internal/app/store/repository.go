package store

import (
	"http-rest-api/internal/app/model/files"
	"http-rest-api/internal/app/model/roles"
	"http-rest-api/internal/app/model/users"
)

// UserRepository ...
type UserRepository interface {
	Create(*users.User) error
	Find(int) (*users.User, error)
	FindByEmail(string) (*users.User, error)
	Update(int, *users.User) error
	GetAll() (*[]users.User, error)
	Remove(int) error
}

type RoleRepository interface {
	Create(*roles.Role) error
	Find(int) (*roles.Role, error)
	GetAll() (*[]roles.Role, error)
	Remove(int) error
}

type FileRepository interface {
	Add(*files.File) error
}
