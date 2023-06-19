package teststore

import (
	"http-rest-api/internal/app/model/roles"
	"http-rest-api/internal/app/store"
)

type RoleRepository struct {
	store *Store
	roles map[int]*roles.Role
}

func (r RoleRepository) Create(role *roles.Role) error {
	if err := role.Validate(); err != nil {
		return err
	}

	role.Id = len(r.roles) + 1
	r.roles[role.Id] = role

	return nil
}

// Find ...
func (r *RoleRepository) Find(id int) (*roles.Role, error) {
	role, ok := r.roles[id]
	if !ok {
		return nil, store.ErrRecordNotFound
	}

	return role, nil
}

func (r *RoleRepository) GetAll() (*[]roles.Role, error) {
	return nil, nil
}

func (r *RoleRepository) Remove(id int) error {
	return nil
}
