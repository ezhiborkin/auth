package teststore

import (
	model "http-rest-api/internal/app/model/users"
	"http-rest-api/internal/app/store"
)

// UserRepository ...
type UserRepository struct {
	store *Store
	users map[int]*model.User
}

// Create ...
func (r UserRepository) Create(u *model.User) error {
	if err := u.Validate(); err != nil {
		return err
	}

	if err := u.EncryptPassword(); err != nil {
		return err
	}

	u.Id = len(r.users) + 1
	r.users[u.Id] = u

	return nil
}

// Find ...
func (r *UserRepository) Find(id int) (*model.User, error) {
	u, ok := r.users[id]
	if !ok {
		return nil, store.ErrRecordNotFound

	}

	return u, nil
}

// FindByEmail ...
func (r *UserRepository) FindByEmail(email string) (*model.User, error) {
	for _, u := range r.users {
		if u.Email == email {
			return u, nil
		}
	}

	return nil, store.ErrRecordNotFound
}

// func (r *UserRepository) UpdateRole(userId int, roleId int) error {
// 	// _, err := r.store.User().Find(userId)
// 	// if err != nil {
// 	// 	return err
// 	// }

// 	return nil
// }

func (r *UserRepository) Update(id int, u *model.User) error {
	// u, err := r.store.User().Find(id)
	// if err != nil {
	// 	return err
	// }

	// if err := u.EncryptPassword(); err != nil {
	// 	return err
	// }

	return nil
}

func (r *UserRepository) GetAll() (*[]model.User, error) {
	return nil, nil
}

func (r *UserRepository) Remove(int) error {
	return nil
}
