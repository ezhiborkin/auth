package sqlstore

import (
	"database/sql"
	"http-rest-api/internal/app/model/users"
	"http-rest-api/internal/app/store"

	"github.com/sirupsen/logrus"
)

// UserRepository ...
type UserRepository struct {
	store *Store
}

// Create user
func (r *UserRepository) Create(u *users.User) error {
	if err := u.Validate(); err != nil {
		return err
	}

	if err := u.EncryptPassword(); err != nil {
		return err
	}

	return r.store.db.QueryRow(
		"INSERT INTO users (email, encrypted_password, role_id) VALUES ($1, $2, $3) RETURNING id",
		u.Email,
		u.EncryptedPassword,
		u.RoleId,
	).Scan(&u.Id)
}

// Find user by email
func (r *UserRepository) FindByEmail(email string) (*users.User, error) {
	u := &users.User{}
	if err := r.store.db.QueryRow(
		"SELECT id, email, encrypted_password, role_id FROM users WHERE email = $1",
		email,
	).Scan(
		&u.Id,
		&u.Email,
		&u.EncryptedPassword,
		&u.RoleId,
	); err != nil {
		if err == sql.ErrNoRows {
			return nil, store.ErrRecordNotFound
		}

		return nil, err
	}

	return u, nil

}

// Get all users
func (r *UserRepository) GetAll() (*[]users.User, error) {
	rows, err := r.store.db.Query("SELECT id, email, role_id FROM users")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var usersArray []users.User

	for rows.Next() {
		var usersArrEl users.User
		if err := rows.Scan(&usersArrEl.Id, &usersArrEl.Email, &usersArrEl.RoleId); err != nil {
			return &usersArray, err
		}
		usersArray = append(usersArray, usersArrEl)
	}

	if err = rows.Err(); err != nil {
		return &usersArray, err
	}

	return &usersArray, err
}

// Find a user
func (r *UserRepository) Find(id int) (*users.User, error) {
	u := &users.User{}
	if err := r.store.db.QueryRow(
		"SELECT id, email, encrypted_password, role_id FROM users WHERE id = $1",
		id,
	).Scan(
		&u.Id,
		&u.Email,
		&u.EncryptedPassword,
		&u.RoleId,
	); err != nil {
		if err == sql.ErrNoRows {
			return nil, store.ErrRecordNotFound
		}

		return nil, err
	}

	return u, nil
}

// Update user
func (r *UserRepository) Update(id int, u *users.User) error {
	if err := u.Validate(); err != nil {
		return err
	}
	uOld, err := r.store.User().Find(id)
	if err != nil {
		return err
	}

	if uOld == nil {
		return store.ErrRecordNotFound
	}

	if err := u.EncryptPassword(); err != nil {
		return err
	}

	r.store.db.QueryRow(
		`
		UPDATE users 
		SET email = $1, encrypted_password = $2, role_id = $3 
		WHERE id = $4
		`,
		u.Email,
		u.EncryptedPassword,
		u.RoleId,
		id,
	)

	logger := logrus.New()
	logger.Infof("email: %s, password: %s, role: %s, id: %s", u.Email,
		u.EncryptedPassword,
		u.RoleId,
		id)

	return nil
}

// Remove user
func (r *UserRepository) Remove(id int) error {
	if err := r.store.db.QueryRow(
		"DELETE FROM users WHERE id = $1",
		id,
	).Err(); err != nil {
		if err == sql.ErrNoRows {
			return store.ErrRecordNotFound
		}

		return err
	}

	return nil
}
