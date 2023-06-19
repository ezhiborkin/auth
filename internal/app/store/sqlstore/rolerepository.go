package sqlstore

import (
	"database/sql"
	model "http-rest-api/internal/app/model/roles"
	"http-rest-api/internal/app/store"
)

type RoleRepository struct {
	store *Store
}

func (rep *RoleRepository) Create(r *model.Role) error {
	if err := r.Validate(); err != nil {
		return err
	}

	return rep.store.db.QueryRow(
		"INSERT INTO roles (title) VALUES ($1) RETURNING id",
		&r.Title,
	).Scan(&r.Id)
}

func (rep *RoleRepository) Find(id int) (*model.Role, error) {
	r := &model.Role{}
	if err := rep.store.db.QueryRow(
		"SELECT id, title FROM roles WHERE id = $1",
		id,
	).Scan(
		&r.Id,
		&r.Title,
	); err != nil {
		return nil, err
	}

	return r, nil
}

func (rep *RoleRepository) GetAll() (*[]model.Role, error) {
	rows, err := rep.store.db.Query("SELECT id, title FROM roles")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var rolesArray []model.Role

	for rows.Next() {
		var rolesArrayEl model.Role
		if err := rows.Scan(&rolesArrayEl.Id, &rolesArrayEl.Title); err != nil {
			return &rolesArray, err
		}
		rolesArray = append(rolesArray, rolesArrayEl)
	}

	if err = rows.Err(); err != nil {
		return &rolesArray, err
	}

	return &rolesArray, err
}

func (rep *RoleRepository) Remove(id int) error {
	if err := rep.store.db.QueryRow(
		"DELETE FROM roles WHERE id = $1",
		id,
	).Err(); err != nil {
		if err == sql.ErrNoRows {
			return store.ErrRecordNotFound
		}

		return err
	}

	return nil
}
