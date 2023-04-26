package users

import "testing"

// TestUser ...
func TestUser(t *testing.T) *User {
	return &User{
		Email:    "zheka0723@gmail.com",
		Password: "password",
	}
}
