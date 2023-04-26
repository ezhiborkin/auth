package store

// Store ...
type Store interface {
	User() UserRepository
	Roles() RoleRepository
	Files() FileRepository
}
