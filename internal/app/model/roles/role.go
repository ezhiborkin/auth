package roles

import validation "github.com/go-ozzo/ozzo-validation"

type Role struct {
	Id    int    `json:"id"`
	Title string `json:"title"`
}

func (r *Role) Validate() error {
	return validation.ValidateStruct(
		r,
		validation.Field(&r.Title, validation.Required, validation.Length(3, 15)),
	)
}
