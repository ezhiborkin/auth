package files

import validation "github.com/go-ozzo/ozzo-validation"

type File struct {
	Id          int    `json:"id"`
	Name        string `json:"file_name"`
	Description string `json:"file_description"`
	Path        string `json:"file_path"`
}

func (f *File) Validate() error {
	return validation.ValidateStruct(
		f,
		validation.Field(&f.Name, validation.Required, validation.Length(1, 20)),
		validation.Field(&f.Description, validation.Required, validation.Length(1, 100)),
		validation.Field(&f.Path, validation.Required, validation.Length(1, 200)),
	)
}
