package vault

// TODO: These will be deleted once validation is moved to the vault.
import (
	"strings"

	"regexp"

	"github.com/go-playground/validator/v10"
)

func ValidateResourceName(fl validator.FieldLevel) bool {
	// Validation for vault internal resource names
	reg := "^[a-zA-Z0-9._-]{1,249}$"
	match, _ := regexp.MatchString(reg, fl.Field().String())

	// Check for prohibited values: single period and double underscore
	if fl.Field().String() == "." || fl.Field().String() == "__" {
		return false
	}

	return match
}

// Validate validates the input struct
func Validate(payload interface{}) error {
	var errors []ValidationError
	var validate = validator.New()
	_ = validate.RegisterValidation("vaultResourceNames", ValidateResourceName)

	err := validate.Struct(payload)

	if err != nil {
		for _, err := range err.(validator.ValidationErrors) {
			var element ValidationError
			element.FailedField = strings.ToLower(err.StructField())
			element.Tag = err.Tag()
			element.Value = err.Param()
			errors = append(errors, element)
		}
	}
	if len(errors) > 0 {
		return newValidationErrors(errors)
	}
	return nil
}
