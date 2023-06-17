package vault

import (
	"regexp"
)

func ValidateCollectionName(name string) bool {
	reg := "^[a-zA-Z0-9._-]{1,249}$"
	match, _ := regexp.MatchString(reg, name)

	// Check for prohibited values: single period and double underscore
	if name == "." || name == "__" {
		return false
	}

	return match
}
