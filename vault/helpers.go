package vault

// TODO: This should be in a separate package

func StringInSlice(s string, list []string) bool {
	// StringInSlice checks if `list` contains `s`
	for _, x := range list {
		if s == x {
			return true
		}
	}
	return false
}
