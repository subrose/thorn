package vault

import (
	"testing"
)

func TestValidateCollectionName(t *testing.T) {
	tests := []struct {
		name string
		want bool
	}{
		{
			name: "CollectionOne",
			want: true,
		},
		{
			name: "1234567890",
			want: true,
		},
		{
			name: "valid_name",
			want: true,
		},
		{
			name: "valid.name",
			want: true,
		},
		{
			name: "valid-name",
			want: true,
		},
		{
			name: "a123456789017890a123456789017890a123456789017890a123456789017890a123456789017890a123456789017890a123456789017890a123456789017890a123456789017890a123456789017890a123456789017890a123456789017890a123456789017890a123456789017890a123456789017890a12345678", // 249 characters
			want: true,
		},
		{
			name: ".",
			want: false,
		},
		{
			name: "__",
			want: false,
		},
		{
			name: "invalid/Name",
			want: false,
		},
		{
			name: "a123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901", // 250 characters
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ValidateCollectionName(tt.name); got != tt.want {
				t.Errorf("ValidateCollectionName() = %v, want %v", got, tt.want)
			}
		})
	}
}
