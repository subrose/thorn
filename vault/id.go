package vault

import (
	"github.com/segmentio/ksuid"
)

func GenerateId(prefix string) string {
	ksuid := ksuid.New()
	return ksuid.String()
}
