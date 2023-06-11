package vault

import (
	"github.com/segmentio/ksuid"
)

func GenerateId() string {
	ksuid := ksuid.New()
	return ksuid.String()
}
