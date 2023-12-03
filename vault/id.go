package vault

import (
	"fmt"

	"github.com/segmentio/ksuid"
)

func GenerateId(prefix string) string {
	ksuid := ksuid.New()
	return fmt.Sprintf("%s_%s", prefix, ksuid.String())

}
