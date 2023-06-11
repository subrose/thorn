package vault

import (
	"fmt"
	"io"
	"os"
	"time"
)

type StdOutAuditor struct {
	w io.Writer
}

func NewStdOutAuditor(silent bool) *StdOutAuditor {
	if silent {
		return &StdOutAuditor{
			w: io.Discard,
		}
	}
	return &StdOutAuditor{
		w: os.Stdout,
	}
}

func (a StdOutAuditor) Log(principal, action, resource string, allowed bool) {
	if allowed {
		fmt.Fprintf(a.w, "%s: Principal: %s ALLOWED Action: %s Resource: %s \n", time.Now().UTC(), principal, action, resource)
	} else {
		fmt.Fprintf(a.w, "%s: Principal: %s DENIED Action: %s Resource: %s \n", time.Now().UTC(), principal, action, resource)
	}
}
