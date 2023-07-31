package vault

import (
	"context"
)

type PolicyAction string

const (
	PolicyActionRead  PolicyAction = "read"
	PolicyActionWrite PolicyAction = "write"
	// TODO: Add more
)

type PolicyEffect string

const (
	EffectDeny  PolicyEffect = "deny"
	EffectAllow PolicyEffect = "allow"
)

type Policy struct {
	PolicyId  string         `redis:"policy_id" json:"policy_id" validate:"required"`
	Effect    PolicyEffect   `redis:"effect" json:"effect" validate:"required"`
	Actions   []PolicyAction `redis:"actions" json:"actions" validate:"required"`
	Resources []string       `redis:"resources" json:"resources" validate:"required"`
}

type Request struct {
	Principal Principal
	Action    PolicyAction
	Resource  string
}

type PolicyManager interface {
	GetPolicy(ctx context.Context, policyId string) (Policy, error)
	GetPolicies(ctx context.Context, policyIds []string) ([]Policy, error)
	CreatePolicy(ctx context.Context, p Policy) (string, error)
	DeletePolicy(ctx context.Context, policyId string) error
	// EvaluateAction(a Action) bool
}

func matchRune(pattern, str []rune) bool {
	for len(pattern) > 0 {
		switch pattern[0] {
		default:
			if len(str) == 0 || str[0] != pattern[0] {
				return false
			}
		case '*':
			return matchRune(pattern[1:], str) ||
				(len(str) > 0 && matchRune(pattern, str[1:]))
		}
		str = str[1:]
		pattern = pattern[1:]
	}
	return len(str) == 0 && len(pattern) == 0
}

func Match(pattern, str string) bool {
	if pattern == "" {
		return str == pattern
	}
	if pattern == "*" {
		return true
	}
	return matchRune([]rune(pattern), []rune(str))
}

func containsAction(p Policy, action PolicyAction) bool {
	for _, a := range p.Actions {
		if a == action {
			return true
		}
	}
	return false
}

func EvaluateRequest(request Request, policies []Policy) bool {
	allowed := false

	for _, p := range policies {
		// check that action exists in the policy
		matched := containsAction(p, request.Action)
		if !matched {
			// no matching action found in current policy
			continue
		}
		for _, resource := range p.Resources {
			if Match(resource, request.Resource) {
				if p.Effect == EffectDeny {
					// deny takes precendence
					return false
				}
				allowed = true
			}
		}
	}
	return allowed
}
