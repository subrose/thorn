package vault

import (
	"context"
	"fmt"
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
	PolicyId string       `redis:"policy_id" json:"policy_id" validate:"required"`
	Effect   PolicyEffect `redis:"effect" json:"effect" validate:"required"`
	Action   PolicyAction `redis:"action" json:"action" validate:"required"`
	Resource string       `redis:"resource" json:"resource" validate:"required"`
}

type Action struct {
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

type DummyPolicyManager struct {
	policies map[string]Policy
}

func (pm DummyPolicyManager) GetPolicy(ctx context.Context, policyId string) (Policy, error) {
	return pm.policies[policyId], nil
}

func (pm DummyPolicyManager) GetPolicies(ctx context.Context, policyIds []string) ([]Policy, error) {
	results := []Policy{}
	for _, pid := range policyIds {
		pol, _ := pm.GetPolicy(ctx, pid)
		results = append(results, pol)
	}
	return results, nil
}

func (pm DummyPolicyManager) CreatePolicy(ctx context.Context, p Policy) (string, error) {
	pm.policies[p.PolicyId] = p

	return p.PolicyId, nil
}

func (pm DummyPolicyManager) DeletePolicy(ctx context.Context, policyId string) error {
	delete(pm.policies, policyId)
	return nil
}

func GetDummyPolicy(principal string) []Policy {
	return []Policy{
		{
			fmt.Sprintf("%s-allow", principal),
			EffectAllow,
			PolicyActionRead,
			"allowed-resource/*",
		},
		{
			fmt.Sprintf("%s-deny", principal),
			EffectDeny,
			PolicyActionRead,
			"restricted-resource",
		},
	}
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

func EvaluateAction(ctx context.Context, a Action, pm PolicyManager) (bool, error) {
	principalPolicies, err := pm.GetPolicies(ctx, a.Principal.Policies)
	if err != nil {
		return false, err
	}
	for _, p := range principalPolicies {
		matched := Match(p.Resource, a.Resource)
		matched = (matched && p.Action == a.Action)
		if !matched {
			continue
		}
		if p.Effect == EffectAllow {
			return true, nil
		} else {
			return false, nil
		}
	}
	return false, nil
}
