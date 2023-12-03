package vault

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

type DummyPolicyManager struct {
	policies map[string]Policy
}

func (pm DummyPolicyManager) GetPolicy(ctx context.Context, policyId string) (Policy, error) {
	return pm.policies[policyId], nil
}

func (pm DummyPolicyManager) GetPolicies(ctx context.Context, policyIds []string) ([]*Policy, error) {
	results := []*Policy{}
	for _, pid := range policyIds {
		pol, _ := pm.GetPolicy(ctx, pid)
		results = append(results, &pol)
	}
	return results, nil
}

func (pm DummyPolicyManager) CreatePolicy(ctx context.Context, p Policy) (string, error) {
	pm.policies[p.Id] = p

	return p.Id, nil
}

func (pm DummyPolicyManager) DeletePolicy(ctx context.Context, policyId string) error {
	delete(pm.policies, policyId)
	return nil
}

func getDummyPolicy(principal string) []Policy {
	return []Policy{
		{
			"",
			fmt.Sprintf("%s-allow", principal),
			"",
			EffectAllow,
			[]PolicyAction{PolicyActionRead},
			[]string{"allowed-resource/*", "restricted-resource"},
			"",
			"",
		},
		{
			"",
			fmt.Sprintf("%s-deny", principal),
			"",
			EffectDeny,
			[]PolicyAction{PolicyActionRead},
			[]string{"restricted-resource"},
			"",
			"",
		},
	}
}

func MakePM() DummyPolicyManager {
	ctx := context.Background()
	policies := getDummyPolicy("test")
	dpm := DummyPolicyManager{
		policies: make(map[string]Policy),
	}
	_, _ = dpm.CreatePolicy(ctx, policies[0])
	_, _ = dpm.CreatePolicy(ctx, policies[1])

	return dpm
}

func makePrincipal() Principal {
	return Principal{
		Username: "test",
		Policies: []string{
			"test-allow",
			"test-deny",
		},
	}
}

func TestPolicies(t *testing.T) {
	pm := MakePM()
	principal := makePrincipal()
	policies, err := pm.GetPolicies(context.Background(), principal.Policies)
	if err != nil {
		t.Error(err)
	}

	t.Run("not allowed when no policy is specified for a resource", func(t *testing.T) {
		request := Request{
			principal,
			PolicyActionRead,
			"very very secret",
		}
		allowed := EvaluateRequest(request, policies)
		if allowed {
			t.Fail()
		}
	})

	t.Run("not allowed when deny policy on resource", func(t *testing.T) {
		request := Request{
			principal,
			PolicyActionRead,
			"restricted-resource",
		}
		allowed := EvaluateRequest(request, policies)
		if allowed {
			t.Fail()
		}
	})

	t.Run("not allowed when deny policy on resource with prefix", func(t *testing.T) {
		request := Request{
			principal,
			PolicyActionRead,
			"aallowed-resource",
		}
		allowed := EvaluateRequest(request, policies)
		if allowed {
			t.Fail()
		}
	})

	t.Run("allowed on resource using glob in policy", func(t *testing.T) {
		request := Request{
			principal,
			PolicyActionRead,
			"allowed-resource/123",
		}
		allowed := EvaluateRequest(request, policies)
		if !allowed {
			t.Fail()
		}
	})
}

func TestMatch(t *testing.T) {
	testCases := []struct {
		pattern  string
		str      string
		expected bool
	}{
		{"/asd*", "asd", false},
		{"/asd*", "/asd/", true},
		{"/asd/*/asd", "/asd/asd/asd", true},
		{"/asd/*/asd/*", "asd", false},
		{"/asd*", "/asd", true},
		{"/asd/*/asd/*", "/asd/aksjdhaks/dajksd/asdk/asdjas/asd/jdjdjsiisad/sdkjsd", true},
		{"exact-match", "exact-match", true},
		{"*", "asd", true},
		{"*", "asd/asd/asd", true},
	}

	for _, tc := range testCases {
		t.Run(tc.pattern, func(t *testing.T) {
			assert.Equal(t, tc.expected, Match(tc.pattern, tc.str))
		})
	}
}
