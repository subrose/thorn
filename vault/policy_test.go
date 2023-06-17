package vault

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
)

func MakePM() PolicyManager {
	ctx := context.Background()
	policies := GetDummyPolicy("test")
	dpm := DummyPolicyManager{
		policies: make(map[string]Policy),
	}
	dpm.CreatePolicy(ctx, policies[0])
	dpm.CreatePolicy(ctx, policies[1])

	return dpm
}

func makePrincipal() Principal {
	return Principal{
		AccessKey: "test",
		Policies: []string{
			"test-allow",
			"test-deny",
		},
	}
}

func TestPolicyNotSpecified(t *testing.T) {
	pm := MakePM()
	action := Action{
		makePrincipal(),
		PolicyActionRead,
		"very very secret",
	}
	result, _ := EvaluateAction(context.Background(), action, pm)
	if result {
		t.Fail()
	}
}

func TestPolicyDenied(t *testing.T) {
	pm := MakePM()
	action := Action{
		makePrincipal(),
		PolicyActionRead,
		"restricted-resource",
	}
	result, _ := EvaluateAction(context.Background(), action, pm)
	if result {
		t.Fail()
	}
}

func TestPolicyDeniedPrefixed(t *testing.T) {
	pm := MakePM()
	action := Action{
		makePrincipal(),
		PolicyActionRead,
		"aallowed-resource",
	}
	result, _ := EvaluateAction(context.Background(), action, pm)
	if result {
		t.Fail()
	}
}

func TestPolicyAllowed(t *testing.T) {
	pm := MakePM()
	action := Action{
		makePrincipal(),
		PolicyActionRead,
		"allowed-resource/123",
	}
	result, _ := EvaluateAction(context.Background(), action, pm)
	if !result {
		t.Fail()
	}
}

var pm = MakePM()

func TestEvaluateAction(t *testing.T) {
	testCases := []struct {
		name     string
		action   Action
		expected bool
	}{
		{
			"PolicyNotSpecified",
			Action{
				makePrincipal(),
				PolicyActionRead,
				"very very secret",
			},
			false,
		},
		{
			"PolicyDenied",
			Action{
				makePrincipal(),
				PolicyActionRead,
				"restricted-resource",
			},
			false,
		},
		{
			"PolicyDeniedPrefixed",
			Action{
				makePrincipal(),
				PolicyActionRead,
				"aallowed-resource",
			},
			false,
		},
		{
			"PolicyAllowed",
			Action{
				makePrincipal(),
				PolicyActionRead,
				"allowed-resource/123",
			},
			true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := EvaluateAction(context.Background(), tc.action, pm)
			assert.NoError(t, err)
			assert.Equal(t, tc.expected, result)
		})
	}
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
