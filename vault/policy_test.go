package vault

import (
	"context"
	"testing"

	"github.com/go-playground/assert/v2"
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

func TestMatch(t *testing.T) {
	assert.Equal(
		t,
		false,
		Match("/asd*", "asd"),
	)
	assert.Equal(
		t,
		false,
		Match("/asd/*/asd/*", "asd"),
	)
	assert.Equal(
		t,
		true,
		Match("/asd*", "/asd"),
	)
	assert.Equal(
		t,
		true,
		Match("/asd/*/asd/*", "/asd/aksjdhaks/dajksd/asdk/asdjas/asd/jdjdjsiisad/sdkjsd"),
	)
	assert.Equal(
		t,
		true,
		Match("exact-match", "exact-match"),
	)
	assert.Equal(
		t,
		true,
		Match("*", "asd"),
	)
}
