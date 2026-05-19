package rulehelpers_test

import (
	"testing"

	"github.com/northpolesec/santa-rule-importer/internal/rulehelpers"

	"github.com/shoenig/test"

	apipb "buf.build/gen/go/northpolesec/workshop-api/protocolbuffers/go/workshop/v1"
)

func TestGetPolicyType(t *testing.T) {
	cases := []struct {
		in   string
		want apipb.Policy
	}{
		{"ALLOWLIST", apipb.Policy_ALLOWLIST},
		{"allow", apipb.Policy_ALLOWLIST},
		{"ALLOWLIST_COMPILER", apipb.Policy_ALLOWLIST_COMPILER},
		{"compiler", apipb.Policy_ALLOWLIST_COMPILER},
		{"BLOCKLIST", apipb.Policy_BLOCKLIST},
		{"block", apipb.Policy_BLOCKLIST},
		{"SILENT_BLOCKLIST", apipb.Policy_SILENT_BLOCKLIST},
		{"silent_block", apipb.Policy_SILENT_BLOCKLIST},
		{"CEL", apipb.Policy_CEL},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			test.Eq(t, tc.want, rulehelpers.GetPolicyType(tc.in))
		})
	}
}

func TestGetRuleType(t *testing.T) {
	cases := []struct {
		in   string
		want apipb.RuleType
	}{
		{"CDHASH", apipb.RuleType_CDHASH},
		{"BINARY", apipb.RuleType_BINARY},
		{"sha256", apipb.RuleType_BINARY},
		{"SIGNINGID", apipb.RuleType_SIGNINGID},
		{"CERTIFICATE", apipb.RuleType_CERTIFICATE},
		{"teamid", apipb.RuleType_TEAMID},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			test.Eq(t, tc.want, rulehelpers.GetRuleType(tc.in))
		})
	}
}
