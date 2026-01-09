package staticrules_test

import (
	"testing"

	"github.com/northpolesec/santa-rule-importer/internal/staticrules"
	"github.com/shoenig/test"
	"github.com/shoenig/test/must"

	apipb "buf.build/gen/go/northpolesec/workshop-api/protocolbuffers/go/workshop/v1"
)

func TestParseRulesFromFile(t *testing.T) {
	rules, err := staticrules.ParseRulesFromFile("testdata/santa.mobileconfig")
	must.NoError(t, err)

	must.Eq(t, 3, len(rules))

	// First rule: TEAMID allowlist
	test.Eq(t, "ZMCG7MLDV9", rules[0].GetIdentifier())
	test.Eq(t, apipb.RuleType_TEAMID, rules[0].GetRuleType())
	test.Eq(t, apipb.Policy_ALLOWLIST, rules[0].GetPolicy())
	test.Eq(t, "North Pole Security Inc", rules[0].GetComment())
	test.Eq(t, "", rules[0].GetCustomMsg())
	test.Eq(t, "", rules[0].GetCustomUrl())
	test.Eq(t, "", rules[0].GetCelExpr())

	// Second rule: BINARY blocklist with custom_msg and custom_url
	test.Eq(t, "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2", rules[1].GetIdentifier())
	test.Eq(t, apipb.RuleType_BINARY, rules[1].GetRuleType())
	test.Eq(t, apipb.Policy_BLOCKLIST, rules[1].GetPolicy())
	test.Eq(t, "This binary is not allowed", rules[1].GetCustomMsg())
	test.Eq(t, "https://example.com/help", rules[1].GetCustomUrl())
	test.Eq(t, "", rules[1].GetComment())
	test.Eq(t, "", rules[1].GetCelExpr())

	// Third rule: SIGNINGID allowlist with cel_expr
	test.Eq(t, "EQHXZ8M8AV:com.google.Chrome", rules[2].GetIdentifier())
	test.Eq(t, apipb.RuleType_SIGNINGID, rules[2].GetRuleType())
	test.Eq(t, apipb.Policy_ALLOWLIST, rules[2].GetPolicy())
	test.Eq(t, `target.signing_time >= timestamp('2025-05-31T00:00:00Z')`, rules[2].GetCelExpr())
	test.Eq(t, "", rules[2].GetCustomMsg())
	test.Eq(t, "", rules[2].GetCustomUrl())
	test.Eq(t, "", rules[2].GetComment())
}
