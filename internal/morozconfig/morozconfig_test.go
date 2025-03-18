package morozconfig_test

import (
	"slices"
	"strings"
	"testing"

	"github.com/northpolesec/santa-rule-importer/internal/morozconfig"
	"github.com/shoenig/test"
	"github.com/shoenig/test/must"

	syncpb "buf.build/gen/go/northpolesec/protos/protocolbuffers/go/sync"
	apipb "buf.build/gen/go/northpolesec/workshop-api/protocolbuffers/go/workshop/v1"
)

func TestParseRulesFromFile(t *testing.T) {
	// Test with a valid file
	rules, err := morozconfig.ParseRulesFromFile("testdata/global.toml", false)
	must.NoError(t, err)

	// Sort the rules by identifier since the TOML parser uses a map under the
	// hood
	slices.SortFunc(rules, func(a, b *apipb.Rule) int {
		return strings.Compare(a.GetIdentifier(), b.GetIdentifier())
	})

	must.Eq(t, 2, len(rules))

	test.Eq(t, syncpb.Policy_BLOCKLIST, rules[0].GetPolicy())
	test.Eq(t, syncpb.RuleType_SIGNINGID, rules[0].GetRuleType())
	test.Eq(t, "platform:com.apple.osacompile", rules[0].GetIdentifier())
	test.Eq(t, "https://gist.github.com/pmarkowsky/bfa5840261351f506444b2d8541e9654",
		rules[0].GetCustomUrl())
	test.Eq(t, "osacompile is banned by policy", rules[0].GetCustomMsg())

	test.Eq(t, syncpb.Policy_BLOCKLIST, rules[1].GetPolicy())
	test.Eq(t, syncpb.RuleType_SIGNINGID, rules[1].GetRuleType())
	test.Eq(t, "platform:com.apple.osascript", rules[1].GetIdentifier())
	test.Eq(t, "https://www.youtube.com/watch?v=dQw4w9WgXcQ", rules[1].GetCustomUrl())
	test.Eq(t, "Where does this go?", rules[1].GetCustomMsg())
}

func TestUsingCustomMsgAsComment(t *testing.T) {
	// Test with a valid file
	rules, err := morozconfig.ParseRulesFromFile("testdata/global.toml", true)
	must.NoError(t, err)

	// Sort the rules by identifier since the TOML parser uses a map under the
	// hood
	// Sort the rules by identifier since the TOML parser uses a map under the
	// hood
	slices.SortFunc(rules, func(a, b *apipb.Rule) int {
		return strings.Compare(a.GetIdentifier(), b.GetIdentifier())
	})

	must.Eq(t, 2, len(rules))
	test.Eq(t, "osacompile is banned by policy", rules[0].GetComment())

	// Ensure the comment and the custom_msg are the same
	test.Eq(t, rules[0].GetCustomMsg(), rules[0].GetComment())

	test.Eq(t, "Where does this go?", rules[1].GetComment())
	// Ensure the comment and the custom_msg are the same
	test.Eq(t, rules[1].GetCustomMsg(), rules[1].GetComment())
}
