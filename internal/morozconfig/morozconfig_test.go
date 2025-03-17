package morozconfig_test

import (
	"sort"
	"strings"
	"testing"

	"github.com/shoenig/test"
	"github.com/shoenig/test/must"

	"github.com/northpolesec/santa-rule-importer/internal/morozconfig"

	syncpb "buf.build/gen/go/northpolesec/protos/protocolbuffers/go/sync"
	apipb "buf.build/gen/go/northpolesec/workshop-api/protocolbuffers/go/workshop/v1"
)

// ByIdentifier implements sort.Interface for sorting rules by their identifier.
type ByIdentifier []*apipb.Rule

func (a ByIdentifier) Len() int      { return len(a) }
func (a ByIdentifier) Swap(i, j int) { a[i], a[j] = a[j], a[i] }
func (a ByIdentifier) Less(i, j int) bool {
	return strings.Compare(a[i].GetIdentifier(), a[j].GetIdentifier()) < 0
}

func TestParseRulesFromFile(t *testing.T) {
	// Test with a valid file
	rules, err := morozconfig.ParseRulesFromFile("testdata/global.toml")
	must.NoError(t, err)

	// Sort the rules by identifier since the TOML parser uses a map under the
	// hood
	sort.Sort(ByIdentifier(rules))

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
