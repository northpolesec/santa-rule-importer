package rudolph_test

import (
	"testing"

	"github.com/shoenig/test"
	"github.com/shoenig/test/must"

	"github.com/northpolesec/santa-rule-importer/internal/rudolph"
)

func TestParseRulesFromFile(t *testing.T) {
	// Test with a valid CSV file
	rules, err := rudolph.ParseRulesFromFile("testdata/rudolph.csv")
	must.NoError(t, err)

	test.Eq(t, 6, len(rules))

	// Check the first rule
	test.Eq(t, "d84db96af8c2e60ac4c851a21ec460f6f84e0235beb17d24a78712b9b021ed57", rules[0].GetIdentifier())
	test.Eq(t, "CERTIFICATE", rules[0].RuleType.String())
	test.Eq(t, "ALLOWLIST", rules[0].Policy.String())
	test.Eq(t, "", rules[0].CustomMsg)
	test.Eq(t, "Software Signing by Apple Inc.", rules[0].Comment)

	// Check the second rule
	test.Eq(t, "d292f56f78effeb715382f3578b3716309da04e31589b23b68c3750edd526660", rules[1].Identifier)
	test.Eq(t, "CERTIFICATE", rules[1].RuleType.String())
	test.Eq(t, "ALLOWLIST", rules[1].Policy.String())
	test.Eq(t, "", rules[1].CustomMsg)
	test.Eq(t, "Developer ID Application: Zoom Video Communications, Inc. (BJ4HAAB9B3)", rules[1].Comment)

	// Check the third rule
	test.Eq(t, "96f18e09d65445985c7df5df74ef152a0bc42e8934175a626180d9700c343e7b", rules[2].Identifier)
	test.Eq(t, "CERTIFICATE", rules[2].RuleType.String())
	test.Eq(t, "ALLOWLIST", rules[2].Policy.String())
	test.Eq(t, "", rules[2].CustomMsg)
	test.Eq(t, "Developer ID Application: Mozilla Corporation (43AQ936H96)", rules[2].Comment)

	// Check the fourth rule
	test.Eq(t, "61977d6006459c4cefe9b988a453589946224957bfc07b262cd7ca1b7a61e04e", rules[3].Identifier)
	test.Eq(t, "CERTIFICATE", rules[3].RuleType.String())
	test.Eq(t, "ALLOWLIST", rules[3].Policy.String())
	test.Eq(t, "", rules[3].CustomMsg)
	test.Eq(t, "Apple Mac OS Application Signing", rules[3].Comment)

	// Check the fifth rule
	test.Eq(t, "345a8e098bd04794aaeefda8c9ef56a0bf3d3706d67d35bc0e23f11bb3bffce5", rules[4].Identifier)
	test.Eq(t, "CERTIFICATE", rules[4].RuleType.String())
	test.Eq(t, "ALLOWLIST", rules[4].Policy.String())
	test.Eq(t, "", rules[4].CustomMsg)
	test.Eq(t, "Developer ID Application: Google, Inc. (EQHXZ8M8AV)", rules[4].Comment)

	// Check the sixth rule
	test.Eq(t, "2401d9aee4e3601e12529f8e48e889533630f1ceb8adb49c976fe5c93c9df5e7", rules[5].Identifier)
	test.Eq(t, "CERTIFICATE", rules[5].RuleType.String())
	test.Eq(t, "ALLOWLIST", rules[5].Policy.String())
	test.Eq(t, "", rules[5].CustomMsg)
	test.Eq(t, "Developer ID Application: Slack Technologies, Inc. (BQR82RBBHL), by Slack Technologies, Inc. (BQR82RBBHL)", rules[5].Comment)
}
