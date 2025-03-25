package santactl_test

import (
	"testing"

	"github.com/northpolesec/santa-rule-importer/internal/santactl"

	"github.com/shoenig/test"
	"github.com/shoenig/test/must"

	syncpb "buf.build/gen/go/northpolesec/protos/protocolbuffers/go/sync"
)

func TestRuleTranslation(t *testing.T) {
	// Test with a valid file
	rules, err := santactl.ParseRulesFromFile("testdata/rules.json")
	must.NoError(t, err)

	must.Eq(t, 3, len(rules))

	test.Eq(t, "EQHXZ8M8AV:com.google.Chrome.helper.renderer", rules[0].GetIdentifier())
	test.Eq(t, syncpb.RuleType_SIGNINGID, rules[0].GetRuleType())
	test.Eq(t, syncpb.Policy_ALLOWLIST, rules[0].GetPolicy())
	test.Eq(t, "This is allowed", rules[0].GetCustomMsg())
	test.Eq(t, "https://support.google.com/chrome/answer/95617",
		rules[0].GetCustomUrl())
	test.Eq(t, "/Applications/Google Chrome.app/Contents/Frameworks/Google Chrome Framework.framework/Versions/131.0.6778.86/Helpers/Google Chrome Helper (Renderer).app/Contents/MacOS/Google Chrome Helper (Renderer)", rules[0].GetComment())

	test.Eq(t, "6c58905785bccb8a0854cca5a646c4ea6b20e522c9b61de842a759919df002e7", rules[1].GetIdentifier())
	test.Eq(t, syncpb.RuleType_BINARY, rules[1].GetRuleType())
	test.Eq(t, syncpb.Policy_ALLOWLIST, rules[1].GetPolicy())
	test.Eq(t, "", rules[1].GetCustomMsg())
	test.Eq(t, "", rules[1].GetCustomUrl())
	test.Eq(t, "/Users/peterm/Library/Application Support/Code/User/globalStorage/llvm-vs-code-extensions.vscode-clangd/install/15.0.6/clangd_15.0.6/bin/clangd", rules[1].GetComment())

	test.Eq(t, "platform:com.apple.osascript", rules[2].GetIdentifier())
	test.Eq(t, syncpb.RuleType_SIGNINGID, rules[2].GetRuleType())
	test.Eq(t, syncpb.Policy_BLOCKLIST, rules[2].GetPolicy())
	test.Eq(t, "", rules[2].GetCustomMsg())
	test.Eq(t, "", rules[2].GetCustomUrl())
	test.Eq(t, "", rules[2].GetComment())
}
