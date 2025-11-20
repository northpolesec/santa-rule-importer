package faa_test

import (
	"os"
	"testing"

	"github.com/shoenig/test"
	"github.com/shoenig/test/must"

	"github.com/northpolesec/santa-rule-importer/internal/faa"

	apipb "buf.build/gen/go/northpolesec/workshop-api/protocolbuffers/go/workshop/v1"
)

func TestParseRulesFromFile(t *testing.T) {
	rules, err := faa.ParseRulesFromFile("faa.plist")
	must.NoError(t, err)
	must.Positive(t, len(rules))

	// Check that we have at least one rule
	test.Eq(t, true, len(rules) > 0)

	// Find the ChromeProfile rule
	var chromeProfileRule *apipb.FileAccessRule
	for _, rule := range rules {
		if rule.Name == "ChromeProfile" {
			chromeProfileRule = rule
			break
		}
	}
	must.NotNil(t, chromeProfileRule)

	// Verify ChromeProfile rule structure
	test.Eq(t, "ChromeProfile", chromeProfileRule.Name)
	must.Positive(t, len(chromeProfileRule.PathPrefixes))
	test.Eq(t, "/Users/*/Library/Application Support/Google/Chrome/*/Cookies", chromeProfileRule.PathPrefixes[0])
	test.Eq(t, false, chromeProfileRule.AllowReadAccess)
	test.Eq(t, true, chromeProfileRule.BlockViolations) // AuditOnly is false, so BlockViolations should be true
	must.Positive(t, len(chromeProfileRule.ProcessSigningIds))
}

func TestParseRulesFromFileChromeExtensions(t *testing.T) {
	rules, err := faa.ParseRulesFromFile("faa.plist")
	must.NoError(t, err)

	// Find the ChromeExtensions rule
	var chromeExtensionsRule *apipb.FileAccessRule
	for _, rule := range rules {
		if rule.Name == "ChromeExtensions" {
			chromeExtensionsRule = rule
			break
		}
	}
	must.NotNil(t, chromeExtensionsRule)

	test.Eq(t, "ChromeExtensions", chromeExtensionsRule.Name)
	must.Positive(t, len(chromeExtensionsRule.PathPrefixes))
	test.Eq(t, "/Users/*/Library/Application Support/Google/Chrome/*/Extensions/", chromeExtensionsRule.PathPrefixes[0])
	test.Eq(t, false, chromeExtensionsRule.AllowReadAccess)
}

func TestParseRulesFromFileSignalDB(t *testing.T) {
	rules, err := faa.ParseRulesFromFile("faa.plist")
	must.NoError(t, err)

	// Find the SignalDB rule
	var signalDBRule *apipb.FileAccessRule
	for _, rule := range rules {
		if rule.Name == "SignalDB" {
			signalDBRule = rule
			break
		}
	}
	must.NotNil(t, signalDBRule)

	test.Eq(t, "SignalDB", signalDBRule.Name)
	must.Positive(t, len(signalDBRule.PathPrefixes))
	test.Eq(t, "/Users/*/Library/Application Support/Signal", signalDBRule.PathPrefixes[0])
}

func TestParseRulesFromFileSudoProtection(t *testing.T) {
	rules, err := faa.ParseRulesFromFile("faa.plist")
	must.NoError(t, err)

	// Find the SudoProtection rule
	var sudoRule *apipb.FileAccessRule
	for _, rule := range rules {
		if rule.Name == "SudoProtection" {
			sudoRule = rule
			break
		}
	}
	must.NotNil(t, sudoRule)

	test.Eq(t, "SudoProtection", sudoRule.Name)
	test.Eq(t, 2, len(sudoRule.PathPrefixes))
	test.Eq(t, "/private/var/db/sudo", sudoRule.PathPrefixes[0])
	test.Eq(t, "/etc/sudoers.d", sudoRule.PathPrefixes[1])
}

func TestParseRulesFromFileSploitlightProtection(t *testing.T) {
	rules, err := faa.ParseRulesFromFile("faa.plist")
	must.NoError(t, err)

	// Find the SploitlightProtection rule
	var sploitlightRule *apipb.FileAccessRule
	for _, rule := range rules {
		if rule.Name == "SploitlightProtection" {
			sploitlightRule = rule
			break
		}
	}
	must.NotNil(t, sploitlightRule)

	test.Eq(t, "SploitlightProtection", sploitlightRule.Name)
	test.Eq(t, true, sploitlightRule.AllowReadAccess)
	test.Eq(t, true, sploitlightRule.EnableSilentMode)
}

func TestParseRulesFromFileSlackCookies(t *testing.T) {
	rules, err := faa.ParseRulesFromFile("faa.plist")
	must.NoError(t, err)

	// Find the SlackCookies rule
	var slackRule *apipb.FileAccessRule
	for _, rule := range rules {
		if rule.Name == "SlackCookies" {
			slackRule = rule
			break
		}
	}
	must.NotNil(t, slackRule)

	test.Eq(t, "SlackCookies", slackRule.Name)
	test.Eq(t, 4, len(slackRule.PathPrefixes))
	test.Eq(t, apipb.FileAccessRuleType_FILE_ACCESS_RULE_TYPE_PATHS_WITH_ALLOWED_PROCESSES, slackRule.RuleType)
	must.Positive(t, len(slackRule.ProcessSigningIds))
	must.Positive(t, len(slackRule.ProcessTeamIds))
}

func TestParseRulesFromFileNotFound(t *testing.T) {
	_, err := faa.ParseRulesFromFile("nonexistent.plist")
	must.Error(t, err)
	must.StrContains(t, err.Error(), "failed to open plist file")
}

func TestParseRulesFromFileInvalidPlist(t *testing.T) {
	// Create a temporary invalid plist file
	tmpFile, err := os.CreateTemp("", "invalid-*.plist")
	must.NoError(t, err)
	defer os.Remove(tmpFile.Name())

	_, err = tmpFile.WriteString("invalid plist content")
	must.NoError(t, err)
	tmpFile.Close()

	_, err = faa.ParseRulesFromFile(tmpFile.Name())
	must.Error(t, err)
	must.StrContains(t, err.Error(), "failed to decode plist")
}
