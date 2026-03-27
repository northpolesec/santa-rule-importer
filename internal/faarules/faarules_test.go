package faarules_test

import (
	"testing"

	"github.com/northpolesec/santa-rule-importer/internal/faarules"
	"github.com/shoenig/test"
	"github.com/shoenig/test/must"

	apipb "buf.build/gen/go/northpolesec/workshop-api/protocolbuffers/go/workshop/v1"
)

func findRule(rules []*apipb.FileAccessRule, name string) *apipb.FileAccessRule {
	for _, r := range rules {
		if r.GetName() == name {
			return r
		}
	}
	return nil
}

func TestParseRulesFromFile(t *testing.T) {
	rules, err := faarules.ParseRulesFromFile("testdata/faa_policy.plist")
	must.NoError(t, err)
	must.Eq(t, 4, len(rules))

	// SensitiveData: all fields explicitly set
	r := findRule(rules, "SensitiveData")
	must.NotNil(t, r)
	test.Eq(t, apipb.FileAccessRuleType_FILE_ACCESS_RULE_TYPE_PATHS_WITH_ALLOWED_PROCESSES, r.GetRuleType())
	test.Eq(t, false, r.GetAllowReadAccess())
	test.Eq(t, true, r.GetBlockViolations())
	test.Eq(t, "https://example.com/rule-specific", r.GetEventDetailUrl())
	test.Eq(t, "Rule Help", r.GetEventDetailText())
	test.Eq(t, "Access denied to sensitive data", r.GetBlockMessage())
	test.Eq(t, true, r.GetEnableSilentMode())
	test.Eq(t, true, r.GetEnableSilentTtyMode())

	// Paths: /etc/passwd as literal, /var/secrets/ as prefix
	test.SliceContains(t, r.GetPathLiterals(), "/etc/passwd")
	test.SliceContains(t, r.GetPathPrefixes(), "/var/secrets/")

	// Processes
	test.SliceContains(t, r.GetProcessSigningIds(), "EQHXZ8M8AV:com.google.Chrome")
	test.SliceContains(t, r.GetProcessTeamIds(), "ZMCG7MLDV9")
	test.SliceContains(t, r.GetProcessCdHashes(), "abc123")
	test.SliceContains(t, r.GetProcessCertificateSha256S(), "deadbeef")
	test.SliceContains(t, r.GetProcessBinaryPaths(), "/usr/bin/cat")
}

func TestParseRulesFromFile_Defaults(t *testing.T) {
	rules, err := faarules.ParseRulesFromFile("testdata/faa_policy.plist")
	must.NoError(t, err)

	// DefaultsRule: AuditOnly and AllowReadAccess not set, should use defaults
	r := findRule(rules, "DefaultsRule")
	must.NotNil(t, r)
	test.Eq(t, apipb.FileAccessRuleType_FILE_ACCESS_RULE_TYPE_PATHS_WITH_DENIED_PROCESSES, r.GetRuleType())

	// AllowReadAccess defaults to true
	test.Eq(t, true, r.GetAllowReadAccess())

	// AuditOnly defaults to true → BlockViolations defaults to false
	test.Eq(t, false, r.GetBlockViolations())

	// Falls back to root-level EventDetailURL and EventDetailText
	test.Eq(t, "https://example.com/faa?rule=%rule_name%", r.GetEventDetailUrl())
	test.Eq(t, "View Details", r.GetEventDetailText())

	// Other options default to zero values
	test.Eq(t, false, r.GetEnableSilentMode())
	test.Eq(t, false, r.GetEnableSilentTtyMode())
	test.Eq(t, "", r.GetBlockMessage())
}

func TestParseRulesFromFile_TeamAndSigningID(t *testing.T) {
	rules, err := faarules.ParseRulesFromFile("testdata/faa_policy.plist")
	must.NoError(t, err)

	r := findRule(rules, "TeamSigningIDRule")
	must.NotNil(t, r)
	// TeamID + SigningID should be combined as TeamID:SigningID
	test.SliceContains(t, r.GetProcessSigningIds(), "EQHXZ8M8AV:com.google.Chrome")
	// TeamID should NOT appear separately since it was combined with SigningID
	test.Eq(t, 0, len(r.GetProcessTeamIds()))
}

func TestParseRulesFromFile_PlatformBinary(t *testing.T) {
	rules, err := faarules.ParseRulesFromFile("testdata/faa_policy.plist")
	must.NoError(t, err)

	// PlatformBinaryRule: PlatformBinary=true with SigningID should produce platform:<SigningID>
	r := findRule(rules, "PlatformBinaryRule")
	must.NotNil(t, r)
	test.SliceContains(t, r.GetProcessSigningIds(), "platform:com.apple.mdmclient")
}

func TestParseRulesFromMobileConfig(t *testing.T) {
	rules, err := faarules.ParseRulesFromMobileConfig("testdata/santa_with_faa.mobileconfig")
	must.NoError(t, err)
	must.Eq(t, 1, len(rules))

	r := rules[0]
	test.Eq(t, "ConfigData", r.GetName())
	test.Eq(t, apipb.FileAccessRuleType_FILE_ACCESS_RULE_TYPE_PATHS_WITH_ALLOWED_PROCESSES, r.GetRuleType())
	test.Eq(t, true, r.GetBlockViolations()) // AuditOnly=false → BlockViolations=true
	test.Eq(t, true, r.GetAllowReadAccess()) // default
	test.SliceContains(t, r.GetPathPrefixes(), "/etc/ssh/")
	test.SliceContains(t, r.GetProcessSigningIds(), "com.openssh.sshd")
	test.Eq(t, "https://example.com/mobileconfig-faa", r.GetEventDetailUrl())
}

func TestParseRulesFromMobileConfig_NoFAA(t *testing.T) {
	// staticrules mobileconfig has no FileAccessPolicy
	rules, err := faarules.ParseRulesFromMobileConfig("../../internal/staticrules/testdata/santa.mobileconfig")
	must.NoError(t, err)
	test.Nil(t, rules)
}
