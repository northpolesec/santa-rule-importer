package rulehelpers

import (
	"log"
	"strings"

	syncpb "buf.build/gen/go/northpolesec/protos/protocolbuffers/go/sync"
)

// GetPolicyType maps a string to a syncpb.Policy type or panics if it's unknown.
func GetPolicyType(policy string) syncpb.Policy {
	policy = strings.ToUpper(policy)
	switch policy {
	case "ALLOWLIST", "ALLOW":
		return syncpb.Policy_ALLOWLIST
	case "BLOCK", "BLOCKLIST":
		return syncpb.Policy_BLOCKLIST
	default:
		log.Fatalf("Unknown policy type: %s", policy)
		return syncpb.Policy_POLICY_UNKNOWN
	}
}

// GetRuleType maps a string to a syncpb.RuleType type or panics if it's unknown.
func GetRuleType(ruleType string) syncpb.RuleType {
	ruleType = strings.ToUpper(ruleType)
	switch ruleType {
	case "CDHASH":
		return syncpb.RuleType_CDHASH
	case "SHA256", "BINARY":
		return syncpb.RuleType_BINARY
	case "SIGNINGID":
		return syncpb.RuleType_SIGNINGID
	case "CERTIFICATE":
		return syncpb.RuleType_CERTIFICATE
	case "TEAMID":
		return syncpb.RuleType_TEAMID
	default:
		log.Fatalf("Unknown rule type: %s", ruleType)
		// Should never reach here, but return BINARY as a fallback
		return syncpb.RuleType_BINARY
	}
}
