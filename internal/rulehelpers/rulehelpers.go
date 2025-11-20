package rulehelpers

import (
	"log"
	"strings"

	apipb "buf.build/gen/go/northpolesec/workshop-api/protocolbuffers/go/workshop/v1"
)

// GetPolicyType maps a string to a apipb.Policy type or panics if it's unknown.
func GetPolicyType(policy string) apipb.Policy {
	policy = strings.ToUpper(policy)
	switch policy {
	case "ALLOWLIST", "ALLOW":
		return apipb.Policy_ALLOWLIST
	case "BLOCK", "BLOCKLIST":
		return apipb.Policy_BLOCKLIST
	default:
		log.Fatalf("Unknown policy type: %s", policy)
		return apipb.Policy_POLICY_UNKNOWN
	}
}

// GetRuleType maps a string to a apipb.RuleType type or panics if it's unknown.
func GetRuleType(ruleType string) apipb.RuleType {
	ruleType = strings.ToUpper(ruleType)
	switch ruleType {
	case "CDHASH":
		return apipb.RuleType_CDHASH
	case "SHA256", "BINARY":
		return apipb.RuleType_BINARY
	case "SIGNINGID":
		return apipb.RuleType_SIGNINGID
	case "CERTIFICATE":
		return apipb.RuleType_CERTIFICATE
	case "TEAMID":
		return apipb.RuleType_TEAMID
	default:
		log.Fatalf("Unknown rule type: %s", ruleType)
		// Should never reach here, but return BINARY as a fallback
		return apipb.RuleType_BINARY
	}
}
