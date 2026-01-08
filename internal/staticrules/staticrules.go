package staticrules

import (
	"fmt"
	"os"

	"howett.net/plist"
	"github.com/northpolesec/santa-rule-importer/internal/rulehelpers"

	apipb "buf.build/gen/go/northpolesec/workshop-api/protocolbuffers/go/workshop/v1"
)

// Rule represents a single rule from the StaticRules array in a mobileconfig file.
type Rule struct {
	Identifier string `plist:"identifier"`
	Policy     string `plist:"policy"`
	RuleType   string `plist:"rule_type"`
	CustomMsg  string `plist:"custom_msg"`
	CustomURL  string `plist:"custom_url"`
	CelExpr    string `plist:"cel_expr"`
	Comment    string `plist:"comment"`
}

// PayloadContent represents the Santa configuration payload within a mobileconfig.
type PayloadContent struct {
	StaticRules []Rule `plist:"StaticRules"`
}

// MobileConfig represents the structure of a Santa mobileconfig file.
type MobileConfig struct {
	PayloadContent []PayloadContent `plist:"PayloadContent"`
}

// ParseRulesFromFile reads a mobileconfig file and returns the rules from the
// StaticRules array converted to Workshop API format.
func ParseRulesFromFile(filePath string) ([]*apipb.Rule, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var config MobileConfig
	decoder := plist.NewDecoder(f)
	if err := decoder.Decode(&config); err != nil {
		return nil, fmt.Errorf("failed to decode plist: %w", err)
	}

	if len(config.PayloadContent) == 0 {
		return nil, fmt.Errorf("no PayloadContent found in mobileconfig")
	}

	staticRules := config.PayloadContent[0].StaticRules
	if len(staticRules) == 0 {
		return []*apipb.Rule{}, nil
	}

	rules := make([]*apipb.Rule, len(staticRules))
	for i, rule := range staticRules {
		rules[i] = &apipb.Rule{
			RuleType:   rulehelpers.GetRuleType(rule.RuleType),
			Policy:     rulehelpers.GetPolicyType(rule.Policy),
			Identifier: rule.Identifier,
			CustomMsg:  rule.CustomMsg,
			CustomUrl:  rule.CustomURL,
			CelExpr:    rule.CelExpr,
			Comment:    rule.Comment,
		}
	}

	return rules, nil
}
