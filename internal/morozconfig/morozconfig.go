package morozconfig

import (
	"os"

	"github.com/northpolesec/santa-rule-importer/internal/rulehelpers"
	"github.com/pelletier/go-toml/v2"

	apipb "buf.build/gen/go/northpolesec/workshop-api/protocolbuffers/go/workshop/v1"
)

// Rule represents a single rule from the configuration
type Rule struct {
	RuleType   string `toml:"rule_type"`
	Policy     string `toml:"policy"`
	Identifier string `toml:"identifier"`
	CustomMsg  string `toml:"custom_msg"`
	CustomURL  string `toml:"custom_url"`
}

// Config represents the overall configuration structure
type Config struct {
	Rules []Rule `toml:"rules"`
}

// ParseRulesFromFile reads a moroz TOML configuration file and returns a slice
// of rules.
func ParseRulesFromFile(filePath string, useCustomMsgAsComment bool) ([]*apipb.Rule, error) {
	// Read the file content
	tomlData, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	var config Config
	err = toml.Unmarshal(tomlData, &config)
	if err != nil {
		return nil, err
	}

	rules := []*apipb.Rule{}

	for _, rule := range config.Rules {
		comment := ""

		if useCustomMsgAsComment {
			comment = rule.CustomMsg
		}
		rules = append(rules, &apipb.Rule{
			RuleType:   rulehelpers.GetRuleType(rule.RuleType),
			Policy:     rulehelpers.GetPolicyType(rule.Policy),
			Identifier: rule.Identifier,
			CustomMsg:  rule.CustomMsg,
			CustomUrl:  rule.CustomURL,
			Comment:    comment,
		})
	}

	return rules, nil
}
