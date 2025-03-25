package santactl

import (
	"encoding/json"
	"os"

	"github.com/northpolesec/santa-rule-importer/internal/rulehelpers"

	apipb "buf.build/gen/go/northpolesec/workshop-api/protocolbuffers/go/workshop/v1"
)

type Rule struct {
	RuleType   string `json:"rule_type"`
	Policy     string `json:"policy"`
	Identifier string `json:"identifier"`
	CustomMsg  string `json:"custom_msg"`
	CustomURL  string `json:"custom_url"`
	Comment    string `json:"comment"`
}

type RulesFile struct {
	Rules []Rule `json:"rules"`
}

func ParseRulesFromFile(filePath string) ([]*apipb.Rule, error) {
	// Read the file content
	f, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}
	var rulesFile RulesFile
	err = json.Unmarshal(f, &rulesFile)
	if err != nil {
		return nil, err
	}
	rules := make([]*apipb.Rule, len(rulesFile.Rules))
	for i, rule := range rulesFile.Rules {
		rules[i] = &apipb.Rule{
			RuleType:   rulehelpers.GetRuleType(rule.RuleType),
			Policy:     rulehelpers.GetPolicyType(rule.Policy),
			Identifier: rule.Identifier,
			CustomMsg:  rule.CustomMsg,
			CustomUrl:  rule.CustomURL,
			Comment:    rule.Comment,
		}
	}

	return rules, nil
}
