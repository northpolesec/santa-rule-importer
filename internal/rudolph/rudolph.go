package rudolph

import (
	"encoding/csv"
	"fmt"
	"io"
	"os"

	"github.com/northpolesec/santa-rule-importer/internal/rulehelpers"

	apipb "buf.build/gen/go/northpolesec/workshop-api/protocolbuffers/go/workshop/v1"
)

// Rudolph CSV column names
const (
	ColIdentifier  = "identifier"
	ColType        = "type"
	ColPolicy      = "policy"
	ColCustomMsg   = "custom_msg"
	ColDescription = "description"
)

func ParseRulesFromFile(filePath string) ([]*apipb.Rule, error) {
	// Open the CSV file
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	// Create a new CSV reader
	reader := csv.NewReader(file)

	// Read the header row
	header, err := reader.Read()
	if err != nil {
		return nil, fmt.Errorf("error reading CSV header: %w", err)
	}

	// Map column indices
	colIndices := make(map[string]int)
	for i, col := range header {
		colIndices[col] = i
	}

	// Required columns
	requiredCols := []string{ColIdentifier, ColType, ColPolicy}
	for _, col := range requiredCols {
		if _, ok := colIndices[col]; !ok {
			return nil, fmt.Errorf("missing required column: %s", col)
		}
	}

	rules := []*apipb.Rule{}

	// Read data rows
	for {
		row, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}

		// Extract rule fields from the row
		identifier := row[colIndices[ColIdentifier]]
		ruleType := row[colIndices[ColType]]
		policy := row[colIndices[ColPolicy]]

		// Optional fields
		customMsg := ""
		if idx, ok := colIndices[ColCustomMsg]; ok && idx < len(row) {
			customMsg = row[idx]
		}

		comment := ""
		if idx, ok := colIndices[ColDescription]; ok && idx < len(row) {
			comment = row[idx]
		}

		rules = append(rules, &apipb.Rule{
			RuleType:   rulehelpers.GetRuleType(ruleType),
			Policy:     rulehelpers.GetPolicyType(policy),
			Identifier: identifier,
			CustomMsg:  customMsg,
			Comment:    comment,
		})
	}

	return rules, nil
}
