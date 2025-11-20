package faa

import (
	"fmt"
	"os"

	"github.com/micromdm/plist"

	apipb "buf.build/gen/go/northpolesec/workshop-api/protocolbuffers/go/workshop/v1"
)

// Plist represents the root structure of the FAA plist file
type Plist struct {
	Version    string               `plist:"Version"`
	WatchItems map[string]WatchItem `plist:"WatchItems"`
}

// WatchItem represents a single file access rule in the plist
type WatchItem struct {
	Paths     []PathItem    `plist:"Paths"`
	Options   Options       `plist:"Options"`
	Processes []ProcessItem `plist:"Processes"`
}

// PathItem represents a path to watch
type PathItem struct {
	Path     string `plist:"Path"`
	IsPrefix bool   `plist:"IsPrefix"`
}

// Options represents the options for a watch item
type Options struct {
	AllowReadAccess     *bool  `plist:"AllowReadAccess,omitempty"`
	AuditOnly           *bool  `plist:"AuditOnly,omitempty"`
	EnableSilentMode    *bool  `plist:"EnableSilentMode,omitempty"`
	EnableSilentTTYMode *bool  `plist:"EnableSilentTTYMode,omitempty"`
	RuleType            string `plist:"RuleType,omitempty"`
}

// ProcessItem represents a process that can access the paths
type ProcessItem struct {
	TeamID         string `plist:"TeamID,omitempty"`
	SigningID      string `plist:"SigningID,omitempty"`
	PlatformBinary *bool  `plist:"PlatformBinary,omitempty"`
}

// ParseRulesFromFile reads an FAA plist file and returns a slice of FileAccessRule protobuf messages
func ParseRulesFromFile(filePath string) ([]*apipb.FileAccessRule, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open plist file: %w", err)
	}
	defer file.Close()

	var plistData Plist
	decoder := plist.NewDecoder(file)
	if err := decoder.Decode(&plistData); err != nil {
		return nil, fmt.Errorf("failed to decode plist: %w", err)
	}

	var rules []*apipb.FileAccessRule

	for name, watchItem := range plistData.WatchItems {
		rule, err := convertWatchItemToFileAccessRule(name, watchItem)
		if err != nil {
			return nil, fmt.Errorf("failed to convert watch item %s: %w", name, err)
		}
		rules = append(rules, rule)
	}

	return rules, nil
}

// convertWatchItemToFileAccessRule converts a WatchItem to a FileAccessRule protobuf message
func convertWatchItemToFileAccessRule(name string, item WatchItem) (*apipb.FileAccessRule, error) {
	rule := &apipb.FileAccessRule{
		Name: name,
	}

	// Convert paths
	var pathLiterals []string
	var pathPrefixes []string
	for _, pathItem := range item.Paths {
		if pathItem.IsPrefix {
			pathPrefixes = append(pathPrefixes, pathItem.Path)
		} else {
			pathLiterals = append(pathLiterals, pathItem.Path)
		}
	}
	rule.PathLiterals = pathLiterals
	rule.PathPrefixes = pathPrefixes

	// Convert options
	if item.Options.AllowReadAccess != nil {
		rule.AllowReadAccess = *item.Options.AllowReadAccess
	}
	if item.Options.AuditOnly != nil {
		// AuditOnly means we don't block, just monitor
		rule.BlockViolations = !*item.Options.AuditOnly
	} else {
		// Default to blocking if not specified
		rule.BlockViolations = true
	}
	if item.Options.EnableSilentMode != nil {
		rule.EnableSilentMode = *item.Options.EnableSilentMode
	}
	if item.Options.EnableSilentTTYMode != nil {
		rule.EnableSilentTtyMode = *item.Options.EnableSilentTTYMode
	}

	// Convert rule type
	if item.Options.RuleType != "" {
		ruleType, err := parseRuleType(item.Options.RuleType)
		if err != nil {
			return nil, fmt.Errorf("invalid rule type %s: %w", item.Options.RuleType, err)
		}
		rule.RuleType = ruleType
	} else {
		// Default to PATHS_WITH_DENIED_PROCESSES if not specified
		rule.RuleType = apipb.FileAccessRuleType_FILE_ACCESS_RULE_TYPE_PATHS_WITH_DENIED_PROCESSES
	}

	// Convert processes
	var processSigningIDs []string
	var processTeamIDs []string
	var processCDHashes []string
	var processCertificateSHA256s []string

	for _, proc := range item.Processes {
		if proc.SigningID != "" {
			processSigningIDs = append(processSigningIDs, proc.SigningID)
		}
		if proc.TeamID != "" {
			processTeamIDs = append(processTeamIDs, proc.TeamID)
		}
		// Note: PlatformBinary is a boolean flag in the plist but doesn't directly map
		// to a process identifier in the FileAccessRule. We'll need to handle this
		// differently - PlatformBinary processes are typically system processes that
		// should be allowed. For now, we'll just capture the SigningID.
	}

	rule.ProcessSigningIds = processSigningIDs
	rule.ProcessTeamIds = processTeamIDs
	rule.ProcessCdHashes = processCDHashes
	rule.ProcessCertificateSha256S = processCertificateSHA256s

	return rule, nil
}

// parseRuleType converts a string rule type to the protobuf enum
func parseRuleType(ruleType string) (apipb.FileAccessRuleType, error) {
	switch ruleType {
	case "PathsWithAllowedProcesses":
		return apipb.FileAccessRuleType_FILE_ACCESS_RULE_TYPE_PATHS_WITH_ALLOWED_PROCESSES, nil
	case "PathsWithDeniedProcesses":
		return apipb.FileAccessRuleType_FILE_ACCESS_RULE_TYPE_PATHS_WITH_DENIED_PROCESSES, nil
	case "ProcessesWithAllowedPaths":
		return apipb.FileAccessRuleType_FILE_ACCESS_RULE_TYPE_PROCESSES_WITH_ALLOWED_PATHS, nil
	case "ProcessesWithDeniedPaths":
		return apipb.FileAccessRuleType_FILE_ACCESS_RULE_TYPE_PROCESSES_WITH_DENIED_PATHS, nil
	default:
		return apipb.FileAccessRuleType_FILE_ACCESS_RULE_TYPE_UNSPECIFIED, fmt.Errorf("unknown rule type: %s", ruleType)
	}
}
