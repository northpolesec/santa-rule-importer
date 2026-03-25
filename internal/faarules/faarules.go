package faarules

import (
	"fmt"
	"log"
	"os"
	"strings"

	"howett.net/plist"

	apipb "buf.build/gen/go/northpolesec/workshop-api/protocolbuffers/go/workshop/v1"
)

// FAAPolicy represents the root structure of a Santa File Access Authorization policy plist.
type FAAPolicy struct {
	Version         string              `plist:"Version"`
	EventDetailURL  string              `plist:"EventDetailURL"`
	EventDetailText string              `plist:"EventDetailText"`
	WatchItems      map[string]WatchItem `plist:"WatchItems"`
}

// WatchItem represents a single watch item rule in the FAA policy.
type WatchItem struct {
	Paths     []PathEntry    `plist:"Paths"`
	Processes []ProcessEntry `plist:"Processes"`
	Options   Options        `plist:"Options"`
}

// PathEntry represents a path to monitor.
type PathEntry struct {
	Path     string `plist:"Path"`
	IsPrefix bool   `plist:"IsPrefix"`
}

// ProcessEntry represents a process identifier in a watch item.
type ProcessEntry struct {
	SigningID         string `plist:"SigningID"`
	TeamID            string `plist:"TeamID"`
	CDHash            string `plist:"CDHash"`
	CertificateSha256 string `plist:"CertificateSha256"`
	BinaryPath        string `plist:"BinaryPath"`
	PlatformBinary    *bool  `plist:"PlatformBinary"`
}

// Options represents the options for a watch item rule.
type Options struct {
	RuleType            string `plist:"RuleType"`
	AllowReadAccess     *bool  `plist:"AllowReadAccess"`
	AuditOnly           *bool  `plist:"AuditOnly"`
	EventDetailURL      string `plist:"EventDetailURL"`
	EventDetailText     string `plist:"EventDetailText"`
	BlockMessage        string `plist:"BlockMessage"`
	EnableSilentMode    bool   `plist:"EnableSilentMode"`
	EnableSilentTTYMode bool   `plist:"EnableSilentTTYMode"`
}

// MobileConfig represents the structure of a Santa mobileconfig file.
type MobileConfig struct {
	PayloadContent []PayloadContent `plist:"PayloadContent"`
}

// PayloadContent represents the Santa configuration payload within a mobileconfig.
type PayloadContent struct {
	FileAccessPolicy *FAAPolicy `plist:"FileAccessPolicy"`
}

// ParseRulesFromFile reads a standalone FAA policy plist file and returns
// FileAccessRule objects for the Workshop API.
func ParseRulesFromFile(filePath string) ([]*apipb.FileAccessRule, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var policy FAAPolicy
	decoder := plist.NewDecoder(f)
	if err := decoder.Decode(&policy); err != nil {
		return nil, fmt.Errorf("failed to decode FAA policy plist: %w", err)
	}

	return convertWatchItems(&policy)
}

// ParseRulesFromMobileConfig extracts the FileAccessPolicy from a mobileconfig
// file and returns FileAccessRule objects for the Workshop API.
func ParseRulesFromMobileConfig(filePath string) ([]*apipb.FileAccessRule, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var config MobileConfig
	decoder := plist.NewDecoder(f)
	if err := decoder.Decode(&config); err != nil {
		return nil, fmt.Errorf("failed to decode mobileconfig: %w", err)
	}

	if len(config.PayloadContent) == 0 {
		return nil, nil
	}

	policy := config.PayloadContent[0].FileAccessPolicy
	if policy == nil {
		return nil, nil
	}

	return convertWatchItems(policy)
}

func convertWatchItems(policy *FAAPolicy) ([]*apipb.FileAccessRule, error) {
	if len(policy.WatchItems) == 0 {
		return []*apipb.FileAccessRule{}, nil
	}

	var rules []*apipb.FileAccessRule
	for name, item := range policy.WatchItems {
		rule, err := convertWatchItem(name, &item, policy)
		if err != nil {
			return nil, fmt.Errorf("watch item %q: %w", name, err)
		}
		if rule != nil {
			rules = append(rules, rule)
		}
	}

	return rules, nil
}

func convertWatchItem(name string, item *WatchItem, policy *FAAPolicy) (*apipb.FileAccessRule, error) {
	var pathLiterals, pathPrefixes []string
	for _, p := range item.Paths {
		if p.IsPrefix {
			pathPrefixes = append(pathPrefixes, p.Path)
		} else {
			pathLiterals = append(pathLiterals, p.Path)
		}
	}

	var (
		signingIDs    []string
		teamIDs       []string
		cdHashes      []string
		certSha256s   []string
		binaryPaths   []string
	)

	for _, proc := range item.Processes {
		if proc.PlatformBinary != nil && *proc.PlatformBinary {
			if proc.SigningID != "" {
				signingIDs = append(signingIDs, "platform:"+proc.SigningID)
			} else {
				log.Printf("Warning: skipping watch item %q: PlatformBinary is true but no SigningID is set", name)
				return nil, nil
			}
			continue
		}
		if proc.SigningID != "" && proc.TeamID != "" {
			signingIDs = append(signingIDs, proc.TeamID+":"+proc.SigningID)
		} else if proc.SigningID != "" {
			signingIDs = append(signingIDs, proc.SigningID)
		}
		if proc.TeamID != "" && proc.SigningID == "" {
			teamIDs = append(teamIDs, proc.TeamID)
		}
		if proc.CDHash != "" {
			cdHashes = append(cdHashes, proc.CDHash)
		}
		if proc.CertificateSha256 != "" {
			certSha256s = append(certSha256s, proc.CertificateSha256)
		}
		if proc.BinaryPath != "" {
			binaryPaths = append(binaryPaths, proc.BinaryPath)
		}
	}

	// AllowReadAccess defaults to true
	allowReadAccess := true
	if item.Options.AllowReadAccess != nil {
		allowReadAccess = *item.Options.AllowReadAccess
	}

	// AuditOnly defaults to true; BlockViolations is the inverse
	blockViolations := false
	if item.Options.AuditOnly != nil {
		blockViolations = !*item.Options.AuditOnly
	}

	// EventDetailUrl: use per-rule value, fall back to root-level
	eventDetailURL := item.Options.EventDetailURL
	if eventDetailURL == "" {
		eventDetailURL = policy.EventDetailURL
	}

	// EventDetailText: use per-rule value, fall back to root-level
	eventDetailText := item.Options.EventDetailText
	if eventDetailText == "" {
		eventDetailText = policy.EventDetailText
	}

	rule := &apipb.FileAccessRule{
		Name:                    name,
		RuleType:                getRuleType(item.Options.RuleType),
		AllowReadAccess:         allowReadAccess,
		BlockViolations:         blockViolations,
		EnableSilentMode:        item.Options.EnableSilentMode,
		EnableSilentTtyMode:     item.Options.EnableSilentTTYMode,
		BlockMessage:            item.Options.BlockMessage,
		EventDetailUrl:          eventDetailURL,
		EventDetailText:         eventDetailText,
		PathLiterals:            pathLiterals,
		PathPrefixes:            pathPrefixes,
		ProcessSigningIds:       signingIDs,
		ProcessTeamIds:          teamIDs,
		ProcessCdHashes:         cdHashes,
		ProcessCertificateSha256S: certSha256s,
		ProcessBinaryPaths:      binaryPaths,
	}

	return rule, nil
}

func getRuleType(s string) apipb.FileAccessRuleType {
	switch strings.ToUpper(s) {
	case "PATHSWITHALLOWEDPROCESSES":
		return apipb.FileAccessRuleType_FILE_ACCESS_RULE_TYPE_PATHS_WITH_ALLOWED_PROCESSES
	case "PATHSWITHDENIEDPROCESSES":
		return apipb.FileAccessRuleType_FILE_ACCESS_RULE_TYPE_PATHS_WITH_DENIED_PROCESSES
	case "PROCESSESWITHALLOWEDPATHS":
		return apipb.FileAccessRuleType_FILE_ACCESS_RULE_TYPE_PROCESSES_WITH_ALLOWED_PATHS
	case "PROCESSESWITHDENIEDPATHS":
		return apipb.FileAccessRuleType_FILE_ACCESS_RULE_TYPE_PROCESSES_WITH_DENIED_PATHS
	default:
		return apipb.FileAccessRuleType_FILE_ACCESS_RULE_TYPE_UNSPECIFIED
	}
}
