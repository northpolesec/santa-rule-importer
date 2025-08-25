package zentral

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"

	"github.com/northpolesec/santa-rule-importer/internal/rulehelpers"

	apipb "buf.build/gen/go/northpolesec/workshop-api/protocolbuffers/go/workshop/v1"
)

// Rule represents a Santa rule from Zentral API response
type Rule struct {
	ID                int    `json:"id"`
	TargetType        string `json:"target_type"`
	TargetIdentifier  string `json:"target_identifier"`
	Policy            string `json:"policy"`
	CustomMsg         string `json:"custom_msg"`
	Description       string `json:"description"`
	ConfigurationID   int    `json:"configuration"`
	CreatedAt         string `json:"created_at"`
	UpdatedAt         string `json:"updated_at"`
}

// APIResponse represents the paginated response from Zentral API
type APIResponse struct {
	Count    int    `json:"count"`
	Next     *string `json:"next"`
	Previous *string `json:"previous"`
	Results  []Rule `json:"results"`
}

// Client represents a Zentral API client
type Client struct {
	BaseURL    string
	Token      string
	HTTPClient *http.Client
}

// NewClient creates a new Zentral API client
func NewClient(baseURL, token string) *Client {
	return &Client{
		BaseURL:    baseURL,
		Token:      token,
		HTTPClient: &http.Client{},
	}
}

// makeRequest makes an authenticated HTTP request to the Zentral API
func (c *Client) makeRequest(endpoint string) (*http.Response, error) {
	// Parse base URL
	baseURL, err := url.Parse(c.BaseURL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse base URL: %w", err)
	}

	// Parse endpoint (which may contain query parameters)
	endpointURL, err := url.Parse(endpoint)
	if err != nil {
		return nil, fmt.Errorf("failed to parse endpoint: %w", err)
	}

	// Resolve the endpoint against the base URL
	fullURL := baseURL.ResolveReference(endpointURL)

	req, err := http.NewRequest("GET", fullURL.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Token "+c.Token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("HTTP request failed: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("API request failed with status %d: %s", resp.StatusCode, string(body))
	}

	return resp, nil
}

// GetRules retrieves all Santa rules from Zentral API with optional filters
func (c *Client) GetRules(targetType, targetIdentifier string, configurationID int) ([]Rule, error) {
	var allRules []Rule
	endpoint := "/api/santa/rules/"

	// Add query parameters if provided
	params := url.Values{}
	if targetType != "" {
		params.Set("target_type", targetType)
	}
	if targetIdentifier != "" {
		params.Set("target_identifier", targetIdentifier)
	}
	if configurationID > 0 {
		params.Set("configuration_id", strconv.Itoa(configurationID))
	}

	if len(params) > 0 {
		endpoint += "?" + params.Encode()
	}

	for {
		resp, err := c.makeRequest(endpoint)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("failed to read response body: %w", err)
		}

		var apiResp APIResponse
		if err := json.Unmarshal(body, &apiResp); err != nil {
			return nil, fmt.Errorf("failed to parse API response: %w", err)
		}

		allRules = append(allRules, apiResp.Results...)

		// Check if there are more pages
		if apiResp.Next == nil {
			break
		}

		// Parse the next URL to get just the path and query
		nextURL, err := url.Parse(*apiResp.Next)
		if err != nil {
			return nil, fmt.Errorf("failed to parse next URL: %w", err)
		}
		endpoint = nextURL.Path + "?" + nextURL.RawQuery
	}

	return allRules, nil
}

// ConvertToWorkshopRules converts Zentral rules to Workshop format
func ConvertToWorkshopRules(zenRules []Rule) []*apipb.Rule {
	rules := make([]*apipb.Rule, len(zenRules))

	for i, zenRule := range zenRules {
		rules[i] = &apipb.Rule{
			RuleType:   rulehelpers.GetRuleType(zenRule.TargetType),
			Policy:     rulehelpers.GetPolicyType(zenRule.Policy),
			Identifier: zenRule.TargetIdentifier,
			CustomMsg:  zenRule.CustomMsg,
			Comment:    zenRule.Description,
		}
	}

	return rules
}

// GetRulesFromZentral is a convenience function that fetches and converts rules
func GetRulesFromZentral(baseURL, token, targetType, targetIdentifier string, configurationID int) ([]*apipb.Rule, error) {
	client := NewClient(baseURL, token)
	
	zenRules, err := client.GetRules(targetType, targetIdentifier, configurationID)
	if err != nil {
		return nil, fmt.Errorf("failed to get rules from Zentral: %w", err)
	}

	return ConvertToWorkshopRules(zenRules), nil
}