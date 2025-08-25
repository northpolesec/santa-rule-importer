package zentral_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/shoenig/test"
	"github.com/shoenig/test/must"

	"github.com/northpolesec/santa-rule-importer/internal/zentral"
)

func TestNewClient(t *testing.T) {
	baseURL := "https://zentral.example.com"
	token := "test-token"
	
	client := zentral.NewClient(baseURL, token)
	
	test.Eq(t, baseURL, client.BaseURL)
	test.Eq(t, token, client.Token)
	must.NotNil(t, client.HTTPClient)
}

func TestClientGetRules(t *testing.T) {
	// Load test data
	testData, err := os.ReadFile("testdata/zentral_rules.json")
	must.NoError(t, err)
	
	// Create test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify the request
		test.Eq(t, "/api/santa/rules/", r.URL.Path)
		test.Eq(t, "Token test-token", r.Header.Get("Authorization"))
		test.Eq(t, "application/json", r.Header.Get("Content-Type"))
		
		// Return test data
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write(testData)
	}))
	defer server.Close()
	
	client := zentral.NewClient(server.URL, "test-token")
	rules, err := client.GetRules("", "", 0)
	
	must.NoError(t, err)
	test.Eq(t, 3, len(rules))
	
	// Check first rule
	test.Eq(t, 1, rules[0].ID)
	test.Eq(t, "BINARY", rules[0].TargetType)
	test.Eq(t, "a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3", rules[0].TargetIdentifier)
	test.Eq(t, "BLOCKLIST", rules[0].Policy)
	test.Eq(t, "Malicious binary detected", rules[0].CustomMsg)
	test.Eq(t, "Known malware hash from threat intel", rules[0].Description)
	test.Eq(t, 123, rules[0].ConfigurationID)
	
	// Check second rule
	test.Eq(t, 2, rules[1].ID)
	test.Eq(t, "CERTIFICATE", rules[1].TargetType)
	test.Eq(t, "59FB936AC5B6FED8A00F7F8CFBCD5A5A6F4F7D9A5D2E8A8A8A8A8A8A8A8A8A8A", rules[1].TargetIdentifier)
	test.Eq(t, "ALLOWLIST", rules[1].Policy)
	test.Eq(t, "Trusted certificate", rules[1].CustomMsg)
	test.Eq(t, "Certificate for approved application", rules[1].Description)
	test.Eq(t, 123, rules[1].ConfigurationID)
	
	// Check third rule
	test.Eq(t, 3, rules[2].ID)
	test.Eq(t, "TEAMID", rules[2].TargetType)
	test.Eq(t, "ABCDEF1234", rules[2].TargetIdentifier)
	test.Eq(t, "ALLOWLIST", rules[2].Policy)
	test.Eq(t, "", rules[2].CustomMsg)
	test.Eq(t, "Apple Developer Team ID", rules[2].Description)
	test.Eq(t, 456, rules[2].ConfigurationID)
}

func TestClientGetRulesWithFilters(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify path and query parameters
		test.Eq(t, "/api/santa/rules/", r.URL.Path)
		query := r.URL.Query()
		test.Eq(t, "BINARY", query.Get("target_type"))
		test.Eq(t, "somehash", query.Get("target_identifier"))
		test.Eq(t, "123", query.Get("configuration_id"))
		
		// Return empty result
		response := zentral.APIResponse{
			Count:    0,
			Next:     nil,
			Previous: nil,
			Results:  []zentral.Rule{},
		}
		
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()
	
	client := zentral.NewClient(server.URL, "test-token")
	rules, err := client.GetRules("BINARY", "somehash", 123)
	
	must.NoError(t, err)
	test.Eq(t, 0, len(rules))
}

func TestClientGetRulesPaginated(t *testing.T) {
	page1Data, err := os.ReadFile("testdata/zentral_paginated_page1.json")
	must.NoError(t, err)
	
	page2Data, err := os.ReadFile("testdata/zentral_paginated_page2.json")
	must.NoError(t, err)
	
	requestCount := 0
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		
		// Fix the pagination by updating the next URL to point to our test server
		if r.URL.Query().Get("page") == "2" {
			w.Write(page2Data)
		} else {
			// Replace the next URL with our test server URL
			var response zentral.APIResponse
			json.Unmarshal(page1Data, &response)
			nextURL := server.URL + "/api/santa/rules/?page=2"
			response.Next = &nextURL
			json.NewEncoder(w).Encode(response)
		}
	}))
	defer server.Close()
	
	client := zentral.NewClient(server.URL, "test-token")
	rules, err := client.GetRules("", "", 0)
	
	must.NoError(t, err)
	test.Eq(t, 3, len(rules)) // Total rules across both pages
	test.Eq(t, 2, requestCount) // Should have made 2 requests
	
	// Check that we got rules from both pages
	test.Eq(t, "hash1", rules[0].TargetIdentifier)
	test.Eq(t, "cert1", rules[1].TargetIdentifier)
	test.Eq(t, "team1", rules[2].TargetIdentifier)
}

func TestClientGetRulesAPIError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte("Unauthorized"))
	}))
	defer server.Close()
	
	client := zentral.NewClient(server.URL, "invalid-token")
	_, err := client.GetRules("", "", 0)
	
	must.Error(t, err)
	must.StrContains(t, err.Error(), "API request failed with status 401")
}

func TestClientGetRulesInvalidJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("invalid json"))
	}))
	defer server.Close()
	
	client := zentral.NewClient(server.URL, "test-token")
	_, err := client.GetRules("", "", 0)
	
	must.Error(t, err)
	must.StrContains(t, err.Error(), "failed to parse API response")
}

func TestConvertToWorkshopRules(t *testing.T) {
	zenRules := []zentral.Rule{
		{
			ID:               1,
			TargetType:       "BINARY",
			TargetIdentifier: "hash123",
			Policy:           "BLOCKLIST",
			CustomMsg:        "Blocked binary",
			Description:      "Malicious file",
			ConfigurationID:  123,
		},
		{
			ID:               2,
			TargetType:       "CERTIFICATE",
			TargetIdentifier: "cert456",
			Policy:           "ALLOWLIST",
			CustomMsg:        "Trusted cert",
			Description:      "Known good certificate",
			ConfigurationID:  456,
		},
	}
	
	workshopRules := zentral.ConvertToWorkshopRules(zenRules)
	
	test.Eq(t, 2, len(workshopRules))
	
	// Check first rule conversion
	test.Eq(t, "BINARY", workshopRules[0].RuleType.String())
	test.Eq(t, "BLOCKLIST", workshopRules[0].Policy.String())
	test.Eq(t, "hash123", workshopRules[0].Identifier)
	test.Eq(t, "Blocked binary", workshopRules[0].CustomMsg)
	test.Eq(t, "Malicious file", workshopRules[0].Comment)
	
	// Check second rule conversion
	test.Eq(t, "CERTIFICATE", workshopRules[1].RuleType.String())
	test.Eq(t, "ALLOWLIST", workshopRules[1].Policy.String())
	test.Eq(t, "cert456", workshopRules[1].Identifier)
	test.Eq(t, "Trusted cert", workshopRules[1].CustomMsg)
	test.Eq(t, "Known good certificate", workshopRules[1].Comment)
}

func TestGetRulesFromZentral(t *testing.T) {
	testData, err := os.ReadFile("testdata/zentral_rules.json")
	must.NoError(t, err)
	
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write(testData)
	}))
	defer server.Close()
	
	rules, err := zentral.GetRulesFromZentral(server.URL, "test-token", "", "", 0)
	
	must.NoError(t, err)
	test.Eq(t, 3, len(rules))
	
	// Check that rules are properly converted
	test.Eq(t, "BINARY", rules[0].RuleType.String())
	test.Eq(t, "BLOCKLIST", rules[0].Policy.String())
	test.Eq(t, "a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3", rules[0].Identifier)
	test.Eq(t, "Malicious binary detected", rules[0].CustomMsg)
	test.Eq(t, "Known malware hash from threat intel", rules[0].Comment)
}