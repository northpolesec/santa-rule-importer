package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/user"
	"path/filepath"

	"github.com/golang-jwt/jwt/v5"
	"github.com/pkg/browser"
	"golang.org/x/oauth2"
	"google.golang.org/grpc/credentials"
)

const (
	// Path, relative to the user's home directory, where the token should be stored.
	tokenFilePathSuffix = ".config/nps_token.json"
)

// tokenFilePath returns the full path to the token file.
// Overridden in tests via tokenFilePathOverride.
var tokenFilePathOverride string

func tokenFilePath() (string, error) {
	if tokenFilePathOverride != "" {
		return tokenFilePathOverride, nil
	}
	usr, err := user.Current()
	if err != nil {
		return "", fmt.Errorf("failed to get current user: %w", err)
	}
	return filepath.Join(usr.HomeDir, tokenFilePathSuffix), nil
}

// GetAndStoreToken retrieves a device access token and stores it locally.
func GetAndStoreToken(ctx context.Context, serverURL string) error {
	cfg, _, err := createConfig(serverURL)
	if err != nil {
		return err
	}

	deviceAuthResp, err := cfg.DeviceAuth(context.Background())
	if err != nil {
		return fmt.Errorf("failed to request device authorization: %v", err)
	}

	browser.OpenURL(deviceAuthResp.VerificationURIComplete)

	fmt.Println("Attempting to automatically open the SSO authorization page in your default browser.")
	fmt.Println("If the browser does not open or you wish to use a different device to authorize this request, open the following URL:")
	fmt.Println()
	fmt.Printf("%s\n", deviceAuthResp.VerificationURIComplete)
	fmt.Println()
	fmt.Println("Waiting for token...")

	// This will block until the user has authorized the request or the device
	// code expires.
	token, err := cfg.DeviceAccessToken(ctx, deviceAuthResp)
	if err != nil {
		return fmt.Errorf("failed to get device access token: %v", err)
	}

	addTokenExpiry(token)

	if err := writeTokenToFile(token); err != nil {
		return fmt.Errorf("failed to write token to file: %v", err)
	}

	fmt.Println("Successfully logged in")
	return nil
}

// APIKeyOrToken returns gRPC credentials from the best available source:
//  1. The WORKSHOP_API_KEY environment variable
//  2. A valid token stored in the user's home directory
//
// If no valid credentials are found, an error is returned advising the user to
// run the binary with the -login flag.
func APIKeyOrToken(serverURL string, useInsecure bool) (credentials.PerRPCCredentials, error) {
	if e := os.Getenv("WORKSHOP_API_KEY"); e != "" {
		return apiKeyAuthorizer(e), nil
	}

	cfg, _, err := createConfig(serverURL)
	if err != nil {
		return nil, err
	}

	token := apiTokenFromFile()
	if token != nil {
		return oauthRPCCreds{
			ts:        cfg.TokenSource(context.Background(), token),
			insecure:  useInsecure,
			serverURL: serverURL,
		}, nil
	}

	//lint:ignore ST1005 This error is directly presented to the user without
	// any prefix so we need to capitalize it.
	return nil, fmt.Errorf("Not logged in. Run the following to login:\n\n\t%s -login %s", os.Args[0], serverURL)
}

func createConfig(endpoint string) (*oauth2.Config, bool, error) {
	insecure := false
	url := ""
	if endpoint == "localhost:8080" {
		insecure = true
		url = "http://localhost:8080/.well-known/workos-client-id"
	} else {
		url = fmt.Sprintf("https://%s/.well-known/workos-client-id", endpoint)
	}

	resp, err := http.Get(url)
	if err != nil {
		return nil, insecure, fmt.Errorf("failed to get client ID from endpoint: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, insecure, fmt.Errorf("failed to get client ID from endpoint: status %d", resp.StatusCode)
	}

	clientID, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, insecure, fmt.Errorf("failed to read response body: %v", err)
	}

	return &oauth2.Config{
		ClientID: string(clientID),
		Endpoint: oauth2.Endpoint{
			DeviceAuthURL: "https://api.workos.com/user_management/authorize/device",
			TokenURL:      "https://api.workos.com/user_management/authenticate",
		},
	}, insecure, nil
}

func apiTokenFromFile() *oauth2.Token {
	path, err := tokenFilePath()
	if err != nil {
		return nil
	}

	fileContent, err := os.ReadFile(path)
	if err != nil {
		return nil
	}

	var t oauth2.Token
	if err := json.Unmarshal(fileContent, &t); err != nil {
		return nil
	}

	if t.AccessToken == "" && t.RefreshToken == "" {
		return nil
	}

	return &t
}

func writeTokenToFile(token *oauth2.Token) error {
	path, err := tokenFilePath()
	if err != nil {
		return err
	}

	b, err := json.Marshal(token)
	if err != nil {
		return err
	}

	return os.WriteFile(path, b, 0600)
}

func deleteTokenFromFile() error {
	path, err := tokenFilePath()
	if err != nil {
		return err
	}
	return os.Remove(path)
}

// apiKeyAuthorizer is a PerRPCCredentials implementation that uses a static API key.
type apiKeyAuthorizer string

func (k apiKeyAuthorizer) GetRequestMetadata(ctx context.Context, uri ...string) (map[string]string, error) {
	return map[string]string{"Authorization": string(k)}, nil
}
func (k apiKeyAuthorizer) RequireTransportSecurity() bool {
	return false
}

// oauthRPCCreds is a PerRPCCredentials implementation that uses an OAuth TokenSource.
type oauthRPCCreds struct {
	ts        oauth2.TokenSource
	serverURL string
	insecure  bool
}

func (o oauthRPCCreds) GetRequestMetadata(ctx context.Context, uri ...string) (map[string]string, error) {
	token, err := o.ts.Token()
	if err != nil {
		if err := deleteTokenFromFile(); err != nil {
			log.Printf("Failed to delete token from file: %v", err)
		}
		return nil, fmt.Errorf("%w. Run the following to login:\n\n\t%s -login %s", err, os.Args[0], o.serverURL)
	}

	addTokenExpiry(token)
	if err := writeTokenToFile(token); err != nil {
		log.Printf("Warning: failed to persist refreshed token: %v", err)
	}

	if !o.insecure {
		ri, _ := credentials.RequestInfoFromContext(ctx)
		if err = credentials.CheckSecurityLevel(ri.AuthInfo, credentials.PrivacyAndIntegrity); err != nil {
			return nil, fmt.Errorf("unable to transfer TokenSource PerRPCCredentials: %v", err)
		}
	}

	return map[string]string{
		"authorization": token.Type() + " " + token.AccessToken,
	}, nil
}

func (o oauthRPCCreds) RequireTransportSecurity() bool {
	return !o.insecure
}

// addTokenExpiry adds the expiry time to the token if it's not already set.
// The response from WorkOS doesn't include an expiry time so we have to parse
// the access token JWT ourselves.
func addTokenExpiry(token *oauth2.Token) {
	if !token.Expiry.IsZero() {
		return
	}

	parser := jwt.NewParser()
	parsedToken, _, err := parser.ParseUnverified(token.AccessToken, jwt.MapClaims{})
	if err != nil {
		return
	}

	exp, err := parsedToken.Claims.GetExpirationTime()
	if err != nil {
		return
	}

	token.Expiry = exp.Time
}
