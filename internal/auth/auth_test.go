package auth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/shoenig/test"
	"github.com/shoenig/test/must"
	"golang.org/x/oauth2"
)

func setupTokenFile(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "token.json")
	tokenFilePathOverride = path
	t.Cleanup(func() { tokenFilePathOverride = "" })
	return path
}

func TestAPIKeyOrToken_EnvVar(t *testing.T) {
	t.Setenv("WORKSHOP_API_KEY", "test-api-key")

	creds, err := APIKeyOrToken(context.Background(), "example.com", true)
	must.NoError(t, err)

	meta, err := creds.GetRequestMetadata(context.Background())
	must.NoError(t, err)
	test.Eq(t, "test-api-key", meta["Authorization"])
	test.Eq(t, false, creds.RequireTransportSecurity())
}

func TestAPIKeyOrToken_NoCredsReturnsError(t *testing.T) {
	t.Setenv("WORKSHOP_API_KEY", "")
	setupTokenFile(t)

	// No token file and unreachable endpoint: createConfig will fail.
	_, err := APIKeyOrToken(context.Background(), "example.com", false)
	must.Error(t, err)
}

func TestAPIKeyAuthorizer_GetRequestMetadata(t *testing.T) {
	a := apiKeyAuthorizer{key: "my-key"}

	meta, err := a.GetRequestMetadata(context.Background())
	must.NoError(t, err)
	test.Eq(t, "my-key", meta["Authorization"])
}

func TestAPIKeyAuthorizer_RequireTransportSecurity(t *testing.T) {
	secure := apiKeyAuthorizer{key: "my-key", insecure: false}
	test.Eq(t, true, secure.RequireTransportSecurity())

	insecure := apiKeyAuthorizer{key: "my-key", insecure: true}
	test.Eq(t, false, insecure.RequireTransportSecurity())
}

func TestOAuthRPCCreds_RequireTransportSecurity(t *testing.T) {
	secure := oauthRPCCreds{insecure: false}
	test.Eq(t, true, secure.RequireTransportSecurity())

	insecureCreds := oauthRPCCreds{insecure: true}
	test.Eq(t, false, insecureCreds.RequireTransportSecurity())
}

func TestWriteAndReadTokenFile(t *testing.T) {
	setupTokenFile(t)

	token := &oauth2.Token{
		AccessToken:  "access-123",
		RefreshToken: "refresh-456",
		TokenType:    "Bearer",
		Expiry:       time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC),
	}

	err := writeTokenToFile(token)
	must.NoError(t, err)

	got := apiTokenFromFile()
	must.NotNil(t, got)
	test.Eq(t, "access-123", got.AccessToken)
	test.Eq(t, "refresh-456", got.RefreshToken)
	test.Eq(t, "Bearer", got.TokenType)
}

func TestWriteTokenFile_CreatesParentDir(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nested", "subdir", "token.json")
	tokenFilePathOverride = path
	t.Cleanup(func() { tokenFilePathOverride = "" })

	token := &oauth2.Token{AccessToken: "abc"}
	must.NoError(t, writeTokenToFile(token))

	got := apiTokenFromFile()
	must.NotNil(t, got)
	test.Eq(t, "abc", got.AccessToken)
}

func TestApiTokenFromFile_NoFile(t *testing.T) {
	setupTokenFile(t)

	got := apiTokenFromFile()
	test.Nil(t, got)
}

func TestApiTokenFromFile_InvalidJSON(t *testing.T) {
	path := setupTokenFile(t)

	must.NoError(t, os.WriteFile(path, []byte("not json"), 0600))

	got := apiTokenFromFile()
	test.Nil(t, got)
}

func TestApiTokenFromFile_EmptyToken(t *testing.T) {
	path := setupTokenFile(t)

	token := &oauth2.Token{}
	b, _ := json.Marshal(token)
	must.NoError(t, os.WriteFile(path, b, 0600))

	got := apiTokenFromFile()
	test.Nil(t, got)
}

func TestDeleteTokenFromFile(t *testing.T) {
	path := setupTokenFile(t)

	token := &oauth2.Token{AccessToken: "abc"}
	must.NoError(t, writeTokenToFile(token))

	// File exists.
	_, err := os.Stat(path)
	must.NoError(t, err)

	must.NoError(t, deleteTokenFromFile())

	// File is gone.
	_, err = os.Stat(path)
	test.Error(t, err)
}

func TestWriteTokenFile_Permissions(t *testing.T) {
	path := setupTokenFile(t)

	token := &oauth2.Token{AccessToken: "secret"}
	must.NoError(t, writeTokenToFile(token))

	info, err := os.Stat(path)
	must.NoError(t, err)
	test.Eq(t, os.FileMode(0600), info.Mode().Perm())
}

func TestAddTokenExpiry_AlreadySet(t *testing.T) {
	expiry := time.Date(2030, 6, 15, 0, 0, 0, 0, time.UTC)
	token := &oauth2.Token{
		AccessToken: "not-a-jwt",
		Expiry:      expiry,
	}

	addTokenExpiry(token)

	// Should not be modified.
	test.Eq(t, expiry, token.Expiry)
}

func TestAddTokenExpiry_FromJWT(t *testing.T) {
	expiry := time.Date(2030, 6, 15, 12, 0, 0, 0, time.UTC)

	// Create a real JWT with an exp claim.
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	must.NoError(t, err)

	claims := jwt.MapClaims{"exp": float64(expiry.Unix())}
	jwtToken := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	signed, err := jwtToken.SignedString(key)
	must.NoError(t, err)

	token := &oauth2.Token{AccessToken: signed}
	addTokenExpiry(token)

	test.Eq(t, expiry.Unix(), token.Expiry.Unix())
}

func TestAddTokenExpiry_InvalidJWT(t *testing.T) {
	token := &oauth2.Token{AccessToken: "not-a-valid-jwt"}
	addTokenExpiry(token)

	// Expiry should remain zero.
	test.Eq(t, true, token.Expiry.IsZero())
}

func TestCreateConfig_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		test.Eq(t, "/.well-known/workos-client-id", r.URL.Path)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("my-client-id"))
	}))
	defer server.Close()

	// Use the test server's host:port as the endpoint with insecure=true (http).
	// Strip the "http://" prefix since createConfig builds the URL itself.
	endpoint := server.Listener.Addr().String()
	cfg, err := createConfig(context.Background(), endpoint, true)
	must.NoError(t, err)
	test.Eq(t, "my-client-id", cfg.ClientID)
}

func TestCreateConfig_Non200Status(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	endpoint := server.Listener.Addr().String()
	_, err := createConfig(context.Background(), endpoint, true)
	must.Error(t, err)
	must.StrContains(t, err.Error(), "status 404")
}

func TestCreateConfig_Unreachable(t *testing.T) {
	_, err := createConfig(context.Background(), "unreachable.invalid.example", false)
	must.Error(t, err)
	must.StrContains(t, err.Error(), "failed to get client ID from endpoint")
}

func TestCreateConfig_ContextTimeout(t *testing.T) {
	// Server that never responds.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	endpoint := server.Listener.Addr().String()
	_, err := createConfig(ctx, endpoint, true)
	must.Error(t, err)
}

func TestCreateConfig_InsecureUsesHTTP(t *testing.T) {
	var receivedScheme string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// httptest.NewServer is HTTP, so if we got here with insecure=true it worked.
		receivedScheme = "http"
		w.Write([]byte("client-id"))
	}))
	defer server.Close()

	endpoint := server.Listener.Addr().String()
	_, err := createConfig(context.Background(), endpoint, true)
	must.NoError(t, err)
	test.Eq(t, "http", receivedScheme)
}
