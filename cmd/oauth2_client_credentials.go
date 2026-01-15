package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// OAuth2Token represents the token response from the OAuth2 token endpoint
type OAuth2Token struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"` // seconds until expiration
	Scope       string `json:"scope,omitempty"`
	expiresAt   time.Time
}

// ClientCredentialsConfig holds the configuration for OAuth2 client credentials flow
type ClientCredentialsConfig struct {
	ClientID     string
	ClientSecret string
	TokenURL     string
}

// cachedToken stores the cached OAuth2 token and its expiration
var cachedClientCredentialsToken *OAuth2Token
var tokenMutex sync.RWMutex

// DefaultSnykTokenURL is the default Snyk OAuth2 token endpoint
const DefaultSnykTokenURL = "https://api.snyk.io/oauth2/token"

// tokenExpiryBuffer is how long before actual expiry we consider the token expired
const tokenExpiryBuffer = 5 * time.Minute

// getClientCredentialsToken retrieves an access token using OAuth2 client credentials grant
func getClientCredentialsToken(config ClientCredentialsConfig) (string, error) {
	if config.ClientID == "" || config.ClientSecret == "" {
		return "", fmt.Errorf("client credentials not configured")
	}

	// Check if we have a valid cached token
	tokenMutex.RLock()
	if cachedClientCredentialsToken != nil && !isOAuth2TokenExpired(cachedClientCredentialsToken) {
		token := cachedClientCredentialsToken.AccessToken
		tokenMutex.RUnlock()
		return token, nil
	}
	tokenMutex.RUnlock()

	// Need to fetch a new token
	tokenMutex.Lock()
	defer tokenMutex.Unlock()

	// Double-check after acquiring write lock
	if cachedClientCredentialsToken != nil && !isOAuth2TokenExpired(cachedClientCredentialsToken) {
		return cachedClientCredentialsToken.AccessToken, nil
	}

	// Fetch new token
	token, err := fetchClientCredentialsToken(config)
	if err != nil {
		return "", err
	}

	// Cache the token
	cachedClientCredentialsToken = token
	return token.AccessToken, nil
}

// fetchClientCredentialsToken makes the HTTP request to obtain a new access token
func fetchClientCredentialsToken(config ClientCredentialsConfig) (*OAuth2Token, error) {
	tokenURL := config.TokenURL
	if tokenURL == "" {
		tokenURL = DefaultSnykTokenURL
	}

	// Prepare the request body
	data := url.Values{}
	data.Set("grant_type", "client_credentials")

	req, err := http.NewRequest("POST", tokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to create token request: %w", err)
	}

	// Set headers
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(config.ClientID, config.ClientSecret)

	// Make the request
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("token request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read token response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("token request failed with status %d: %s", resp.StatusCode, string(body))
	}

	var token OAuth2Token
	if err := json.Unmarshal(body, &token); err != nil {
		return nil, fmt.Errorf("failed to parse token response: %w", err)
	}

	// Calculate expiration time
	if token.ExpiresIn > 0 {
		token.expiresAt = time.Now().Add(time.Duration(token.ExpiresIn) * time.Second)
	}

	return &token, nil
}

// isOAuth2TokenExpired checks if the OAuth2 token is expired or will expire soon
func isOAuth2TokenExpired(token *OAuth2Token) bool {
	if token == nil || token.AccessToken == "" {
		return true
	}

	if token.expiresAt.IsZero() {
		// If no expiry is set, assume token is valid
		return false
	}

	// Consider token expired if it expires within the buffer time
	return time.Now().Add(tokenExpiryBuffer).After(token.expiresAt)
}

// clearCachedClientCredentialsToken clears the cached token (useful for testing)
func clearCachedClientCredentialsToken() {
	tokenMutex.Lock()
	defer tokenMutex.Unlock()
	cachedClientCredentialsToken = nil
}

// buildTokenURLFromEndpoint constructs the token URL from the API endpoint
func buildTokenURLFromEndpoint(endpoint string) string {
	// Normalize the endpoint
	endpoint = strings.TrimPrefix(endpoint, "https://")
	endpoint = strings.TrimPrefix(endpoint, "http://")
	endpoint = strings.TrimSuffix(endpoint, "/")

	return fmt.Sprintf("https://%s/oauth2/token", endpoint)
}

