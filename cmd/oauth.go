package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

// SnykToken represents the OAuth token structure from snyk config
type SnykToken struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	Expiry       time.Time `json:"expiry"`
}

// parseSnykToken parses the JSON token string into a SnykToken struct
func parseSnykToken(tokenJSON string) (SnykToken, error) {
	var token SnykToken
	if strings.TrimSpace(tokenJSON) == "" {
		return token, nil // Return empty token for empty input
	}

	err := json.Unmarshal([]byte(tokenJSON), &token)
	if err != nil {
		return SnykToken{}, fmt.Errorf("failed to parse token JSON: %w", err)
	}

	return token, nil
}

// isTokenExpired checks if the token is expired or expires within 5 minutes
func isTokenExpired(token SnykToken) bool {
	if token.Expiry.IsZero() {
		return true // Zero time is considered expired
	}

	// Consider token expired if it expires within 5 minutes
	expiryThreshold := time.Now().Add(5 * time.Minute)
	return token.Expiry.Before(expiryThreshold)
}

// buildAuthHeaderFromEnvToken creates an Authorization header from SNYK_TOKEN environment variable
func buildAuthHeaderFromEnvToken(envValue string) (string, error) {
	token := strings.TrimSpace(envValue)
	if token == "" {
		return "", fmt.Errorf("SNYK_TOKEN is empty")
	}
	return fmt.Sprintf("Bearer %s", token), nil
}

// getAuthSourcePriority determines which authentication source to use based on priority
func getAuthSourcePriority(hasManualAuth bool, snykToken, oauthToken string) (source string, useAuto bool) {
	if hasManualAuth {
		return "manual", false
	}

	snykToken = strings.TrimSpace(snykToken)
	if snykToken != "" {
		return "env", true
	}

	if oauthToken != "" {
		return "oauth", true
	}

	return "none", false
}

// determineAuthMethod determines which authentication method to use with full precedence logic
func determineAuthMethod(manualHeaders []string, snykTokenEnv, oauthToken string) (shouldUse bool, authHeader, source string) {
	// Check for manual Authorization header (highest precedence)
	hasManualAuth := false
	var manualAuthHeader string

	for _, header := range manualHeaders {
		if strings.HasPrefix(strings.ToLower(header), "authorization:") {
			hasManualAuth = true
			// Extract the header value after "Authorization: "
			parts := strings.SplitN(header, ":", 2)
			if len(parts) == 2 {
				manualAuthHeader = strings.TrimSpace(parts[1])
			}
			break
		}
	}

	// Determine auth source priority
	authSource, _ := getAuthSourcePriority(hasManualAuth, snykTokenEnv, oauthToken)

	switch authSource {
	case "manual":
		return false, manualAuthHeader, "manual"
	case "env":
		envHeader, err := buildAuthHeaderFromEnvToken(snykTokenEnv)
		if err != nil {
			// Fall back to OAuth if env token is invalid
			if oauthToken != "" {
				return true, fmt.Sprintf("Bearer %s", oauthToken), "oauth"
			}
			return false, "", "none"
		}
		return true, envHeader, "env"
	case "oauth":
		return true, fmt.Sprintf("Bearer %s", oauthToken), "oauth"
	default:
		return false, "", "none"
	}
}

// getValidAccessToken retrieves a valid OAuth access token from snyk CLI
func getValidAccessToken() (string, error) {
	token, err := getSnykToken()
	if err != nil {
		return "", err
	}

	// Check if token is expired
	if isTokenExpired(token) {
		if token.RefreshToken == "" {
			return "", fmt.Errorf("token expired and no refresh token available")
		}

		// Try to refresh the token
		newToken, err := refreshSnykToken(token.RefreshToken)
		if err != nil {
			return "", fmt.Errorf("failed to refresh token: %w", err)
		}

		// Save the new token
		err = saveSnykToken(newToken)
		if err != nil {
			// Log warning but continue with the new token
			fmt.Printf("Warning: failed to save refreshed token: %v\n", err)
		}

		token = newToken
	}

	return token.AccessToken, nil
}

// buildAuthHeader creates an Authorization header, checking precedence: manual > SNYK_TOKEN > OAuth
func buildAuthHeader(manualHeaders []string) (string, error) {
	// Get SNYK_TOKEN from environment
	snykToken := os.Getenv("SNYK_TOKEN")

	// Get OAuth token
	oauthToken, err := getValidAccessToken()
	var oauthTokenStr string
	if err == nil && oauthToken != "" {
		oauthTokenStr = oauthToken
	}

	shouldUse, authHeader, source := determineAuthMethod(manualHeaders, snykToken, oauthTokenStr)

	if shouldUse {
		if verbose {
			fmt.Printf("* Using %s authentication\n", source)
		}
		return authHeader, nil
	}

	// Manual auth or no auth available
	if source == "manual" && verbose {
		fmt.Println("* Using manual Authorization header")
	}

	return "", nil
}

// buildAuthHeaderFromToken creates a Bearer authorization header from the token (legacy function)
func buildAuthHeaderFromToken(token SnykToken) (string, error) {
	accessToken := strings.TrimSpace(token.AccessToken)
	if accessToken == "" {
		return "", fmt.Errorf("access token is empty")
	}

	return fmt.Sprintf("Bearer %s", accessToken), nil
}

// shouldUseAutoAuth determines if automatic auth should be used and returns the appropriate header
func shouldUseAutoAuth(manualHeaders []string, autoToken string) (bool, string) {
	// Check if Authorization header is already manually provided
	for _, header := range manualHeaders {
		headerLower := strings.ToLower(header)
		if strings.HasPrefix(headerLower, "authorization:") {
			// Extract the manual authorization value
			parts := strings.SplitN(header, ":", 2)
			if len(parts) == 2 {
				return false, strings.TrimSpace(parts[1])
			}
		}
	}

	// No manual auth header found, use automatic token
	if autoToken != "" {
		return true, fmt.Sprintf("Bearer %s", autoToken)
	}

	return false, ""
}

// executeSnykCommand executes a snyk CLI command and returns the output
func executeSnykCommand(args ...string) (string, error) {
	cmd := exec.Command("snyk", args...)
	output, err := cmd.Output()
	if err != nil {
		// Check if it's a "command not found" error
		if strings.Contains(err.Error(), "executable file not found") ||
			strings.Contains(err.Error(), "command not found") {
			return "", fmt.Errorf("snyk CLI not found: %w", err)
		}
		return "", fmt.Errorf("snyk command failed: %w", err)
	}

	return strings.TrimSpace(string(output)), nil
}

// getSnykToken retrieves the OAuth token from snyk config
func getSnykToken() (SnykToken, error) {
	output, err := executeSnykCommand("config", "get", "INTERNAL_OAUTH_TOKEN_STORAGE")
	if err != nil {
		return SnykToken{}, err
	}

	if output == "" {
		return SnykToken{}, fmt.Errorf("no token found in snyk config")
	}

	return parseSnykToken(output)
}

// refreshSnykToken uses the refresh token to get a new access token
func refreshSnykToken(_ string) (SnykToken, error) {
	// In a real implementation, this would make an HTTP request to Snyk's OAuth endpoint
	// For now, we'll simulate the refresh process

	// This is a placeholder - in reality you'd make an HTTP POST to the OAuth refresh endpoint
	// with the refresh token and get back a new access token

	return SnykToken{}, fmt.Errorf("token refresh not implemented - this would require OAuth endpoint integration")
}

// saveSnykToken saves the updated token back to snyk config
func saveSnykToken(token SnykToken) error {
	tokenJSON, err := json.Marshal(token)
	if err != nil {
		return fmt.Errorf("failed to marshal token: %w", err)
	}

	_, err = executeSnykCommand("config", "set", "INTERNAL_OAUTH_TOKEN_STORAGE", string(tokenJSON))
	if err != nil {
		return fmt.Errorf("failed to save token: %w", err)
	}

	return nil
}
