package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// CreateOrgServiceAccountCmd represents the create-org-service-account command
var CreateOrgServiceAccountCmd = &cobra.Command{
	Use:   "create-org-service-account [org_id]",
	Short: "Create a service account for an organization",
	Long: `Create a service account for an organization in the Snyk API.

This command creates a service account for a specific organization by its ID.
The name, authentication type, and role ID must be provided as required flags.

Required permissions: Create service accounts (org.service_account.create)

Examples:
  snyk-api-cli create-org-service-account 12345678-1234-1234-1234-123456789012 --name "CI/CD Service Account" --auth-type "api_key" --role-id "87654321-4321-8765-2109-876543210987"
  snyk-api-cli create-org-service-account 12345678-1234-1234-1234-123456789012 --name "OAuth Client" --auth-type "oauth_client_secret" --role-id "87654321-4321-8765-2109-876543210987"
  snyk-api-cli create-org-service-account 12345678-1234-1234-1234-123456789012 --name "JWT Service" --auth-type "oauth_private_key_jwt" --role-id "87654321-4321-8765-2109-876543210987" --jwks-url "https://example.com/.well-known/jwks.json"
  snyk-api-cli create-org-service-account 12345678-1234-1234-1234-123456789012 --name "Access Token Account" --auth-type "access_token" --role-id "87654321-4321-8765-2109-876543210987" --access-token-ttl-seconds 7200
  snyk-api-cli create-org-service-account 12345678-1234-1234-1234-123456789012 --name "Service Account" --auth-type "api_key" --role-id "87654321-4321-8765-2109-876543210987" --verbose`,
	Args: cobra.ExactArgs(1),
	RunE: runCreateOrgServiceAccount,
}

var (
	createOrgServiceAccountName                 string
	createOrgServiceAccountAuthType             string
	createOrgServiceAccountRoleID               string
	createOrgServiceAccountJwksURL              string
	createOrgServiceAccountAccessTokenExpiresAt string
	createOrgServiceAccountAccessTokenTTL       int
	createOrgServiceAccountVerbose              bool
	createOrgServiceAccountSilent               bool
	createOrgServiceAccountIncludeResp          bool
	createOrgServiceAccountUserAgent            string
)

func init() {
	// Add flags for request body attributes
	CreateOrgServiceAccountCmd.Flags().StringVar(&createOrgServiceAccountName, "name", "", "Name of the service account (required)")
	CreateOrgServiceAccountCmd.Flags().StringVar(&createOrgServiceAccountAuthType, "auth-type", "", "Authentication type: api_key, oauth_client_secret, oauth_private_key_jwt, access_token (required)")
	CreateOrgServiceAccountCmd.Flags().StringVar(&createOrgServiceAccountRoleID, "role-id", "", "Role ID (UUID) for the service account (required)")
	CreateOrgServiceAccountCmd.Flags().StringVar(&createOrgServiceAccountJwksURL, "jwks-url", "", "JWKS URL for oauth_private_key_jwt auth type (optional)")
	CreateOrgServiceAccountCmd.Flags().StringVar(&createOrgServiceAccountAccessTokenExpiresAt, "access-token-expires-at", "", "Access token expiration time in RFC3339 format (optional)")
	CreateOrgServiceAccountCmd.Flags().IntVar(&createOrgServiceAccountAccessTokenTTL, "access-token-ttl-seconds", 0, "Access token TTL in seconds (3600-86400, optional)")

	// Add standard flags like other commands
	CreateOrgServiceAccountCmd.Flags().BoolVarP(&createOrgServiceAccountVerbose, "verbose", "v", false, "Make the operation more talkative")
	CreateOrgServiceAccountCmd.Flags().BoolVarP(&createOrgServiceAccountSilent, "silent", "s", false, "Silent mode")
	CreateOrgServiceAccountCmd.Flags().BoolVarP(&createOrgServiceAccountIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	CreateOrgServiceAccountCmd.Flags().StringVarP(&createOrgServiceAccountUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")

	// Mark required flags
	CreateOrgServiceAccountCmd.MarkFlagRequired("name")
	CreateOrgServiceAccountCmd.MarkFlagRequired("auth-type")
	CreateOrgServiceAccountCmd.MarkFlagRequired("role-id")
}

func runCreateOrgServiceAccount(cmd *cobra.Command, args []string) error {
	orgID := args[0]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Validate auth type
	validAuthTypes := []string{"api_key", "oauth_client_secret", "oauth_private_key_jwt", "access_token"}
	isValid := false
	for _, authType := range validAuthTypes {
		if createOrgServiceAccountAuthType == authType {
			isValid = true
			break
		}
	}
	if !isValid {
		return fmt.Errorf("invalid auth-type: %s. Valid options are: %s", createOrgServiceAccountAuthType, strings.Join(validAuthTypes, ", "))
	}

	// Validate access token TTL if provided
	if createOrgServiceAccountAccessTokenTTL > 0 && (createOrgServiceAccountAccessTokenTTL < 3600 || createOrgServiceAccountAccessTokenTTL > 86400) {
		return fmt.Errorf("access-token-ttl-seconds must be between 3600 and 86400 seconds")
	}

	// Build the URL
	fullURL, err := buildCreateOrgServiceAccountURL(endpoint, version, orgID)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	if createOrgServiceAccountVerbose {
		fmt.Fprintf(os.Stderr, "* Requesting POST %s\n", fullURL)
	}

	// Build request body
	requestBody, err := buildCreateOrgServiceAccountRequestBody()
	if err != nil {
		return fmt.Errorf("failed to build request body: %w", err)
	}

	if createOrgServiceAccountVerbose {
		fmt.Fprintf(os.Stderr, "* Request body: %s\n", requestBody)
	}

	// Create the HTTP request
	req, err := http.NewRequest("POST", fullURL, strings.NewReader(requestBody))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Set content type for JSON:API
	req.Header.Set("Content-Type", "application/vnd.api+json")

	// Handle authentication with same precedence as curl: Authorization header > SNYK_TOKEN > OAuth
	if createOrgServiceAccountVerbose {
		fmt.Fprintf(os.Stderr, "* Checking authentication options\n")
	}

	authHeader, err := buildAuthHeader([]string{}) // No manual headers for this command
	if err != nil {
		if createOrgServiceAccountVerbose {
			fmt.Fprintf(os.Stderr, "* Warning: failed to get automatic auth: %v\n", err)
		}
		// Don't fail the request, just proceed without automatic auth
	} else if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
		if createOrgServiceAccountVerbose {
			fmt.Fprintf(os.Stderr, "* Added automatic authorization header\n")
		}
	} else if createOrgServiceAccountVerbose {
		fmt.Fprintf(os.Stderr, "* No automatic authorization available\n")
	}

	// Set user agent
	req.Header.Set("User-Agent", createOrgServiceAccountUserAgent)

	// Make the request
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	if createOrgServiceAccountVerbose {
		fmt.Fprintf(os.Stderr, "* Making request...\n")
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// Handle response using the same pattern as other commands
	return handleCreateOrgServiceAccountResponse(resp, createOrgServiceAccountIncludeResp, createOrgServiceAccountVerbose, createOrgServiceAccountSilent)
}

func buildCreateOrgServiceAccountURL(endpoint, version, orgID string) (string, error) {
	// Build base URL with organization ID path parameter
	baseURL := fmt.Sprintf("https://%s/rest/orgs/%s/service_accounts", endpoint, orgID)

	// Parse URL to handle query parameters properly
	u, err := url.Parse(baseURL)
	if err != nil {
		return "", err
	}

	// Add version parameter
	q := u.Query()
	q.Set("version", version)

	u.RawQuery = q.Encode()

	return u.String(), nil
}

func buildCreateOrgServiceAccountRequestBody() (string, error) {
	// Build request body according to the API specification
	attributes := map[string]interface{}{
		"name":      createOrgServiceAccountName,
		"auth_type": createOrgServiceAccountAuthType,
		"role_id":   createOrgServiceAccountRoleID,
	}

	// Add optional attributes if provided
	if createOrgServiceAccountJwksURL != "" {
		attributes["jwks_url"] = createOrgServiceAccountJwksURL
	}

	if createOrgServiceAccountAccessTokenExpiresAt != "" {
		attributes["access_token_expires_at"] = createOrgServiceAccountAccessTokenExpiresAt
	}

	if createOrgServiceAccountAccessTokenTTL > 0 {
		attributes["access_token_ttl_seconds"] = createOrgServiceAccountAccessTokenTTL
	}

	requestData := map[string]interface{}{
		"data": map[string]interface{}{
			"attributes": attributes,
		},
	}

	// Convert to JSON
	jsonData, err := json.Marshal(requestData)
	if err != nil {
		return "", fmt.Errorf("failed to marshal request body: %w", err)
	}

	return string(jsonData), nil
}

func handleCreateOrgServiceAccountResponse(resp *http.Response, includeResp, verbose, silent bool) error {
	if verbose {
		fmt.Fprintf(os.Stderr, "* Response: %s\n", resp.Status)
	}

	// Print response headers if requested
	if includeResp {
		fmt.Printf("%s %s\n", resp.Proto, resp.Status)
		for key, values := range resp.Header {
			for _, value := range values {
				fmt.Printf("%s: %s\n", key, value)
			}
		}
		fmt.Println()
	}

	// Read and print response body
	if !silent {
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return fmt.Errorf("failed to read response body: %w", err)
		}
		fmt.Print(string(body))
	}

	// Return error for non-2xx status codes if verbose
	if verbose && (resp.StatusCode < 200 || resp.StatusCode >= 300) {
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, resp.Status)
	}

	return nil
}