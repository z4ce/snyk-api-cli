package cmd

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

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

	// Build request body
	requestBody, err := buildCreateOrgServiceAccountRequestBody()
	if err != nil {
		return fmt.Errorf("failed to build request body: %w", err)
	}

	return ExecuteAPIRequest(RequestOptions{
		Method:      "POST",
		URL:         fullURL,
		Body:        requestBody,
		Verbose:     createOrgServiceAccountVerbose,
		Silent:      createOrgServiceAccountSilent,
		IncludeResp: createOrgServiceAccountIncludeResp,
		UserAgent:   createOrgServiceAccountUserAgent,
	})
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
