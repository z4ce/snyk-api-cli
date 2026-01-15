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

// CreateGroupServiceAccountCmd represents the create-group-service-account command
var CreateGroupServiceAccountCmd = &cobra.Command{
	Use:   "create-group-service-account [group_id]",
	Short: "Create a service account for a specific group in Snyk",
	Long: `Create a service account for a specific group in the Snyk API.

This command creates a service account by providing the required attributes such as
name, role ID, and authentication type. The group ID must be provided as a 
required argument, and the service account details must be provided as flags.

Examples:
  snyk-api-cli create-group-service-account 12345678-1234-1234-1234-123456789012 --name "My Service Account" --role-id 11111111-1111-1111-1111-111111111111 --auth-type api_key
  snyk-api-cli create-group-service-account 12345678-1234-1234-1234-123456789012 --name "OAuth Service Account" --role-id 11111111-1111-1111-1111-111111111111 --auth-type oauth_client_secret --verbose --include`,
	Args: cobra.ExactArgs(1),
	RunE: runCreateGroupServiceAccount,
}

var (
	createGroupServiceAccountName                 string
	createGroupServiceAccountRoleID               string
	createGroupServiceAccountAuthType             string
	createGroupServiceAccountAccessTokenExpiresAt string
	createGroupServiceAccountAccessTokenTTL       int64
	createGroupServiceAccountJWKSURL              string
	createGroupServiceAccountVerbose              bool
	createGroupServiceAccountSilent               bool
	createGroupServiceAccountIncludeResp          bool
	createGroupServiceAccountUserAgent            string
)

func init() {
	// Add flags for request body attributes
	CreateGroupServiceAccountCmd.Flags().StringVar(&createGroupServiceAccountName, "name", "", "Human-friendly service account name (required)")
	CreateGroupServiceAccountCmd.Flags().StringVar(&createGroupServiceAccountRoleID, "role-id", "", "Role ID for the service account (required)")
	CreateGroupServiceAccountCmd.Flags().StringVar(&createGroupServiceAccountAuthType, "auth-type", "", "Authentication strategy: api_key, oauth_client_secret, oauth_private_key_jwt, access_token (required)")
	CreateGroupServiceAccountCmd.Flags().StringVar(&createGroupServiceAccountAccessTokenExpiresAt, "access-token-expires-at", "", "Access token expiration time (ISO 8601 format)")
	CreateGroupServiceAccountCmd.Flags().Int64Var(&createGroupServiceAccountAccessTokenTTL, "access-token-ttl-seconds", 0, "Access token TTL in seconds")
	CreateGroupServiceAccountCmd.Flags().StringVar(&createGroupServiceAccountJWKSURL, "jwks-url", "", "JWKS URL for oauth_private_key_jwt auth type")

	// Add standard flags like other commands
	CreateGroupServiceAccountCmd.Flags().BoolVarP(&createGroupServiceAccountVerbose, "verbose", "v", false, "Make the operation more talkative")
	CreateGroupServiceAccountCmd.Flags().BoolVarP(&createGroupServiceAccountSilent, "silent", "s", false, "Silent mode")
	CreateGroupServiceAccountCmd.Flags().BoolVarP(&createGroupServiceAccountIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	CreateGroupServiceAccountCmd.Flags().StringVarP(&createGroupServiceAccountUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")

	// Mark required flags
	CreateGroupServiceAccountCmd.MarkFlagRequired("name")
	CreateGroupServiceAccountCmd.MarkFlagRequired("role-id")
	CreateGroupServiceAccountCmd.MarkFlagRequired("auth-type")
}

func runCreateGroupServiceAccount(cmd *cobra.Command, args []string) error {
	groupID := args[0]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Validate auth type
	validAuthTypes := []string{"api_key", "oauth_client_secret", "oauth_private_key_jwt", "access_token"}
	if !contains(validAuthTypes, createGroupServiceAccountAuthType) {
		return fmt.Errorf("invalid auth-type: %s. Valid options are: %s", createGroupServiceAccountAuthType, strings.Join(validAuthTypes, ", "))
	}

	// Build the URL
	fullURL, err := buildCreateGroupServiceAccountURL(endpoint, version, groupID)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	if createGroupServiceAccountVerbose {
		fmt.Fprintf(os.Stderr, "* Requesting POST %s\n", fullURL)
	}

	// Build request body
	requestBody, err := buildCreateGroupServiceAccountRequestBody()
	if err != nil {
		return fmt.Errorf("failed to build request body: %w", err)
	}

	if createGroupServiceAccountVerbose {
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
	if createGroupServiceAccountVerbose {
		fmt.Fprintf(os.Stderr, "* Checking authentication options\n")
	}

	authHeader, err := buildAuthHeader([]string{}) // No manual headers for this command
	if err != nil {
		if createGroupServiceAccountVerbose {
			fmt.Fprintf(os.Stderr, "* Warning: failed to get automatic auth: %v\n", err)
		}
		// Don't fail the request, just proceed without automatic auth
	} else if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
		if createGroupServiceAccountVerbose {
			fmt.Fprintf(os.Stderr, "* Added automatic authorization header\n")
		}
	} else if createGroupServiceAccountVerbose {
		fmt.Fprintf(os.Stderr, "* No automatic authorization available\n")
	}

	// Set user agent
	req.Header.Set("User-Agent", createGroupServiceAccountUserAgent)

	// Make the request
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	if createGroupServiceAccountVerbose {
		fmt.Fprintf(os.Stderr, "* Making request...\n")
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// Handle response using the same pattern as other commands
	return handleCreateGroupServiceAccountResponse(resp, createGroupServiceAccountIncludeResp, createGroupServiceAccountVerbose, createGroupServiceAccountSilent)
}

func buildCreateGroupServiceAccountURL(endpoint, version, groupID string) (string, error) {
	// Build base URL with group ID path parameter
	baseURL := fmt.Sprintf("https://%s/rest/groups/%s/service_accounts", endpoint, groupID)

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

func buildCreateGroupServiceAccountRequestBody() (string, error) {
	// Build attributes object
	attributes := map[string]interface{}{
		"name":      createGroupServiceAccountName,
		"role_id":   createGroupServiceAccountRoleID,
		"auth_type": createGroupServiceAccountAuthType,
	}

	// Add optional attributes based on flags
	if createGroupServiceAccountAccessTokenExpiresAt != "" {
		attributes["access_token_expires_at"] = createGroupServiceAccountAccessTokenExpiresAt
	}
	if createGroupServiceAccountAccessTokenTTL > 0 {
		attributes["access_token_ttl_seconds"] = createGroupServiceAccountAccessTokenTTL
	}
	if createGroupServiceAccountJWKSURL != "" {
		attributes["jwks_url"] = createGroupServiceAccountJWKSURL
	}

	// Build JSON:API format request body according to the specification
	requestData := map[string]interface{}{
		"data": map[string]interface{}{
			"type":       "service_account",
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

func handleCreateGroupServiceAccountResponse(resp *http.Response, includeResp, verbose, silent bool) error {
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

// Helper function to check if a slice contains a string
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}
