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

// UpdateOrgServiceAccountSecretCmd represents the update-org-service-account-secret command
var UpdateOrgServiceAccountSecretCmd = &cobra.Command{
	Use:   "update-org-service-account-secret [org_id] [serviceaccount_id]",
	Short: "Manage an organization service account's client secret",
	Long: `Manage an organization service account's client secret in the Snyk API.

This command manages the client secret for a service account in the specified organization.
Both org_id and serviceaccount_id parameters are required and should be valid UUIDs.
The mode parameter specifies the action to take on the secret.

Required permissions: Edit service accounts (org.service_account.edit)

Mode Options:
- replace: Replace existing secrets with a new generated secret
- create: Add a new secret, preserving existing secrets (max 2 secrets)
- delete: Remove an existing secret by value

Examples:
  snyk-api-cli update-org-service-account-secret 12345678-1234-1234-1234-123456789012 87654321-4321-8765-2109-876543210987 --mode "replace"
  snyk-api-cli update-org-service-account-secret 12345678-1234-1234-1234-123456789012 87654321-4321-8765-2109-876543210987 --mode "create"
  snyk-api-cli update-org-service-account-secret 12345678-1234-1234-1234-123456789012 87654321-4321-8765-2109-876543210987 --mode "delete" --secret "existing_secret_value"
  snyk-api-cli update-org-service-account-secret 12345678-1234-1234-1234-123456789012 87654321-4321-8765-2109-876543210987 --mode "replace" --verbose`,
	Args: cobra.ExactArgs(2),
	RunE: runUpdateOrgServiceAccountSecret,
}

var (
	updateOrgServiceAccountSecretMode       string
	updateOrgServiceAccountSecretValue      string
	updateOrgServiceAccountSecretVerbose    bool
	updateOrgServiceAccountSecretSilent     bool
	updateOrgServiceAccountSecretIncludeResp bool
	updateOrgServiceAccountSecretUserAgent  string
)

func init() {
	// Add flags for request body attributes
	UpdateOrgServiceAccountSecretCmd.Flags().StringVar(&updateOrgServiceAccountSecretMode, "mode", "", "Secret management mode: replace, create, delete (required)")
	UpdateOrgServiceAccountSecretCmd.Flags().StringVar(&updateOrgServiceAccountSecretValue, "secret", "", "Secret value (required for delete mode)")

	// Add standard flags like other commands
	UpdateOrgServiceAccountSecretCmd.Flags().BoolVarP(&updateOrgServiceAccountSecretVerbose, "verbose", "v", false, "Make the operation more talkative")
	UpdateOrgServiceAccountSecretCmd.Flags().BoolVarP(&updateOrgServiceAccountSecretSilent, "silent", "s", false, "Silent mode")
	UpdateOrgServiceAccountSecretCmd.Flags().BoolVarP(&updateOrgServiceAccountSecretIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	UpdateOrgServiceAccountSecretCmd.Flags().StringVarP(&updateOrgServiceAccountSecretUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")

	// Mark required flags
	UpdateOrgServiceAccountSecretCmd.MarkFlagRequired("mode")
}

func runUpdateOrgServiceAccountSecret(cmd *cobra.Command, args []string) error {
	orgID := args[0]
	serviceAccountID := args[1]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Validate mode
	validModes := []string{"replace", "create", "delete"}
	isValid := false
	for _, mode := range validModes {
		if updateOrgServiceAccountSecretMode == mode {
			isValid = true
			break
		}
	}
	if !isValid {
		return fmt.Errorf("invalid mode: %s. Valid options are: %s", updateOrgServiceAccountSecretMode, strings.Join(validModes, ", "))
	}

	// Validate that secret is provided for delete mode
	if updateOrgServiceAccountSecretMode == "delete" && updateOrgServiceAccountSecretValue == "" {
		return fmt.Errorf("secret value is required when mode is 'delete'")
	}

	// Build the URL
	fullURL, err := buildUpdateOrgServiceAccountSecretURL(endpoint, version, orgID, serviceAccountID)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	if updateOrgServiceAccountSecretVerbose {
		fmt.Fprintf(os.Stderr, "* Requesting POST %s\n", fullURL)
	}

	// Build request body
	requestBody, err := buildUpdateOrgServiceAccountSecretRequestBody()
	if err != nil {
		return fmt.Errorf("failed to build request body: %w", err)
	}

	if updateOrgServiceAccountSecretVerbose {
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
	if updateOrgServiceAccountSecretVerbose {
		fmt.Fprintf(os.Stderr, "* Checking authentication options\n")
	}

	authHeader, err := buildAuthHeader([]string{}) // No manual headers for this command
	if err != nil {
		if updateOrgServiceAccountSecretVerbose {
			fmt.Fprintf(os.Stderr, "* Warning: failed to get automatic auth: %v\n", err)
		}
		// Don't fail the request, just proceed without automatic auth
	} else if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
		if updateOrgServiceAccountSecretVerbose {
			fmt.Fprintf(os.Stderr, "* Added automatic authorization header\n")
		}
	} else if updateOrgServiceAccountSecretVerbose {
		fmt.Fprintf(os.Stderr, "* No automatic authorization available\n")
	}

	// Set user agent
	req.Header.Set("User-Agent", updateOrgServiceAccountSecretUserAgent)

	// Make the request
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	if updateOrgServiceAccountSecretVerbose {
		fmt.Fprintf(os.Stderr, "* Making request...\n")
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// Handle response using the same pattern as other commands
	return handleUpdateOrgServiceAccountSecretResponse(resp, updateOrgServiceAccountSecretIncludeResp, updateOrgServiceAccountSecretVerbose, updateOrgServiceAccountSecretSilent)
}

func buildUpdateOrgServiceAccountSecretURL(endpoint, version, orgID, serviceAccountID string) (string, error) {
	// Build base URL with organization ID and service account ID path parameters
	baseURL := fmt.Sprintf("https://%s/rest/orgs/%s/service_accounts/%s/secrets", endpoint, orgID, serviceAccountID)

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

func buildUpdateOrgServiceAccountSecretRequestBody() (string, error) {
	// Build request body according to the API specification
	attributes := map[string]interface{}{
		"mode": updateOrgServiceAccountSecretMode,
	}

	// Add secret value if provided (required for delete mode)
	if updateOrgServiceAccountSecretValue != "" {
		attributes["secret"] = updateOrgServiceAccountSecretValue
	}

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

func handleUpdateOrgServiceAccountSecretResponse(resp *http.Response, includeResp, verbose, silent bool) error {
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