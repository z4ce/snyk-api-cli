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

// UpdateOrgServiceAccountCmd represents the update-org-service-account command
var UpdateOrgServiceAccountCmd = &cobra.Command{
	Use:   "update-org-service-account [org_id] [serviceaccount_id]",
	Short: "Update an organization service account",
	Long: `Update an organization service account in the Snyk API.

This command updates a service account in the specified organization using the Snyk API.
Both org_id and serviceaccount_id parameters are required and should be valid UUIDs.
The name is the only updatable attribute for service accounts.

Required permissions: Edit service accounts (org.service_account.edit)

Examples:
  snyk-api-cli update-org-service-account 12345678-1234-1234-1234-123456789012 87654321-4321-8765-2109-876543210987 --name "Updated Service Account Name"
  snyk-api-cli update-org-service-account 12345678-1234-1234-1234-123456789012 87654321-4321-8765-2109-876543210987 --name "CI/CD Service Account" --verbose`,
	Args: cobra.ExactArgs(2),
	RunE: runUpdateOrgServiceAccount,
}

var (
	updateOrgServiceAccountName         string
	updateOrgServiceAccountVerboseFlag  bool
	updateOrgServiceAccountSilentFlag   bool
	updateOrgServiceAccountIncludeFlag  bool
	updateOrgServiceAccountUserAgentFlag string
)

func init() {
	// Add flags for request body attributes
	UpdateOrgServiceAccountCmd.Flags().StringVar(&updateOrgServiceAccountName, "name", "", "Name of the service account (required)")
	
	// Add standard flags like curl command
	UpdateOrgServiceAccountCmd.Flags().BoolVarP(&updateOrgServiceAccountVerboseFlag, "verbose", "v", false, "Make the operation more talkative")
	UpdateOrgServiceAccountCmd.Flags().BoolVarP(&updateOrgServiceAccountSilentFlag, "silent", "s", false, "Silent mode")
	UpdateOrgServiceAccountCmd.Flags().BoolVarP(&updateOrgServiceAccountIncludeFlag, "include", "i", false, "Include HTTP response headers in output")
	UpdateOrgServiceAccountCmd.Flags().StringVarP(&updateOrgServiceAccountUserAgentFlag, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")
	
	// Mark required flags
	UpdateOrgServiceAccountCmd.MarkFlagRequired("name")
}

func runUpdateOrgServiceAccount(cmd *cobra.Command, args []string) error {
	orgID := args[0]
	serviceAccountID := args[1]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Build the URL
	fullURL, err := buildUpdateOrgServiceAccountURL(endpoint, orgID, serviceAccountID, version)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	if updateOrgServiceAccountVerboseFlag {
		fmt.Fprintf(os.Stderr, "* Requesting PATCH %s\n", fullURL)
	}

	// Build request body
	requestBody, err := buildUpdateOrgServiceAccountRequestBody(serviceAccountID)
	if err != nil {
		return fmt.Errorf("failed to build request body: %w", err)
	}

	if updateOrgServiceAccountVerboseFlag {
		fmt.Fprintf(os.Stderr, "* Request body: %s\n", requestBody)
	}

	// Create the HTTP request
	req, err := http.NewRequest("PATCH", fullURL, strings.NewReader(requestBody))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Set content type for JSON:API
	req.Header.Set("Content-Type", "application/vnd.api+json")

	// Handle authentication with same precedence as curl: Authorization header > SNYK_TOKEN > OAuth
	if updateOrgServiceAccountVerboseFlag {
		fmt.Fprintf(os.Stderr, "* Checking authentication options\n")
	}

	authHeader, err := buildAuthHeader([]string{}) // No manual headers for this command
	if err != nil {
		if updateOrgServiceAccountVerboseFlag {
			fmt.Fprintf(os.Stderr, "* Warning: failed to get automatic auth: %v\n", err)
		}
		// Don't fail the request, just proceed without automatic auth
	} else if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
		if updateOrgServiceAccountVerboseFlag {
			fmt.Fprintf(os.Stderr, "* Added automatic authorization header\n")
		}
	} else if updateOrgServiceAccountVerboseFlag {
		fmt.Fprintf(os.Stderr, "* No automatic authorization available\n")
	}

	// Set user agent
	req.Header.Set("User-Agent", updateOrgServiceAccountUserAgentFlag)

	// Make the request
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	if updateOrgServiceAccountVerboseFlag {
		fmt.Fprintf(os.Stderr, "* Making request...\n")
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// Handle response using the same pattern as curl
	return handleUpdateOrgServiceAccountResponse(resp, updateOrgServiceAccountIncludeFlag, updateOrgServiceAccountVerboseFlag, updateOrgServiceAccountSilentFlag)
}

func buildUpdateOrgServiceAccountURL(endpoint, orgID, serviceAccountID, version string) (string, error) {
	// Build base URL
	baseURL := fmt.Sprintf("https://%s/rest/orgs/%s/service_accounts/%s", endpoint, orgID, serviceAccountID)

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

func buildUpdateOrgServiceAccountRequestBody(serviceAccountID string) (string, error) {
	// Build JSON:API format request body
	data := map[string]interface{}{
		"type": "service_account",
		"id":   serviceAccountID,
	}

	// Build attributes object
	attributes := make(map[string]interface{})
	
	if updateOrgServiceAccountName != "" {
		attributes["name"] = updateOrgServiceAccountName
	}

	// Add attributes if any were provided
	if len(attributes) > 0 {
		data["attributes"] = attributes
	}

	requestData := map[string]interface{}{
		"data": data,
	}

	// Convert to JSON
	jsonData, err := json.Marshal(requestData)
	if err != nil {
		return "", fmt.Errorf("failed to marshal request body: %w", err)
	}

	return string(jsonData), nil
}

func handleUpdateOrgServiceAccountResponse(resp *http.Response, includeResp, verbose, silent bool) error {
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