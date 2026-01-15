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

// UpdateGroupServiceAccountCmd represents the update-group-service-account command
var UpdateGroupServiceAccountCmd = &cobra.Command{
	Use:   "update-group-service-account [group_id] [serviceaccount_id]",
	Short: "Update a service account for a specific group in Snyk",
	Long: `Update a service account for a specific group in the Snyk API.

This command updates a service account by providing the required attributes such as
name. The group ID and service account ID must be provided as required arguments.

Examples:
  snyk-api-cli update-group-service-account 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321 --name "Updated Service Account Name"
  snyk-api-cli update-group-service-account 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321 --name "New Name" --verbose --include`,
	Args: cobra.ExactArgs(2),
	RunE: runUpdateGroupServiceAccount,
}

var (
	updateGroupServiceAccountName        string
	updateGroupServiceAccountVerbose     bool
	updateGroupServiceAccountSilent      bool
	updateGroupServiceAccountIncludeResp bool
	updateGroupServiceAccountUserAgent   string
)

func init() {
	// Add flags for request body attributes
	UpdateGroupServiceAccountCmd.Flags().StringVar(&updateGroupServiceAccountName, "name", "", "Human-friendly service account name (required)")

	// Add standard flags like other commands
	UpdateGroupServiceAccountCmd.Flags().BoolVarP(&updateGroupServiceAccountVerbose, "verbose", "v", false, "Make the operation more talkative")
	UpdateGroupServiceAccountCmd.Flags().BoolVarP(&updateGroupServiceAccountSilent, "silent", "s", false, "Silent mode")
	UpdateGroupServiceAccountCmd.Flags().BoolVarP(&updateGroupServiceAccountIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	UpdateGroupServiceAccountCmd.Flags().StringVarP(&updateGroupServiceAccountUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")

	// Mark required flags
	UpdateGroupServiceAccountCmd.MarkFlagRequired("name")
}

func runUpdateGroupServiceAccount(cmd *cobra.Command, args []string) error {
	groupID := args[0]
	serviceAccountID := args[1]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Build the URL
	fullURL, err := buildUpdateGroupServiceAccountURL(endpoint, version, groupID, serviceAccountID)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	if updateGroupServiceAccountVerbose {
		fmt.Fprintf(os.Stderr, "* Requesting PATCH %s\n", fullURL)
	}

	// Build request body
	requestBody, err := buildUpdateGroupServiceAccountRequestBody(serviceAccountID)
	if err != nil {
		return fmt.Errorf("failed to build request body: %w", err)
	}

	if updateGroupServiceAccountVerbose {
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
	if updateGroupServiceAccountVerbose {
		fmt.Fprintf(os.Stderr, "* Checking authentication options\n")
	}

	authHeader, err := buildAuthHeader([]string{}) // No manual headers for this command
	if err != nil {
		if updateGroupServiceAccountVerbose {
			fmt.Fprintf(os.Stderr, "* Warning: failed to get automatic auth: %v\n", err)
		}
		// Don't fail the request, just proceed without automatic auth
	} else if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
		if updateGroupServiceAccountVerbose {
			fmt.Fprintf(os.Stderr, "* Added automatic authorization header\n")
		}
	} else if updateGroupServiceAccountVerbose {
		fmt.Fprintf(os.Stderr, "* No automatic authorization available\n")
	}

	// Set user agent
	req.Header.Set("User-Agent", updateGroupServiceAccountUserAgent)

	// Make the request
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	if updateGroupServiceAccountVerbose {
		fmt.Fprintf(os.Stderr, "* Making request...\n")
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// Handle response using the same pattern as other commands
	return handleUpdateGroupServiceAccountResponse(resp, updateGroupServiceAccountIncludeResp, updateGroupServiceAccountVerbose, updateGroupServiceAccountSilent)
}

func buildUpdateGroupServiceAccountURL(endpoint, version, groupID, serviceAccountID string) (string, error) {
	// Build base URL with group ID and service account ID path parameters
	baseURL := fmt.Sprintf("https://%s/rest/groups/%s/service_accounts/%s", endpoint, groupID, serviceAccountID)

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

func buildUpdateGroupServiceAccountRequestBody(serviceAccountID string) (string, error) {
	// Build attributes object
	attributes := map[string]interface{}{
		"name": updateGroupServiceAccountName,
	}

	// Build JSON:API format request body according to the specification
	requestData := map[string]interface{}{
		"data": map[string]interface{}{
			"type":       "service_account",
			"id":         serviceAccountID,
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

func handleUpdateGroupServiceAccountResponse(resp *http.Response, includeResp, verbose, silent bool) error {
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