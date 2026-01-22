package cmd

import (
	"encoding/json"
	"fmt"
	"net/url"

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

	// Build request body
	requestBody, err := buildUpdateGroupServiceAccountRequestBody(serviceAccountID)
	if err != nil {
		return fmt.Errorf("failed to build request body: %w", err)
	}

	return ExecuteAPIRequest(RequestOptions{
		Method:      "PATCH",
		URL:         fullURL,
		Body:        requestBody,
		Verbose:     updateGroupServiceAccountVerbose,
		Silent:      updateGroupServiceAccountSilent,
		IncludeResp: updateGroupServiceAccountIncludeResp,
		UserAgent:   updateGroupServiceAccountUserAgent,
	})
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
