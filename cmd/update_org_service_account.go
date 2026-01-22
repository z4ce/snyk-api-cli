package cmd

import (
	"encoding/json"
	"fmt"
	"net/url"

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
	updateOrgServiceAccountName          string
	updateOrgServiceAccountVerboseFlag   bool
	updateOrgServiceAccountSilentFlag    bool
	updateOrgServiceAccountIncludeFlag   bool
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

	// Build request body
	requestBody, err := buildUpdateOrgServiceAccountRequestBody(serviceAccountID)
	if err != nil {
		return fmt.Errorf("failed to build request body: %w", err)
	}

	return ExecuteAPIRequest(RequestOptions{
		Method:      "PATCH",
		URL:         fullURL,
		Body:        requestBody,
		Verbose:     updateOrgServiceAccountVerboseFlag,
		Silent:      updateOrgServiceAccountSilentFlag,
		IncludeResp: updateOrgServiceAccountIncludeFlag,
		UserAgent:   updateOrgServiceAccountUserAgentFlag,
	})
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
