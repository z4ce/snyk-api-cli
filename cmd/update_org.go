package cmd

import (
	"encoding/json"
	"fmt"
	"net/url"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// UpdateOrgCmd represents the update-org command
var UpdateOrgCmd = &cobra.Command{
	Use:   "update-org [org_id]",
	Short: "Update an organization",
	Long: `Update an organization in the Snyk API.

This command updates an organization's details by providing the organization ID
as a required argument. The organization name can be updated via the --name flag.

The org-id flag specifies the organization's ID (defaults to the org_id argument).
The type flag specifies the content type (defaults to "org").

Examples:
  snyk-api-cli update-org 12345678-1234-1234-1234-123456789012 --name "My Updated Organization"
  snyk-api-cli update-org 12345678-1234-1234-1234-123456789012 --name "New Org Name" --verbose --include`,
	Args: cobra.ExactArgs(1),
	RunE: runUpdateOrg,
}

var (
	updateOrgName        string
	updateOrgOrgID       string
	updateOrgType        string
	updateOrgVerbose     bool
	updateOrgSilent      bool
	updateOrgIncludeResp bool
	updateOrgUserAgent   string
)

func init() {
	// Add flags for request body attributes
	UpdateOrgCmd.Flags().StringVar(&updateOrgName, "name", "", "Organization name (required)")
	UpdateOrgCmd.Flags().StringVar(&updateOrgOrgID, "org-id", "", "Organization's ID (optional, defaults to org_id argument)")
	UpdateOrgCmd.Flags().StringVar(&updateOrgType, "type", "org", "Content type for the organization (defaults to 'org')")

	// Add standard flags like other commands
	UpdateOrgCmd.Flags().BoolVarP(&updateOrgVerbose, "verbose", "v", false, "Make the operation more talkative")
	UpdateOrgCmd.Flags().BoolVarP(&updateOrgSilent, "silent", "s", false, "Silent mode")
	UpdateOrgCmd.Flags().BoolVarP(&updateOrgIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	UpdateOrgCmd.Flags().StringVarP(&updateOrgUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")

	// Mark required flags
	UpdateOrgCmd.MarkFlagRequired("name")
}

func runUpdateOrg(cmd *cobra.Command, args []string) error {
	orgID := args[0]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Use org ID from argument if not provided via flag
	if updateOrgOrgID == "" {
		updateOrgOrgID = orgID
	}

	// Build the URL
	fullURL, err := buildUpdateOrgURL(endpoint, version, orgID)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	// Build request body
	requestBody, err := buildUpdateOrgRequestBody()
	if err != nil {
		return fmt.Errorf("failed to build request body: %w", err)
	}

	return ExecuteAPIRequest(RequestOptions{
		Method:      "PATCH",
		URL:         fullURL,
		Body:        requestBody,
		Verbose:     updateOrgVerbose,
		Silent:      updateOrgSilent,
		IncludeResp: updateOrgIncludeResp,
		UserAgent:   updateOrgUserAgent,
	})
}

func buildUpdateOrgURL(endpoint, version, orgID string) (string, error) {
	// Build base URL with org ID path parameter
	baseURL := fmt.Sprintf("https://%s/rest/orgs/%s", endpoint, orgID)

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

func buildUpdateOrgRequestBody() (string, error) {
	// Build JSON:API format request body according to the specification
	requestData := map[string]interface{}{
		"data": map[string]interface{}{
			"type": updateOrgType,
			"id":   updateOrgOrgID,
			"attributes": map[string]interface{}{
				"name": updateOrgName,
			},
		},
	}

	// Convert to JSON
	jsonData, err := json.Marshal(requestData)
	if err != nil {
		return "", fmt.Errorf("failed to marshal request body: %w", err)
	}

	return string(jsonData), nil
}
