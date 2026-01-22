package cmd

import (
	"encoding/json"
	"fmt"
	"net/url"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// UpdateOrgMembershipCmd represents the update-org-membership command
var UpdateOrgMembershipCmd = &cobra.Command{
	Use:   "update-org-membership [org_id] [membership_id]",
	Short: "Update an organization membership role in Snyk",
	Long: `Update an organization membership role in the Snyk API.

This command updates the role of an existing membership in the specified organization.
Both org_id and membership_id parameters are required and should be valid UUIDs.
The new role ID must be provided as a flag.

Examples:
  snyk-api-cli update-org-membership 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-876543210987 --role-id 11111111-2222-3333-4444-555555555555
  snyk-api-cli update-org-membership 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-876543210987 --role-id 11111111-2222-3333-4444-555555555555 --verbose`,
	Args: cobra.ExactArgs(2),
	RunE: runUpdateOrgMembership,
}

var (
	updateOrgMembershipRoleID      string
	updateOrgMembershipVerbose     bool
	updateOrgMembershipSilent      bool
	updateOrgMembershipIncludeResp bool
	updateOrgMembershipUserAgent   string
)

func init() {
	// Add flags for request body attributes
	UpdateOrgMembershipCmd.Flags().StringVar(&updateOrgMembershipRoleID, "role-id", "", "New role ID to assign to the membership (required)")
	
	// Add standard flags like other commands
	UpdateOrgMembershipCmd.Flags().BoolVarP(&updateOrgMembershipVerbose, "verbose", "v", false, "Make the operation more talkative")
	UpdateOrgMembershipCmd.Flags().BoolVarP(&updateOrgMembershipSilent, "silent", "s", false, "Silent mode")
	UpdateOrgMembershipCmd.Flags().BoolVarP(&updateOrgMembershipIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	UpdateOrgMembershipCmd.Flags().StringVarP(&updateOrgMembershipUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")
	
	// Mark required flags
	UpdateOrgMembershipCmd.MarkFlagRequired("role-id")
}

func runUpdateOrgMembership(cmd *cobra.Command, args []string) error {
	orgID := args[0]
	membershipID := args[1]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Build the URL
	fullURL, err := buildUpdateOrgMembershipURL(endpoint, orgID, membershipID, version)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	// Build request body
	requestBody, err := buildUpdateOrgMembershipRequestBody(membershipID)
	if err != nil {
		return fmt.Errorf("failed to build request body: %w", err)
	}

	return ExecuteAPIRequest(RequestOptions{
		Method:      "PATCH",
		URL:         fullURL,
		Body:        requestBody,
		Verbose:     updateOrgMembershipVerbose,
		Silent:      updateOrgMembershipSilent,
		IncludeResp: updateOrgMembershipIncludeResp,
		UserAgent:   updateOrgMembershipUserAgent,
	})
}

func buildUpdateOrgMembershipURL(endpoint, orgID, membershipID, version string) (string, error) {
	// Build base URL
	baseURL := fmt.Sprintf("https://%s/rest/orgs/%s/memberships/%s", endpoint, orgID, membershipID)

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

func buildUpdateOrgMembershipRequestBody(membershipID string) (string, error) {
	// Build JSON:API format request body
	requestData := map[string]interface{}{
		"data": map[string]interface{}{
			"id":   membershipID,
			"type": "org_membership",
			"relationships": map[string]interface{}{
				"role": map[string]interface{}{
					"data": map[string]interface{}{
						"id":   updateOrgMembershipRoleID,
						"type": "org_role",
					},
				},
			},
			"attributes": map[string]interface{}{},
		},
	}

	// Convert to JSON
	jsonData, err := json.Marshal(requestData)
	if err != nil {
		return "", fmt.Errorf("failed to marshal request body: %w", err)
	}

	return string(jsonData), nil
}
