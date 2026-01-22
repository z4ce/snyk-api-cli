package cmd

import (
	"encoding/json"
	"fmt"
	"net/url"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// CreateOrgMembershipCmd represents the create-org-membership command
var CreateOrgMembershipCmd = &cobra.Command{
	Use:   "create-org-membership [org_id]",
	Short: "Create an organization membership for a user with role in Snyk",
	Long: `Create an organization membership for a user with role in the Snyk API.

This command creates a membership for a specific user in an organization with a specified role.
The organization ID must be provided as a required argument, and the user ID and role ID 
must be provided as flags.

Examples:
  snyk-api-cli create-org-membership 12345678-1234-1234-1234-123456789012 --user-id 87654321-4321-4321-4321-876543210987 --role-id 11111111-2222-3333-4444-555555555555
  snyk-api-cli create-org-membership 12345678-1234-1234-1234-123456789012 --user-id 87654321-4321-4321-4321-876543210987 --role-id 11111111-2222-3333-4444-555555555555 --verbose`,
	Args: cobra.ExactArgs(1),
	RunE: runCreateOrgMembership,
}

var (
	createOrgMembershipUserID      string
	createOrgMembershipRoleID      string
	createOrgMembershipVerbose     bool
	createOrgMembershipSilent      bool
	createOrgMembershipIncludeResp bool
	createOrgMembershipUserAgent   string
)

func init() {
	// Add flags for request body attributes
	CreateOrgMembershipCmd.Flags().StringVar(&createOrgMembershipUserID, "user-id", "", "User ID to add to the organization (required)")
	CreateOrgMembershipCmd.Flags().StringVar(&createOrgMembershipRoleID, "role-id", "", "Role ID to assign to the user (required)")

	// Add standard flags like other commands
	CreateOrgMembershipCmd.Flags().BoolVarP(&createOrgMembershipVerbose, "verbose", "v", false, "Make the operation more talkative")
	CreateOrgMembershipCmd.Flags().BoolVarP(&createOrgMembershipSilent, "silent", "s", false, "Silent mode")
	CreateOrgMembershipCmd.Flags().BoolVarP(&createOrgMembershipIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	CreateOrgMembershipCmd.Flags().StringVarP(&createOrgMembershipUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")

	// Mark required flags
	CreateOrgMembershipCmd.MarkFlagRequired("user-id")
	CreateOrgMembershipCmd.MarkFlagRequired("role-id")
}

func runCreateOrgMembership(cmd *cobra.Command, args []string) error {
	orgID := args[0]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Build the URL
	fullURL, err := buildCreateOrgMembershipURL(endpoint, version, orgID)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	// Build request body
	requestBody, err := buildCreateOrgMembershipRequestBody(orgID)
	if err != nil {
		return fmt.Errorf("failed to build request body: %w", err)
	}

	return ExecuteAPIRequest(RequestOptions{
		Method:      "POST",
		URL:         fullURL,
		Body:        requestBody,
		ContentType: "application/vnd.api+json",
		Verbose:     createOrgMembershipVerbose,
		Silent:      createOrgMembershipSilent,
		IncludeResp: createOrgMembershipIncludeResp,
		UserAgent:   createOrgMembershipUserAgent,
	})
}

func buildCreateOrgMembershipURL(endpoint, version, orgID string) (string, error) {
	// Build base URL with organization ID path parameter
	baseURL := fmt.Sprintf("https://%s/rest/orgs/%s/memberships", endpoint, orgID)

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

func buildCreateOrgMembershipRequestBody(orgID string) (string, error) {
	// Build request body according to the JSON:API specification
	requestData := map[string]interface{}{
		"data": map[string]interface{}{
			"type": "org_membership",
			"relationships": map[string]interface{}{
				"org": map[string]interface{}{
					"data": map[string]interface{}{
						"id":   orgID,
						"type": "org",
					},
				},
				"role": map[string]interface{}{
					"data": map[string]interface{}{
						"id":   createOrgMembershipRoleID,
						"type": "org_role",
					},
				},
				"user": map[string]interface{}{
					"data": map[string]interface{}{
						"id":   createOrgMembershipUserID,
						"type": "user",
					},
				},
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
