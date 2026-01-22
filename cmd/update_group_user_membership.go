package cmd

import (
	"encoding/json"
	"fmt"
	"net/url"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// UpdateGroupUserMembershipCmd represents the update-group-user-membership command
var UpdateGroupUserMembershipCmd = &cobra.Command{
	Use:   "update-group-user-membership [group_id] [membership_id]",
	Short: "Update a user's membership in a group",
	Long: `Update a user's membership in a group in the Snyk API.

This command updates a user's membership by changing their role within a group.
Both the group ID and membership ID must be provided as required arguments.

The role-id flag specifies the new role to assign to the user's membership.

Examples:
  snyk-api-cli update-group-user-membership 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321 --role-id 11111111-1111-1111-1111-111111111111
  snyk-api-cli update-group-user-membership 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321 --role-id 11111111-1111-1111-1111-111111111111 --verbose --include`,
	Args: cobra.ExactArgs(2),
	RunE: runUpdateGroupUserMembership,
}

var (
	updateGroupUserMembershipRoleID      string
	updateGroupUserMembershipID          string
	updateGroupUserMembershipType        string
	updateGroupUserMembershipVerbose     bool
	updateGroupUserMembershipSilent      bool
	updateGroupUserMembershipIncludeResp bool
	updateGroupUserMembershipUserAgent   string
)

func init() {
	// Add flags for request body attributes
	UpdateGroupUserMembershipCmd.Flags().StringVar(&updateGroupUserMembershipRoleID, "role-id", "", "Role ID to assign to the user (required)")
	UpdateGroupUserMembershipCmd.Flags().StringVar(&updateGroupUserMembershipID, "id", "", "Membership ID (optional, defaults to membership_id argument)")
	UpdateGroupUserMembershipCmd.Flags().StringVar(&updateGroupUserMembershipType, "type", "", "Type field for the membership (optional)")
	
	// Add standard flags like other commands
	UpdateGroupUserMembershipCmd.Flags().BoolVarP(&updateGroupUserMembershipVerbose, "verbose", "v", false, "Make the operation more talkative")
	UpdateGroupUserMembershipCmd.Flags().BoolVarP(&updateGroupUserMembershipSilent, "silent", "s", false, "Silent mode")
	UpdateGroupUserMembershipCmd.Flags().BoolVarP(&updateGroupUserMembershipIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	UpdateGroupUserMembershipCmd.Flags().StringVarP(&updateGroupUserMembershipUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")

	// Mark required flags
	UpdateGroupUserMembershipCmd.MarkFlagRequired("role-id")
}

func runUpdateGroupUserMembership(cmd *cobra.Command, args []string) error {
	groupID := args[0]
	membershipID := args[1]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Use membership ID from argument if not provided via flag
	if updateGroupUserMembershipID == "" {
		updateGroupUserMembershipID = membershipID
	}

	// Build the URL
	fullURL, err := buildUpdateGroupUserMembershipURL(endpoint, version, groupID, membershipID)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	// Build request body
	requestBody, err := buildUpdateGroupUserMembershipRequestBody()
	if err != nil {
		return fmt.Errorf("failed to build request body: %w", err)
	}

	return ExecuteAPIRequest(RequestOptions{
		Method:      "PATCH",
		URL:         fullURL,
		Body:        requestBody,
		Verbose:     updateGroupUserMembershipVerbose,
		Silent:      updateGroupUserMembershipSilent,
		IncludeResp: updateGroupUserMembershipIncludeResp,
		UserAgent:   updateGroupUserMembershipUserAgent,
	})
}

func buildUpdateGroupUserMembershipURL(endpoint, version, groupID, membershipID string) (string, error) {
	// Build base URL with group ID and membership ID path parameters
	baseURL := fmt.Sprintf("https://%s/rest/groups/%s/memberships/%s", endpoint, groupID, membershipID)

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

func buildUpdateGroupUserMembershipRequestBody() (string, error) {
	// Build JSON:API format request body according to the specification
	requestData := map[string]interface{}{
		"data": map[string]interface{}{
			"id": updateGroupUserMembershipID,
			"relationships": map[string]interface{}{
				"role": map[string]interface{}{
					"data": map[string]interface{}{
						"id":   updateGroupUserMembershipRoleID,
						"type": "group_role",
					},
				},
			},
		},
	}

	// Add optional attributes if provided
	dataMap := requestData["data"].(map[string]interface{})
	if updateGroupUserMembershipType != "" {
		dataMap["type"] = updateGroupUserMembershipType
	}

	// Convert to JSON
	jsonData, err := json.Marshal(requestData)
	if err != nil {
		return "", fmt.Errorf("failed to marshal request body: %w", err)
	}

	return string(jsonData), nil
}
