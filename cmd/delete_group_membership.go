package cmd

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// DeleteGroupMembershipCmd represents the delete-group-membership command
var DeleteGroupMembershipCmd = &cobra.Command{
	Use:   "delete-group-membership [group_id] [membership_id]",
	Short: "Delete a group membership from Snyk",
	Long: `Delete a group membership from the Snyk API.

This command deletes a specific group membership using the group ID and membership ID.
Both group_id and membership_id parameters are required and must be valid UUIDs.

Examples:
  snyk-api-cli delete-group-membership 12345678-1234-5678-9012-123456789012 87654321-4321-8765-2109-876543210987
  snyk-api-cli delete-group-membership 12345678-1234-5678-9012-123456789012 87654321-4321-8765-2109-876543210987 --cascade
  snyk-api-cli delete-group-membership --verbose 12345678-1234-5678-9012-123456789012 87654321-4321-8765-2109-876543210987
  snyk-api-cli delete-group-membership --include 12345678-1234-5678-9012-123456789012 87654321-4321-8765-2109-876543210987`,
	Args: cobra.ExactArgs(2),
	RunE: runDeleteGroupMembership,
}

var (
	deleteGroupMembershipCascade     bool
	deleteGroupMembershipVerbose     bool
	deleteGroupMembershipSilent      bool
	deleteGroupMembershipIncludeResp bool
	deleteGroupMembershipUserAgent   string
)

func init() {
	// Add cascade flag for the optional query parameter
	DeleteGroupMembershipCmd.Flags().BoolVar(&deleteGroupMembershipCascade, "cascade", false, "Indicates whether to delete child org memberships")

	// Add standard flags like curl command
	DeleteGroupMembershipCmd.Flags().BoolVarP(&deleteGroupMembershipVerbose, "verbose", "v", false, "Make the operation more talkative")
	DeleteGroupMembershipCmd.Flags().BoolVarP(&deleteGroupMembershipSilent, "silent", "s", false, "Silent mode")
	DeleteGroupMembershipCmd.Flags().BoolVarP(&deleteGroupMembershipIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	DeleteGroupMembershipCmd.Flags().StringVarP(&deleteGroupMembershipUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")
}

func runDeleteGroupMembership(cmd *cobra.Command, args []string) error {
	groupID := args[0]
	membershipID := args[1]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Build the URL with the group_id and membership_id path parameters
	fullURL, err := buildDeleteGroupMembershipURL(endpoint, groupID, membershipID, version)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	return ExecuteAPIRequest(RequestOptions{
		Method:      "DELETE",
		URL:         fullURL,
		Verbose:     deleteGroupMembershipVerbose,
		Silent:      deleteGroupMembershipSilent,
		IncludeResp: deleteGroupMembershipIncludeResp,
		UserAgent:   deleteGroupMembershipUserAgent,
	})
}

func buildDeleteGroupMembershipURL(endpoint, groupID, membershipID, version string) (string, error) {
	// Validate the group_id parameter
	if strings.TrimSpace(groupID) == "" {
		return "", fmt.Errorf("group_id cannot be empty")
	}

	// Validate the membership_id parameter
	if strings.TrimSpace(membershipID) == "" {
		return "", fmt.Errorf("membership_id cannot be empty")
	}

	// Build base URL with the path parameters
	baseURL := fmt.Sprintf("https://%s/rest/groups/%s/memberships/%s", endpoint, groupID, membershipID)

	// Parse URL to handle query parameters properly
	u, err := url.Parse(baseURL)
	if err != nil {
		return "", err
	}

	// Add query parameters
	q := u.Query()

	// Version is required
	q.Set("version", version)

	// Add optional cascade parameter if provided
	if deleteGroupMembershipCascade {
		q.Set("cascade", "true")
	}

	u.RawQuery = q.Encode()
	return u.String(), nil
}
