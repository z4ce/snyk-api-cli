package cmd

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// DeleteOrgMembershipCmd represents the delete-org-membership command
var DeleteOrgMembershipCmd = &cobra.Command{
	Use:   "delete-org-membership [org_id] [membership_id]",
	Short: "Remove user's organization membership from Snyk",
	Long: `Remove user's organization membership from the Snyk API.

This command deletes a specific organization membership using its unique identifier within an organization.
Both org_id and membership_id parameters are required and must be valid UUIDs.

Examples:
  snyk-api-cli delete-org-membership 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-876543210987
  snyk-api-cli delete-org-membership 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-876543210987 --verbose
  snyk-api-cli delete-org-membership 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-876543210987 --include`,
	Args: cobra.ExactArgs(2),
	RunE: runDeleteOrgMembership,
}

var (
	deleteOrgMembershipVerbose     bool
	deleteOrgMembershipSilent      bool
	deleteOrgMembershipIncludeResp bool
	deleteOrgMembershipUserAgent   string
)

func init() {
	// Add standard flags like other commands
	DeleteOrgMembershipCmd.Flags().BoolVarP(&deleteOrgMembershipVerbose, "verbose", "v", false, "Make the operation more talkative")
	DeleteOrgMembershipCmd.Flags().BoolVarP(&deleteOrgMembershipSilent, "silent", "s", false, "Silent mode")
	DeleteOrgMembershipCmd.Flags().BoolVarP(&deleteOrgMembershipIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	DeleteOrgMembershipCmd.Flags().StringVarP(&deleteOrgMembershipUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")
}

func runDeleteOrgMembership(cmd *cobra.Command, args []string) error {
	orgID := args[0]
	membershipID := args[1]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Build the URL with the org_id and membership_id path parameters
	fullURL, err := buildDeleteOrgMembershipURL(endpoint, orgID, membershipID, version)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	return ExecuteAPIRequest(RequestOptions{
		Method:      "DELETE",
		URL:         fullURL,
		Verbose:     deleteOrgMembershipVerbose,
		Silent:      deleteOrgMembershipSilent,
		IncludeResp: deleteOrgMembershipIncludeResp,
		UserAgent:   deleteOrgMembershipUserAgent,
	})
}

func buildDeleteOrgMembershipURL(endpoint, orgID, membershipID, version string) (string, error) {
	// Validate the org_id parameter
	if strings.TrimSpace(orgID) == "" {
		return "", fmt.Errorf("org_id cannot be empty")
	}

	// Validate the membership_id parameter
	if strings.TrimSpace(membershipID) == "" {
		return "", fmt.Errorf("membership_id cannot be empty")
	}

	// Build base URL with the path parameters
	baseURL := fmt.Sprintf("https://%s/rest/orgs/%s/memberships/%s", endpoint, orgID, membershipID)

	// Parse URL to handle query parameters properly
	u, err := url.Parse(baseURL)
	if err != nil {
		return "", err
	}

	// Add required version query parameter
	q := u.Query()
	q.Set("version", version)
	u.RawQuery = q.Encode()

	return u.String(), nil
}
