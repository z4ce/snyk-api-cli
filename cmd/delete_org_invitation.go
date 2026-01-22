package cmd

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// DeleteOrgInvitationCmd represents the delete-org-invitation command
var DeleteOrgInvitationCmd = &cobra.Command{
	Use:   "delete-org-invitation [org_id] [invite_id]",
	Short: "Cancel a pending user invitation to an organization",
	Long: `Cancel a pending user invitation to an organization from the Snyk API.

This command cancels a specific pending invitation using its unique identifier within an organization.
Both org_id and invite_id parameters are required and must be valid UUIDs.

Examples:
  snyk-api-cli delete-org-invitation 12345678-1234-5678-9012-123456789012 87654321-4321-8765-2109-876543210987
  snyk-api-cli delete-org-invitation --verbose 12345678-1234-5678-9012-123456789012 87654321-4321-8765-2109-876543210987
  snyk-api-cli delete-org-invitation --include 12345678-1234-5678-9012-123456789012 87654321-4321-8765-2109-876543210987`,
	Args: cobra.ExactArgs(2),
	RunE: runDeleteOrgInvitation,
}

var (
	deleteOrgInvitationVerbose     bool
	deleteOrgInvitationSilent      bool
	deleteOrgInvitationIncludeResp bool
	deleteOrgInvitationUserAgent   string
)

func init() {
	// Add standard flags like other commands
	DeleteOrgInvitationCmd.Flags().BoolVarP(&deleteOrgInvitationVerbose, "verbose", "v", false, "Make the operation more talkative")
	DeleteOrgInvitationCmd.Flags().BoolVarP(&deleteOrgInvitationSilent, "silent", "s", false, "Silent mode")
	DeleteOrgInvitationCmd.Flags().BoolVarP(&deleteOrgInvitationIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	DeleteOrgInvitationCmd.Flags().StringVarP(&deleteOrgInvitationUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")
}

func runDeleteOrgInvitation(cmd *cobra.Command, args []string) error {
	orgID := args[0]
	inviteID := args[1]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Build the URL with the org_id and invite_id path parameters
	fullURL, err := buildDeleteOrgInvitationURL(endpoint, orgID, inviteID, version)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	return ExecuteAPIRequest(RequestOptions{
		Method:      "DELETE",
		URL:         fullURL,
		Verbose:     deleteOrgInvitationVerbose,
		Silent:      deleteOrgInvitationSilent,
		IncludeResp: deleteOrgInvitationIncludeResp,
		UserAgent:   deleteOrgInvitationUserAgent,
	})
}

func buildDeleteOrgInvitationURL(endpoint, orgID, inviteID, version string) (string, error) {
	// Validate the org_id parameter
	if strings.TrimSpace(orgID) == "" {
		return "", fmt.Errorf("org_id cannot be empty")
	}

	// Validate the invite_id parameter
	if strings.TrimSpace(inviteID) == "" {
		return "", fmt.Errorf("invite_id cannot be empty")
	}

	// Build base URL with the path parameters
	baseURL := fmt.Sprintf("https://%s/rest/orgs/%s/invites/%s", endpoint, orgID, inviteID)

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
