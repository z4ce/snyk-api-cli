package cmd

import (
	"fmt"
	"net/url"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// ListOrgInvitationCmd represents the list-org-invitation command
var ListOrgInvitationCmd = &cobra.Command{
	Use:   "list-org-invitation [org_id]",
	Short: "List pending user invitations to an organization",
	Long: `List pending user invitations to an organization from the Snyk API.

This command retrieves a list of pending user invitations for a specific organization.
The organization ID must be provided as a required argument. The results can be
paginated using various query parameters.

Examples:
  snyk-api-cli list-org-invitation 12345678-1234-1234-1234-123456789012
  snyk-api-cli list-org-invitation 12345678-1234-1234-1234-123456789012 --limit 10
  snyk-api-cli list-org-invitation 12345678-1234-1234-1234-123456789012 --starting-after "v1.eyJpZCI6IjEwMDAifQo="
  snyk-api-cli list-org-invitation 12345678-1234-1234-1234-123456789012 --ending-before "v1.eyJpZCI6IjExMDAifQo="
  snyk-api-cli list-org-invitation 12345678-1234-1234-1234-123456789012 --verbose`,
	Args: cobra.ExactArgs(1),
	RunE: runListOrgInvitation,
}

var (
	listOrgInvitationLimit         int
	listOrgInvitationStartingAfter string
	listOrgInvitationEndingBefore  string
	listOrgInvitationVerbose       bool
	listOrgInvitationSilent        bool
	listOrgInvitationIncludeResp   bool
	listOrgInvitationUserAgent     string
)

func init() {
	// Add flags for query parameters
	ListOrgInvitationCmd.Flags().IntVar(&listOrgInvitationLimit, "limit", 0, "Number of results to return per page")
	ListOrgInvitationCmd.Flags().StringVar(&listOrgInvitationStartingAfter, "starting-after", "", "Return the page of results immediately after this cursor")
	ListOrgInvitationCmd.Flags().StringVar(&listOrgInvitationEndingBefore, "ending-before", "", "Return the page of results immediately before this cursor")

	// Add standard flags like other commands
	ListOrgInvitationCmd.Flags().BoolVarP(&listOrgInvitationVerbose, "verbose", "v", false, "Make the operation more talkative")
	ListOrgInvitationCmd.Flags().BoolVarP(&listOrgInvitationSilent, "silent", "s", false, "Silent mode")
	ListOrgInvitationCmd.Flags().BoolVarP(&listOrgInvitationIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	ListOrgInvitationCmd.Flags().StringVarP(&listOrgInvitationUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")
}

func runListOrgInvitation(cmd *cobra.Command, args []string) error {
	orgID := args[0]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Build the URL with query parameters
	fullURL, err := buildListOrgInvitationURL(endpoint, version, orgID)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	return ExecuteAPIRequest(RequestOptions{
		Method:      "GET",
		URL:         fullURL,
		Verbose:     listOrgInvitationVerbose,
		Silent:      listOrgInvitationSilent,
		IncludeResp: listOrgInvitationIncludeResp,
		UserAgent:   listOrgInvitationUserAgent,
	})
}

func buildListOrgInvitationURL(endpoint, version, orgID string) (string, error) {
	// Build base URL
	baseURL := fmt.Sprintf("https://%s/rest/orgs/%s/invites", endpoint, orgID)

	// Parse URL to handle query parameters properly
	u, err := url.Parse(baseURL)
	if err != nil {
		return "", err
	}

	// Add query parameters
	q := u.Query()

	// Version is required
	q.Set("version", version)

	// Add optional parameters if provided
	if listOrgInvitationLimit > 0 {
		q.Set("limit", fmt.Sprintf("%d", listOrgInvitationLimit))
	}
	if listOrgInvitationStartingAfter != "" {
		q.Set("starting_after", listOrgInvitationStartingAfter)
	}
	if listOrgInvitationEndingBefore != "" {
		q.Set("ending_before", listOrgInvitationEndingBefore)
	}

	u.RawQuery = q.Encode()
	return u.String(), nil
}
