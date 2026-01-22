package cmd

import (
	"fmt"
	"net/url"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// ListGroupUserOrgMembershipsCmd represents the list-group-user-org-memberships command
var ListGroupUserOrgMembershipsCmd = &cobra.Command{
	Use:   "list-group-user-org-memberships [group_id]",
	Short: "List group user org memberships from Snyk",
	Long: `List group user org memberships from the Snyk API.

This command retrieves a list of organization memberships for a specific user within a group.
The results can be paginated and filtered using various parameters.

Examples:
  snyk-api-cli list-group-user-org-memberships 12345678-1234-1234-1234-123456789012 --user-id 87654321-4321-4321-4321-210987654321
  snyk-api-cli list-group-user-org-memberships 12345678-1234-1234-1234-123456789012 --user-id 87654321-4321-4321-4321-210987654321 --limit 10
  snyk-api-cli list-group-user-org-memberships 12345678-1234-1234-1234-123456789012 --user-id 87654321-4321-4321-4321-210987654321 --org-name "MyOrg"
  snyk-api-cli list-group-user-org-memberships 12345678-1234-1234-1234-123456789012 --user-id 87654321-4321-4321-4321-210987654321 --role-name admin
  snyk-api-cli list-group-user-org-memberships 12345678-1234-1234-1234-123456789012 --user-id 87654321-4321-4321-4321-210987654321 --verbose`,
	Args: cobra.ExactArgs(1),
	RunE: runListGroupUserOrgMemberships,
}

var (
	listGroupUserOrgMembershipsUserID        string
	listGroupUserOrgMembershipsOrgName       string
	listGroupUserOrgMembershipsRoleName      string
	listGroupUserOrgMembershipsStartingAfter string
	listGroupUserOrgMembershipsEndingBefore  string
	listGroupUserOrgMembershipsLimit         int
	listGroupUserOrgMembershipsVerbose       bool
	listGroupUserOrgMembershipsSilent        bool
	listGroupUserOrgMembershipsIncludeResp   bool
	listGroupUserOrgMembershipsUserAgent     string
)

func init() {
	// Add flags for query parameters
	ListGroupUserOrgMembershipsCmd.Flags().StringVar(&listGroupUserOrgMembershipsUserID, "user-id", "", "The ID of the User (required)")
	ListGroupUserOrgMembershipsCmd.Flags().StringVar(&listGroupUserOrgMembershipsOrgName, "org-name", "", "The Name of the org")
	ListGroupUserOrgMembershipsCmd.Flags().StringVar(&listGroupUserOrgMembershipsRoleName, "role-name", "", "Filter the response for results only with the specified role")
	ListGroupUserOrgMembershipsCmd.Flags().StringVar(&listGroupUserOrgMembershipsStartingAfter, "starting-after", "", "Return the page of results immediately after this cursor")
	ListGroupUserOrgMembershipsCmd.Flags().StringVar(&listGroupUserOrgMembershipsEndingBefore, "ending-before", "", "Return the page of results immediately before this cursor")
	ListGroupUserOrgMembershipsCmd.Flags().IntVar(&listGroupUserOrgMembershipsLimit, "limit", 0, "Number of results to return per page")

	// Add standard flags like curl command
	ListGroupUserOrgMembershipsCmd.Flags().BoolVarP(&listGroupUserOrgMembershipsVerbose, "verbose", "v", false, "Make the operation more talkative")
	ListGroupUserOrgMembershipsCmd.Flags().BoolVarP(&listGroupUserOrgMembershipsSilent, "silent", "s", false, "Silent mode")
	ListGroupUserOrgMembershipsCmd.Flags().BoolVarP(&listGroupUserOrgMembershipsIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	ListGroupUserOrgMembershipsCmd.Flags().StringVarP(&listGroupUserOrgMembershipsUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")

	// Mark user-id as required
	ListGroupUserOrgMembershipsCmd.MarkFlagRequired("user-id")
}

func runListGroupUserOrgMemberships(cmd *cobra.Command, args []string) error {
	groupID := args[0]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Build the URL with query parameters
	fullURL, err := buildListGroupUserOrgMembershipsURL(endpoint, groupID, version)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	return ExecuteAPIRequest(RequestOptions{
		Method:      "GET",
		URL:         fullURL,
		Verbose:     listGroupUserOrgMembershipsVerbose,
		Silent:      listGroupUserOrgMembershipsSilent,
		IncludeResp: listGroupUserOrgMembershipsIncludeResp,
		UserAgent:   listGroupUserOrgMembershipsUserAgent,
	})
}

func buildListGroupUserOrgMembershipsURL(endpoint, groupID, version string) (string, error) {
	// Build base URL
	baseURL := fmt.Sprintf("https://%s/rest/groups/%s/org_memberships", endpoint, groupID)

	// Parse URL to handle query parameters properly
	u, err := url.Parse(baseURL)
	if err != nil {
		return "", err
	}

	// Add query parameters
	q := u.Query()

	// Version is required
	q.Set("version", version)

	// user_id is required
	if listGroupUserOrgMembershipsUserID != "" {
		q.Set("user_id", listGroupUserOrgMembershipsUserID)
	}

	// Add optional parameters if provided
	if listGroupUserOrgMembershipsOrgName != "" {
		q.Set("org_name", listGroupUserOrgMembershipsOrgName)
	}
	if listGroupUserOrgMembershipsRoleName != "" {
		q.Set("role_name", listGroupUserOrgMembershipsRoleName)
	}
	if listGroupUserOrgMembershipsStartingAfter != "" {
		q.Set("starting_after", listGroupUserOrgMembershipsStartingAfter)
	}
	if listGroupUserOrgMembershipsEndingBefore != "" {
		q.Set("ending_before", listGroupUserOrgMembershipsEndingBefore)
	}
	if listGroupUserOrgMembershipsLimit > 0 {
		q.Set("limit", fmt.Sprintf("%d", listGroupUserOrgMembershipsLimit))
	}

	u.RawQuery = q.Encode()
	return u.String(), nil
}
