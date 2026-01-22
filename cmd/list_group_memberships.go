package cmd

import (
	"fmt"
	"net/url"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// ListGroupMembershipsCmd represents the list-group-memberships command
var ListGroupMembershipsCmd = &cobra.Command{
	Use:   "list-group-memberships [group_id]",
	Short: "List group memberships from Snyk",
	Long: `List group memberships from the Snyk API.

This command retrieves a list of memberships for a specific group.
The results can be paginated and filtered using various parameters.

Examples:
  snyk-api-cli list-group-memberships 12345678-1234-1234-1234-123456789012
  snyk-api-cli list-group-memberships 12345678-1234-1234-1234-123456789012 --limit 10
  snyk-api-cli list-group-memberships 12345678-1234-1234-1234-123456789012 --email user@example.com
  snyk-api-cli list-group-memberships 12345678-1234-1234-1234-123456789012 --role-name admin
  snyk-api-cli list-group-memberships 12345678-1234-1234-1234-123456789012 --sort-by username --sort-order ASC
  snyk-api-cli list-group-memberships 12345678-1234-1234-1234-123456789012 --verbose`,
	Args: cobra.ExactArgs(1),
	RunE: runListGroupMemberships,
}

var (
	listGroupMembershipsStartingAfter              string
	listGroupMembershipsEndingBefore               string
	listGroupMembershipsLimit                      int
	listGroupMembershipsSortBy                     string
	listGroupMembershipsSortOrder                  string
	listGroupMembershipsEmail                      string
	listGroupMembershipsUserID                     string
	listGroupMembershipsUsername                   string
	listGroupMembershipsRoleName                   string
	listGroupMembershipsIncludeGroupMembershipCount bool
	listGroupMembershipsVerbose                    bool
	listGroupMembershipsSilent                     bool
	listGroupMembershipsIncludeResp                bool
	listGroupMembershipsUserAgent                  string
)

func init() {
	// Add flags for query parameters
	ListGroupMembershipsCmd.Flags().StringVar(&listGroupMembershipsStartingAfter, "starting-after", "", "Cursor for pagination, returns results after this point")
	ListGroupMembershipsCmd.Flags().StringVar(&listGroupMembershipsEndingBefore, "ending-before", "", "Cursor for pagination, returns results before this point")
	ListGroupMembershipsCmd.Flags().IntVar(&listGroupMembershipsLimit, "limit", 0, "Number of results per page")
	ListGroupMembershipsCmd.Flags().StringVar(&listGroupMembershipsSortBy, "sort-by", "", "Column to sort results (options: username, user_display_name, email, login_method, role_name)")
	ListGroupMembershipsCmd.Flags().StringVar(&listGroupMembershipsSortOrder, "sort-order", "", "Sort direction (ASC or DESC)")
	ListGroupMembershipsCmd.Flags().StringVar(&listGroupMembershipsEmail, "email", "", "Filter by user email")
	ListGroupMembershipsCmd.Flags().StringVar(&listGroupMembershipsUserID, "user-id", "", "Filter by user ID")
	ListGroupMembershipsCmd.Flags().StringVar(&listGroupMembershipsUsername, "username", "", "Filter by username")
	ListGroupMembershipsCmd.Flags().StringVar(&listGroupMembershipsRoleName, "role-name", "", "Filter by specific role")
	ListGroupMembershipsCmd.Flags().BoolVar(&listGroupMembershipsIncludeGroupMembershipCount, "include-group-membership-count", false, "Include group membership count")

	// Add standard flags like curl command
	ListGroupMembershipsCmd.Flags().BoolVarP(&listGroupMembershipsVerbose, "verbose", "v", false, "Make the operation more talkative")
	ListGroupMembershipsCmd.Flags().BoolVarP(&listGroupMembershipsSilent, "silent", "s", false, "Silent mode")
	ListGroupMembershipsCmd.Flags().BoolVarP(&listGroupMembershipsIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	ListGroupMembershipsCmd.Flags().StringVarP(&listGroupMembershipsUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")
}

func runListGroupMemberships(cmd *cobra.Command, args []string) error {
	groupID := args[0]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Build the URL with query parameters
	fullURL, err := buildListGroupMembershipsURL(endpoint, groupID, version)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	return ExecuteAPIRequest(RequestOptions{
		Method:      "GET",
		URL:         fullURL,
		Verbose:     listGroupMembershipsVerbose,
		Silent:      listGroupMembershipsSilent,
		IncludeResp: listGroupMembershipsIncludeResp,
		UserAgent:   listGroupMembershipsUserAgent,
	})
}

func buildListGroupMembershipsURL(endpoint, groupID, version string) (string, error) {
	// Build base URL
	baseURL := fmt.Sprintf("https://%s/rest/groups/%s/memberships", endpoint, groupID)

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
	if listGroupMembershipsStartingAfter != "" {
		q.Set("starting_after", listGroupMembershipsStartingAfter)
	}
	if listGroupMembershipsEndingBefore != "" {
		q.Set("ending_before", listGroupMembershipsEndingBefore)
	}
	if listGroupMembershipsLimit > 0 {
		q.Set("limit", fmt.Sprintf("%d", listGroupMembershipsLimit))
	}
	if listGroupMembershipsSortBy != "" {
		q.Set("sort_by", listGroupMembershipsSortBy)
	}
	if listGroupMembershipsSortOrder != "" {
		q.Set("sort_order", listGroupMembershipsSortOrder)
	}
	if listGroupMembershipsEmail != "" {
		q.Set("email", listGroupMembershipsEmail)
	}
	if listGroupMembershipsUserID != "" {
		q.Set("user_id", listGroupMembershipsUserID)
	}
	if listGroupMembershipsUsername != "" {
		q.Set("username", listGroupMembershipsUsername)
	}
	if listGroupMembershipsRoleName != "" {
		q.Set("role_name", listGroupMembershipsRoleName)
	}
	if listGroupMembershipsIncludeGroupMembershipCount {
		q.Set("include_group_membership_count", "true")
	}

	u.RawQuery = q.Encode()
	return u.String(), nil
}
