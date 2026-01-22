package cmd

import (
	"fmt"
	"net/url"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// ListOrgMembershipsCmd represents the list-org-memberships command
var ListOrgMembershipsCmd = &cobra.Command{
	Use:   "list-org-memberships [org_id]",
	Short: "List all memberships of an organization from Snyk",
	Long: `List all memberships of an organization from the Snyk API.

This command retrieves a list of memberships for a specific organization that the 
authenticated user can access. The results can be filtered, sorted, and paginated using 
various query parameters.

Examples:
  snyk-api-cli list-org-memberships 12345678-1234-1234-1234-123456789012
  snyk-api-cli list-org-memberships 12345678-1234-1234-1234-123456789012 --email user@example.com
  snyk-api-cli list-org-memberships 12345678-1234-1234-1234-123456789012 --role-name admin
  snyk-api-cli list-org-memberships 12345678-1234-1234-1234-123456789012 --limit 10
  snyk-api-cli list-org-memberships 12345678-1234-1234-1234-123456789012 --sort-by username --sort-order ASC
  snyk-api-cli list-org-memberships 12345678-1234-1234-1234-123456789012 --starting-after abc123
  snyk-api-cli list-org-memberships 12345678-1234-1234-1234-123456789012 --verbose`,
	Args: cobra.ExactArgs(1),
	RunE: runListOrgMemberships,
}

var (
	listOrgMembershipsEmail         string
	listOrgMembershipsUserID        string
	listOrgMembershipsUsername      string
	listOrgMembershipsRoleName      string
	listOrgMembershipsLimit         int
	listOrgMembershipsStartingAfter string
	listOrgMembershipsEndingBefore  string
	listOrgMembershipsSortBy        string
	listOrgMembershipsSortOrder     string
	listOrgMembershipsVerbose       bool
	listOrgMembershipsSilent        bool
	listOrgMembershipsIncludeResp   bool
	listOrgMembershipsUserAgent     string
)

func init() {
	// Add flags for query parameters
	ListOrgMembershipsCmd.Flags().StringVar(&listOrgMembershipsEmail, "email", "", "Filter by user email")
	ListOrgMembershipsCmd.Flags().StringVar(&listOrgMembershipsUserID, "user-id", "", "Filter by user ID")
	ListOrgMembershipsCmd.Flags().StringVar(&listOrgMembershipsUsername, "username", "", "Filter by username")
	ListOrgMembershipsCmd.Flags().StringVar(&listOrgMembershipsRoleName, "role-name", "", "Filter by role name")
	ListOrgMembershipsCmd.Flags().IntVar(&listOrgMembershipsLimit, "limit", 0, "Number of results per page")
	ListOrgMembershipsCmd.Flags().StringVar(&listOrgMembershipsStartingAfter, "starting-after", "", "Cursor for pagination, returns results after this point")
	ListOrgMembershipsCmd.Flags().StringVar(&listOrgMembershipsEndingBefore, "ending-before", "", "Cursor for pagination, returns results before this point")
	ListOrgMembershipsCmd.Flags().StringVar(&listOrgMembershipsSortBy, "sort-by", "", "Column to sort by (username, user_display_name, email, etc.)")
	ListOrgMembershipsCmd.Flags().StringVar(&listOrgMembershipsSortOrder, "sort-order", "", "Sort direction (ASC or DESC)")

	// Add standard flags like other commands
	ListOrgMembershipsCmd.Flags().BoolVarP(&listOrgMembershipsVerbose, "verbose", "v", false, "Make the operation more talkative")
	ListOrgMembershipsCmd.Flags().BoolVarP(&listOrgMembershipsSilent, "silent", "s", false, "Silent mode")
	ListOrgMembershipsCmd.Flags().BoolVarP(&listOrgMembershipsIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	ListOrgMembershipsCmd.Flags().StringVarP(&listOrgMembershipsUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")
}

func runListOrgMemberships(cmd *cobra.Command, args []string) error {
	orgID := args[0]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Build the URL with query parameters
	fullURL, err := buildListOrgMembershipsURL(endpoint, version, orgID, cmd)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	return ExecuteAPIRequest(RequestOptions{
		Method:      "GET",
		URL:         fullURL,
		Verbose:     listOrgMembershipsVerbose,
		Silent:      listOrgMembershipsSilent,
		IncludeResp: listOrgMembershipsIncludeResp,
		UserAgent:   listOrgMembershipsUserAgent,
	})
}

func buildListOrgMembershipsURL(endpoint, version, orgID string, cmd *cobra.Command) (string, error) {
	// Build base URL
	baseURL := fmt.Sprintf("https://%s/rest/orgs/%s/memberships", endpoint, orgID)

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
	if listOrgMembershipsEmail != "" {
		q.Set("email", listOrgMembershipsEmail)
	}
	if listOrgMembershipsUserID != "" {
		q.Set("user_id", listOrgMembershipsUserID)
	}
	if listOrgMembershipsUsername != "" {
		q.Set("username", listOrgMembershipsUsername)
	}
	if listOrgMembershipsRoleName != "" {
		q.Set("role_name", listOrgMembershipsRoleName)
	}
	if listOrgMembershipsLimit > 0 {
		q.Set("limit", fmt.Sprintf("%d", listOrgMembershipsLimit))
	}
	if listOrgMembershipsStartingAfter != "" {
		q.Set("starting_after", listOrgMembershipsStartingAfter)
	}
	if listOrgMembershipsEndingBefore != "" {
		q.Set("ending_before", listOrgMembershipsEndingBefore)
	}
	if listOrgMembershipsSortBy != "" {
		q.Set("sort_by", listOrgMembershipsSortBy)
	}
	if listOrgMembershipsSortOrder != "" {
		q.Set("sort_order", listOrgMembershipsSortOrder)
	}

	u.RawQuery = q.Encode()
	return u.String(), nil
}
