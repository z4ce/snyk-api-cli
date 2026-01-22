package cmd

import (
	"fmt"
	"net/url"
	"strconv"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// ListGroupSsoConnectionUsersCmd represents the list-group-sso-connection-users command
var ListGroupSsoConnectionUsersCmd = &cobra.Command{
	Use:   "list-group-sso-connection-users [group_id] [sso_id]",
	Short: "List users for a specific SSO connection within a group from Snyk",
	Long: `List users for a specific SSO connection within a group from the Snyk API.

This command retrieves a list of users for a specific SSO connection within a group.
Both the group ID and SSO ID must be provided as required arguments.

Examples:
  snyk-api-cli list-group-sso-connection-users 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321
  snyk-api-cli list-group-sso-connection-users 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321 --limit 10
  snyk-api-cli list-group-sso-connection-users 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321 --starting-after "v1.eyJpZCI6IjEwMDAifQo="`,
	Args: cobra.ExactArgs(2),
	RunE: runListGroupSsoConnectionUsers,
}

var (
	listGroupSsoConnectionUsersStartingAfter string
	listGroupSsoConnectionUsersEndingBefore  string
	listGroupSsoConnectionUsersLimit         int
	listGroupSsoConnectionUsersVerbose       bool
	listGroupSsoConnectionUsersSilent        bool
	listGroupSsoConnectionUsersIncludeResp   bool
	listGroupSsoConnectionUsersUserAgent     string
)

func init() {
	// Add query parameter flags
	ListGroupSsoConnectionUsersCmd.Flags().StringVar(&listGroupSsoConnectionUsersStartingAfter, "starting-after", "", "Return the page of results immediately after this cursor")
	ListGroupSsoConnectionUsersCmd.Flags().StringVar(&listGroupSsoConnectionUsersEndingBefore, "ending-before", "", "Return the page of results immediately before this cursor")
	ListGroupSsoConnectionUsersCmd.Flags().IntVar(&listGroupSsoConnectionUsersLimit, "limit", 0, "Number of results to return per page")

	// Add standard flags like other commands
	ListGroupSsoConnectionUsersCmd.Flags().BoolVarP(&listGroupSsoConnectionUsersVerbose, "verbose", "v", false, "Make the operation more talkative")
	ListGroupSsoConnectionUsersCmd.Flags().BoolVarP(&listGroupSsoConnectionUsersSilent, "silent", "s", false, "Silent mode")
	ListGroupSsoConnectionUsersCmd.Flags().BoolVarP(&listGroupSsoConnectionUsersIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	ListGroupSsoConnectionUsersCmd.Flags().StringVarP(&listGroupSsoConnectionUsersUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")
}

func runListGroupSsoConnectionUsers(cmd *cobra.Command, args []string) error {
	groupID := args[0]
	ssoID := args[1]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Build the URL
	fullURL, err := buildListGroupSsoConnectionUsersURL(endpoint, version, groupID, ssoID)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	return ExecuteAPIRequest(RequestOptions{
		Method:      "GET",
		URL:         fullURL,
		Verbose:     listGroupSsoConnectionUsersVerbose,
		Silent:      listGroupSsoConnectionUsersSilent,
		IncludeResp: listGroupSsoConnectionUsersIncludeResp,
		UserAgent:   listGroupSsoConnectionUsersUserAgent,
	})
}

func buildListGroupSsoConnectionUsersURL(endpoint, version, groupID, ssoID string) (string, error) {
	// Build base URL with group ID and SSO ID path parameters
	baseURL := fmt.Sprintf("https://%s/rest/groups/%s/sso_connections/%s/users", endpoint, groupID, ssoID)

	// Parse URL to handle query parameters properly
	u, err := url.Parse(baseURL)
	if err != nil {
		return "", err
	}

	// Add query parameters
	q := u.Query()

	// Version is required
	q.Set("version", version)

	// Add optional query parameters if provided
	if listGroupSsoConnectionUsersStartingAfter != "" {
		q.Set("starting_after", listGroupSsoConnectionUsersStartingAfter)
	}
	if listGroupSsoConnectionUsersEndingBefore != "" {
		q.Set("ending_before", listGroupSsoConnectionUsersEndingBefore)
	}
	if listGroupSsoConnectionUsersLimit > 0 {
		q.Set("limit", strconv.Itoa(listGroupSsoConnectionUsersLimit))
	}

	u.RawQuery = q.Encode()
	return u.String(), nil
}
