package cmd

import (
	"fmt"
	"net/url"
	"strconv"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// ListGroupSsoConnectionsCmd represents the list-group-sso-connections command
var ListGroupSsoConnectionsCmd = &cobra.Command{
	Use:   "list-group-sso-connections [group_id]",
	Short: "List SSO connections for a group from Snyk",
	Long: `List SSO connections for a group from the Snyk API.

This command retrieves a list of SSO connections for a specific group by its ID.
The group ID must be provided as a required argument.

Examples:
  snyk-api-cli list-group-sso-connections 12345678-1234-1234-1234-123456789012
  snyk-api-cli list-group-sso-connections 12345678-1234-1234-1234-123456789012 --limit 10
  snyk-api-cli list-group-sso-connections 12345678-1234-1234-1234-123456789012 --starting-after "v1.eyJpZCI6IjEwMDAifQo="`,
	Args: cobra.ExactArgs(1),
	RunE: runListGroupSsoConnections,
}

var (
	listGroupSsoConnectionsStartingAfter string
	listGroupSsoConnectionsEndingBefore  string
	listGroupSsoConnectionsLimit         int
	listGroupSsoConnectionsVerbose       bool
	listGroupSsoConnectionsSilent        bool
	listGroupSsoConnectionsIncludeResp   bool
	listGroupSsoConnectionsUserAgent     string
)

func init() {
	// Add query parameter flags
	ListGroupSsoConnectionsCmd.Flags().StringVar(&listGroupSsoConnectionsStartingAfter, "starting-after", "", "Return the page of results immediately after this cursor")
	ListGroupSsoConnectionsCmd.Flags().StringVar(&listGroupSsoConnectionsEndingBefore, "ending-before", "", "Return the page of results immediately before this cursor")
	ListGroupSsoConnectionsCmd.Flags().IntVar(&listGroupSsoConnectionsLimit, "limit", 0, "Number of results to return per page")

	// Add standard flags like other commands
	ListGroupSsoConnectionsCmd.Flags().BoolVarP(&listGroupSsoConnectionsVerbose, "verbose", "v", false, "Make the operation more talkative")
	ListGroupSsoConnectionsCmd.Flags().BoolVarP(&listGroupSsoConnectionsSilent, "silent", "s", false, "Silent mode")
	ListGroupSsoConnectionsCmd.Flags().BoolVarP(&listGroupSsoConnectionsIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	ListGroupSsoConnectionsCmd.Flags().StringVarP(&listGroupSsoConnectionsUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")
}

func runListGroupSsoConnections(cmd *cobra.Command, args []string) error {
	groupID := args[0]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Build the URL
	fullURL, err := buildListGroupSsoConnectionsURL(endpoint, version, groupID)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	return ExecuteAPIRequest(RequestOptions{
		Method:      "GET",
		URL:         fullURL,
		Verbose:     listGroupSsoConnectionsVerbose,
		Silent:      listGroupSsoConnectionsSilent,
		IncludeResp: listGroupSsoConnectionsIncludeResp,
		UserAgent:   listGroupSsoConnectionsUserAgent,
	})
}

func buildListGroupSsoConnectionsURL(endpoint, version, groupID string) (string, error) {
	// Build base URL with group ID path parameter
	baseURL := fmt.Sprintf("https://%s/rest/groups/%s/sso_connections", endpoint, groupID)

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
	if listGroupSsoConnectionsStartingAfter != "" {
		q.Set("starting_after", listGroupSsoConnectionsStartingAfter)
	}
	if listGroupSsoConnectionsEndingBefore != "" {
		q.Set("ending_before", listGroupSsoConnectionsEndingBefore)
	}
	if listGroupSsoConnectionsLimit > 0 {
		q.Set("limit", strconv.Itoa(listGroupSsoConnectionsLimit))
	}

	u.RawQuery = q.Encode()
	return u.String(), nil
}
