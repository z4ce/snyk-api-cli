package cmd

import (
	"fmt"
	"net/url"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// ListGroupsCmd represents the list-groups command
var ListGroupsCmd = &cobra.Command{
	Use:   "list-groups",
	Short: "List groups from Snyk",
	Long: `List groups from the Snyk API.

This command retrieves a list of groups that the authenticated user is a member of.
The results can be paginated using cursor-based pagination.

Examples:
  snyk-api-cli list-groups
  snyk-api-cli list-groups --limit 10
  snyk-api-cli list-groups --starting-after abc123
  snyk-api-cli list-groups --ending-before xyz789
  snyk-api-cli list-groups --verbose`,
	RunE: runListGroups,
}

var (
	listGroupsStartingAfter string
	listGroupsEndingBefore  string
	listGroupsLimit         int
	listGroupsVerbose       bool
	listGroupsSilent        bool
	listGroupsIncludeResp   bool
	listGroupsUserAgent     string
)

func init() {
	// Add flags for query parameters
	ListGroupsCmd.Flags().StringVar(&listGroupsStartingAfter, "starting-after", "", "Cursor for pagination, returns results after this point")
	ListGroupsCmd.Flags().StringVar(&listGroupsEndingBefore, "ending-before", "", "Cursor for pagination, returns results before this point")
	ListGroupsCmd.Flags().IntVar(&listGroupsLimit, "limit", 0, "Number of results per page")

	// Add standard flags like curl command
	ListGroupsCmd.Flags().BoolVarP(&listGroupsVerbose, "verbose", "v", false, "Make the operation more talkative")
	ListGroupsCmd.Flags().BoolVarP(&listGroupsSilent, "silent", "s", false, "Silent mode")
	ListGroupsCmd.Flags().BoolVarP(&listGroupsIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	ListGroupsCmd.Flags().StringVarP(&listGroupsUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")
}

func runListGroups(cmd *cobra.Command, args []string) error {
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Build the URL with query parameters
	fullURL, err := buildListGroupsURL(endpoint, version)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	return ExecuteAPIRequest(RequestOptions{
		Method:      "GET",
		URL:         fullURL,
		Verbose:     listGroupsVerbose,
		Silent:      listGroupsSilent,
		IncludeResp: listGroupsIncludeResp,
		UserAgent:   listGroupsUserAgent,
	})
}

func buildListGroupsURL(endpoint, version string) (string, error) {
	// Build base URL
	baseURL := fmt.Sprintf("https://%s/rest/groups", endpoint)

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
	if listGroupsStartingAfter != "" {
		q.Set("starting_after", listGroupsStartingAfter)
	}
	if listGroupsEndingBefore != "" {
		q.Set("ending_before", listGroupsEndingBefore)
	}
	if listGroupsLimit > 0 {
		q.Set("limit", fmt.Sprintf("%d", listGroupsLimit))
	}

	u.RawQuery = q.Encode()
	return u.String(), nil
}
