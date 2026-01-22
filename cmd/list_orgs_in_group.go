package cmd

import (
	"fmt"
	"net/url"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// ListOrgsInGroupCmd represents the list-orgs-in-group command
var ListOrgsInGroupCmd = &cobra.Command{
	Use:   "list-orgs-in-group [group_id]",
	Short: "List organizations in a group",
	Long: `List organizations in a group from the Snyk API.

This command retrieves a list of organizations that belong to a specific group.
The group_id parameter is required and must be a valid UUID.

Examples:
  snyk-api-cli list-orgs-in-group 12345678-1234-1234-1234-123456789012
  snyk-api-cli list-orgs-in-group 12345678-1234-1234-1234-123456789012 --limit 10
  snyk-api-cli list-orgs-in-group 12345678-1234-1234-1234-123456789012 --starting-after abc123
  snyk-api-cli list-orgs-in-group 12345678-1234-1234-1234-123456789012 --name "my org"
  snyk-api-cli list-orgs-in-group 12345678-1234-1234-1234-123456789012 --slug "my-org-slug"
  snyk-api-cli list-orgs-in-group 12345678-1234-1234-1234-123456789012 --verbose`,
	Args: cobra.ExactArgs(1),
	RunE: runListOrgsInGroup,
}

var (
	listOrgsInGroupStartingAfter string
	listOrgsInGroupEndingBefore  string
	listOrgsInGroupLimit         int
	listOrgsInGroupName          string
	listOrgsInGroupSlug          string
	listOrgsInGroupVerbose       bool
	listOrgsInGroupSilent        bool
	listOrgsInGroupIncludeResp   bool
	listOrgsInGroupUserAgent     string
)

func init() {
	// Add flags for query parameters
	ListOrgsInGroupCmd.Flags().StringVar(&listOrgsInGroupStartingAfter, "starting-after", "", "Return the page of results immediately after this cursor")
	ListOrgsInGroupCmd.Flags().StringVar(&listOrgsInGroupEndingBefore, "ending-before", "", "Return the page of results immediately before this cursor")
	ListOrgsInGroupCmd.Flags().IntVar(&listOrgsInGroupLimit, "limit", 0, "Number of results to return per page")
	ListOrgsInGroupCmd.Flags().StringVar(&listOrgsInGroupName, "name", "", "Only return organizations whose name contains this value. Case insensitive.")
	ListOrgsInGroupCmd.Flags().StringVar(&listOrgsInGroupSlug, "slug", "", "Only return organizations whose slug exactly matches this value. Case sensitive.")

	// Add standard flags like curl command
	ListOrgsInGroupCmd.Flags().BoolVarP(&listOrgsInGroupVerbose, "verbose", "v", false, "Make the operation more talkative")
	ListOrgsInGroupCmd.Flags().BoolVarP(&listOrgsInGroupSilent, "silent", "s", false, "Silent mode")
	ListOrgsInGroupCmd.Flags().BoolVarP(&listOrgsInGroupIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	ListOrgsInGroupCmd.Flags().StringVarP(&listOrgsInGroupUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")
}

func runListOrgsInGroup(cmd *cobra.Command, args []string) error {
	groupID := args[0]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Build the URL with query parameters
	fullURL, err := buildListOrgsInGroupURL(endpoint, version, groupID)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	return ExecuteAPIRequest(RequestOptions{
		Method:      "GET",
		URL:         fullURL,
		Verbose:     listOrgsInGroupVerbose,
		Silent:      listOrgsInGroupSilent,
		IncludeResp: listOrgsInGroupIncludeResp,
		UserAgent:   listOrgsInGroupUserAgent,
	})
}

func buildListOrgsInGroupURL(endpoint, version, groupID string) (string, error) {
	// Build base URL
	baseURL := fmt.Sprintf("https://%s/rest/groups/%s/orgs", endpoint, groupID)

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
	if listOrgsInGroupStartingAfter != "" {
		q.Set("starting_after", listOrgsInGroupStartingAfter)
	}
	if listOrgsInGroupEndingBefore != "" {
		q.Set("ending_before", listOrgsInGroupEndingBefore)
	}
	if listOrgsInGroupLimit > 0 {
		q.Set("limit", fmt.Sprintf("%d", listOrgsInGroupLimit))
	}
	if listOrgsInGroupName != "" {
		q.Set("name", listOrgsInGroupName)
	}
	if listOrgsInGroupSlug != "" {
		q.Set("slug", listOrgsInGroupSlug)
	}

	u.RawQuery = q.Encode()
	return u.String(), nil
}
