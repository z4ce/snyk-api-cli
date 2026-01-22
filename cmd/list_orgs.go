package cmd

import (
	"fmt"
	"net/url"
	"strconv"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// ListOrgsCmd represents the list-orgs command
var ListOrgsCmd = &cobra.Command{
	Use:   "list-orgs",
	Short: "List organizations from Snyk",
	Long: `List organizations from the Snyk API.

This command retrieves a list of organizations that the authenticated user can access.
The results can be filtered and paginated using various query parameters.

Examples:
  snyk-api-cli list-orgs
  snyk-api-cli list-orgs --limit 10
  snyk-api-cli list-orgs --group-id 12345678-1234-1234-1234-123456789012
  snyk-api-cli list-orgs --is-personal true
  snyk-api-cli list-orgs --slug my-org
  snyk-api-cli list-orgs --name "My Organization"
  snyk-api-cli list-orgs --expand member_role
  snyk-api-cli list-orgs --starting-after abc123
  snyk-api-cli list-orgs --ending-before xyz789
  snyk-api-cli list-orgs --verbose`,
	RunE: runListOrgs,
}

var (
	listOrgsGroupID       string
	listOrgsIsPersonal    bool
	listOrgsSlug          string
	listOrgsName          string
	listOrgsExpand        []string
	listOrgsStartingAfter string
	listOrgsEndingBefore  string
	listOrgsLimit         int
	listOrgsVerbose       bool
	listOrgsSilent        bool
	listOrgsIncludeResp   bool
	listOrgsUserAgent     string
)

func init() {
	// Add flags for query parameters
	ListOrgsCmd.Flags().StringVar(&listOrgsGroupID, "group-id", "", "Filter organizations within a specific group (UUID)")
	ListOrgsCmd.Flags().BoolVar(&listOrgsIsPersonal, "is-personal", false, "If true, returns only independent organizations")
	ListOrgsCmd.Flags().StringVar(&listOrgsSlug, "slug", "", "Returns orgs with exact matching slug")
	ListOrgsCmd.Flags().StringVar(&listOrgsName, "name", "", "Returns orgs whose name contains this value")
	ListOrgsCmd.Flags().StringSliceVar(&listOrgsExpand, "expand", []string{}, "Expand related resources like member_role (can be used multiple times)")
	ListOrgsCmd.Flags().StringVar(&listOrgsStartingAfter, "starting-after", "", "Cursor for pagination, returns results after this point")
	ListOrgsCmd.Flags().StringVar(&listOrgsEndingBefore, "ending-before", "", "Cursor for pagination, returns results before this point")
	ListOrgsCmd.Flags().IntVar(&listOrgsLimit, "limit", 0, "Number of results per page")

	// Add standard flags like other commands
	ListOrgsCmd.Flags().BoolVarP(&listOrgsVerbose, "verbose", "v", false, "Make the operation more talkative")
	ListOrgsCmd.Flags().BoolVarP(&listOrgsSilent, "silent", "s", false, "Silent mode")
	ListOrgsCmd.Flags().BoolVarP(&listOrgsIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	ListOrgsCmd.Flags().StringVarP(&listOrgsUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")
}

func runListOrgs(cmd *cobra.Command, args []string) error {
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Build the URL with query parameters
	fullURL, err := buildListOrgsURL(endpoint, version, cmd)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	return ExecuteAPIRequest(RequestOptions{
		Method:      "GET",
		URL:         fullURL,
		Verbose:     listOrgsVerbose,
		Silent:      listOrgsSilent,
		IncludeResp: listOrgsIncludeResp,
		UserAgent:   listOrgsUserAgent,
	})
}

func buildListOrgsURL(endpoint, version string, cmd *cobra.Command) (string, error) {
	// Build base URL
	baseURL := fmt.Sprintf("https://%s/rest/orgs", endpoint)

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
	if listOrgsGroupID != "" {
		q.Set("group_id", listOrgsGroupID)
	}
	if cmd.Flags().Changed("is-personal") {
		q.Set("is_personal", strconv.FormatBool(listOrgsIsPersonal))
	}
	if listOrgsSlug != "" {
		q.Set("slug", listOrgsSlug)
	}
	if listOrgsName != "" {
		q.Set("name", listOrgsName)
	}
	if len(listOrgsExpand) > 0 {
		// Handle expand as an array parameter
		for _, expand := range listOrgsExpand {
			q.Add("expand", expand)
		}
	}
	if listOrgsStartingAfter != "" {
		q.Set("starting_after", listOrgsStartingAfter)
	}
	if listOrgsEndingBefore != "" {
		q.Set("ending_before", listOrgsEndingBefore)
	}
	if listOrgsLimit > 0 {
		q.Set("limit", fmt.Sprintf("%d", listOrgsLimit))
	}

	u.RawQuery = q.Encode()
	return u.String(), nil
}
