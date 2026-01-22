package cmd

import (
	"fmt"
	"net/url"
	"strconv"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// ListGroupIssuesCmd represents the list-group-issues command
var ListGroupIssuesCmd = &cobra.Command{
	Use:   "list-group-issues [group_id]",
	Short: "List issues for a specific group",
	Long: `List issues for a specific group from the Snyk API.

This command retrieves a list of issues for the specified group.
The results can be filtered and paginated using various parameters.

Examples:
  snyk-api-cli list-group-issues 12345678-1234-1234-1234-123456789012
  snyk-api-cli list-group-issues 12345678-1234-1234-1234-123456789012 --limit 10
  snyk-api-cli list-group-issues 12345678-1234-1234-1234-123456789012 --updated-after 2024-01-01T00:00:00Z
  snyk-api-cli list-group-issues 12345678-1234-1234-1234-123456789012 --created-before 2024-12-31T23:59:59Z
  snyk-api-cli list-group-issues 12345678-1234-1234-1234-123456789012 --type vulnerability --status open
  snyk-api-cli list-group-issues 12345678-1234-1234-1234-123456789012 --verbose`,
	Args: cobra.ExactArgs(1),
	RunE: runListGroupIssues,
}

var (
	listGroupIssuesStartingAfter          string
	listGroupIssuesEndingBefore           string
	listGroupIssuesLimit                  int
	listGroupIssuesScanItemID             string
	listGroupIssuesScanItemType           string
	listGroupIssuesType                   string
	listGroupIssuesUpdatedBefore          string
	listGroupIssuesUpdatedAfter           string
	listGroupIssuesCreatedBefore          string
	listGroupIssuesCreatedAfter           string
	listGroupIssuesEffectiveSeverityLevel []string
	listGroupIssuesStatus                 []string
	listGroupIssuesIgnored                bool
	listGroupIssuesVerbose                bool
	listGroupIssuesSilent                 bool
	listGroupIssuesIncludeResp            bool
	listGroupIssuesUserAgent              string
)

func init() {
	// Add flags for query parameters
	ListGroupIssuesCmd.Flags().StringVar(&listGroupIssuesStartingAfter, "starting-after", "", "Cursor for pagination, returns results after this point")
	ListGroupIssuesCmd.Flags().StringVar(&listGroupIssuesEndingBefore, "ending-before", "", "Cursor for pagination, returns results before this point")
	ListGroupIssuesCmd.Flags().IntVar(&listGroupIssuesLimit, "limit", 0, "Number of results per page")
	ListGroupIssuesCmd.Flags().StringVar(&listGroupIssuesScanItemID, "scan-item-id", "", "Filter by scan item ID (UUID)")
	ListGroupIssuesCmd.Flags().StringVar(&listGroupIssuesScanItemType, "scan-item-type", "", "Filter by scan item type (project or environment)")
	ListGroupIssuesCmd.Flags().StringVar(&listGroupIssuesType, "type", "", "Filter by issue type (e.g., vulnerability, license)")
	ListGroupIssuesCmd.Flags().StringVar(&listGroupIssuesUpdatedBefore, "updated-before", "", "Filter issues updated before this date-time (ISO 8601 format)")
	ListGroupIssuesCmd.Flags().StringVar(&listGroupIssuesUpdatedAfter, "updated-after", "", "Filter issues updated after this date-time (ISO 8601 format)")
	ListGroupIssuesCmd.Flags().StringVar(&listGroupIssuesCreatedBefore, "created-before", "", "Filter issues created before this date-time (ISO 8601 format)")
	ListGroupIssuesCmd.Flags().StringVar(&listGroupIssuesCreatedAfter, "created-after", "", "Filter issues created after this date-time (ISO 8601 format)")
	ListGroupIssuesCmd.Flags().StringSliceVar(&listGroupIssuesEffectiveSeverityLevel, "effective-severity-level", []string{}, "Filter by effective severity level (can be used multiple times)")
	ListGroupIssuesCmd.Flags().StringSliceVar(&listGroupIssuesStatus, "status", []string{}, "Filter by issue status (open, resolved) (can be used multiple times)")
	ListGroupIssuesCmd.Flags().BoolVar(&listGroupIssuesIgnored, "ignored", false, "Filter ignored issues")

	// Add standard flags like curl command
	ListGroupIssuesCmd.Flags().BoolVarP(&listGroupIssuesVerbose, "verbose", "v", false, "Make the operation more talkative")
	ListGroupIssuesCmd.Flags().BoolVarP(&listGroupIssuesSilent, "silent", "s", false, "Silent mode")
	ListGroupIssuesCmd.Flags().BoolVarP(&listGroupIssuesIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	ListGroupIssuesCmd.Flags().StringVarP(&listGroupIssuesUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")
}

func runListGroupIssues(cmd *cobra.Command, args []string) error {
	groupID := args[0]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Build the URL with query parameters
	fullURL, err := buildListGroupIssuesURL(endpoint, version, groupID, cmd)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	return ExecuteAPIRequest(RequestOptions{
		Method:      "GET",
		URL:         fullURL,
		Verbose:     listGroupIssuesVerbose,
		Silent:      listGroupIssuesSilent,
		IncludeResp: listGroupIssuesIncludeResp,
		UserAgent:   listGroupIssuesUserAgent,
	})
}

func buildListGroupIssuesURL(endpoint, version, groupID string, cmd *cobra.Command) (string, error) {
	// Build base URL
	baseURL := fmt.Sprintf("https://%s/rest/groups/%s/issues", endpoint, groupID)

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
	if listGroupIssuesStartingAfter != "" {
		q.Set("starting_after", listGroupIssuesStartingAfter)
	}
	if listGroupIssuesEndingBefore != "" {
		q.Set("ending_before", listGroupIssuesEndingBefore)
	}
	if listGroupIssuesLimit > 0 {
		q.Set("limit", strconv.Itoa(listGroupIssuesLimit))
	}
	if listGroupIssuesScanItemID != "" {
		q.Set("scan_item.id", listGroupIssuesScanItemID)
	}
	if listGroupIssuesScanItemType != "" {
		q.Set("scan_item.type", listGroupIssuesScanItemType)
	}
	if listGroupIssuesType != "" {
		q.Set("type", listGroupIssuesType)
	}
	if listGroupIssuesUpdatedBefore != "" {
		q.Set("updated_before", listGroupIssuesUpdatedBefore)
	}
	if listGroupIssuesUpdatedAfter != "" {
		q.Set("updated_after", listGroupIssuesUpdatedAfter)
	}
	if listGroupIssuesCreatedBefore != "" {
		q.Set("created_before", listGroupIssuesCreatedBefore)
	}
	if listGroupIssuesCreatedAfter != "" {
		q.Set("created_after", listGroupIssuesCreatedAfter)
	}

	// Handle array parameters
	for _, level := range listGroupIssuesEffectiveSeverityLevel {
		q.Add("effective_severity_level", level)
	}
	for _, status := range listGroupIssuesStatus {
		q.Add("status", status)
	}

	// Handle ignored parameter - only add if explicitly set
	if cmd.Flag("ignored").Changed {
		q.Set("ignored", strconv.FormatBool(listGroupIssuesIgnored))
	}

	u.RawQuery = q.Encode()
	return u.String(), nil
}
