package cmd

import (
	"fmt"
	"net/url"
	"strconv"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// ListGroupAuditLogsCmd represents the list-group-audit-logs command
var ListGroupAuditLogsCmd = &cobra.Command{
	Use:   "list-group-audit-logs [group_id]",
	Short: "List audit logs for a specific group from Snyk",
	Long: `List audit logs for a specific group from the Snyk API.

This command retrieves audit logs for a specific group by its ID. The group ID must be provided as a required argument.
You can filter the results by date range, user, project, events, and other criteria.

Examples:
  snyk-api-cli list-group-audit-logs 12345678-1234-1234-1234-123456789012
  snyk-api-cli list-group-audit-logs 12345678-1234-1234-1234-123456789012 --from 2024-01-01T00:00:00Z --to 2024-01-31T23:59:59Z
  snyk-api-cli list-group-audit-logs 12345678-1234-1234-1234-123456789012 --user-id user-123 --size 50
  snyk-api-cli list-group-audit-logs 12345678-1234-1234-1234-123456789012 --events "user.created,user.updated" --sort-order DESC`,
	Args: cobra.ExactArgs(1),
	RunE: runListGroupAuditLogs,
}

var (
	listGroupAuditLogsCursor        string
	listGroupAuditLogsFrom          string
	listGroupAuditLogsTo            string
	listGroupAuditLogsSize          int
	listGroupAuditLogsSortOrder     string
	listGroupAuditLogsUserID        string
	listGroupAuditLogsProjectID     string
	listGroupAuditLogsEvents        string
	listGroupAuditLogsExcludeEvents string
	listGroupAuditLogsVerbose       bool
	listGroupAuditLogsSilent        bool
	listGroupAuditLogsIncludeResp   bool
	listGroupAuditLogsUserAgent     string
)

func init() {
	// Add flags for query parameters
	ListGroupAuditLogsCmd.Flags().StringVar(&listGroupAuditLogsCursor, "cursor", "", "Next page ID for pagination")
	ListGroupAuditLogsCmd.Flags().StringVar(&listGroupAuditLogsFrom, "from", "", "Start date in RFC3339 format (e.g., 2024-01-01T00:00:00Z)")
	ListGroupAuditLogsCmd.Flags().StringVar(&listGroupAuditLogsTo, "to", "", "End date in RFC3339 format (e.g., 2024-01-31T23:59:59Z)")
	ListGroupAuditLogsCmd.Flags().IntVar(&listGroupAuditLogsSize, "size", 0, "Number of results per page")
	ListGroupAuditLogsCmd.Flags().StringVar(&listGroupAuditLogsSortOrder, "sort-order", "", "Result order (ASC or DESC)")
	ListGroupAuditLogsCmd.Flags().StringVar(&listGroupAuditLogsUserID, "user-id", "", "Filter by user ID")
	ListGroupAuditLogsCmd.Flags().StringVar(&listGroupAuditLogsProjectID, "project-id", "", "Filter by project ID")
	ListGroupAuditLogsCmd.Flags().StringVar(&listGroupAuditLogsEvents, "events", "", "Filter by event types (comma-separated)")
	ListGroupAuditLogsCmd.Flags().StringVar(&listGroupAuditLogsExcludeEvents, "exclude-events", "", "Exclude specific event types (comma-separated)")

	// Add standard flags like other commands
	ListGroupAuditLogsCmd.Flags().BoolVarP(&listGroupAuditLogsVerbose, "verbose", "v", false, "Make the operation more talkative")
	ListGroupAuditLogsCmd.Flags().BoolVarP(&listGroupAuditLogsSilent, "silent", "s", false, "Silent mode")
	ListGroupAuditLogsCmd.Flags().BoolVarP(&listGroupAuditLogsIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	ListGroupAuditLogsCmd.Flags().StringVarP(&listGroupAuditLogsUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")
}

func runListGroupAuditLogs(cmd *cobra.Command, args []string) error {
	groupID := args[0]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Build the URL
	fullURL, err := buildListGroupAuditLogsURL(endpoint, version, groupID)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	return ExecuteAPIRequest(RequestOptions{
		Method:      "GET",
		URL:         fullURL,
		Verbose:     listGroupAuditLogsVerbose,
		Silent:      listGroupAuditLogsSilent,
		IncludeResp: listGroupAuditLogsIncludeResp,
		UserAgent:   listGroupAuditLogsUserAgent,
	})
}

func buildListGroupAuditLogsURL(endpoint, version, groupID string) (string, error) {
	// Build base URL with group ID path parameter
	baseURL := fmt.Sprintf("https://%s/rest/groups/%s/audit_logs/search", endpoint, groupID)

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
	if listGroupAuditLogsCursor != "" {
		q.Set("cursor", listGroupAuditLogsCursor)
	}
	if listGroupAuditLogsFrom != "" {
		q.Set("from", listGroupAuditLogsFrom)
	}
	if listGroupAuditLogsTo != "" {
		q.Set("to", listGroupAuditLogsTo)
	}
	if listGroupAuditLogsSize > 0 {
		q.Set("size", strconv.Itoa(listGroupAuditLogsSize))
	}
	if listGroupAuditLogsSortOrder != "" {
		q.Set("sort_order", listGroupAuditLogsSortOrder)
	}
	if listGroupAuditLogsUserID != "" {
		q.Set("user_id", listGroupAuditLogsUserID)
	}
	if listGroupAuditLogsProjectID != "" {
		q.Set("project_id", listGroupAuditLogsProjectID)
	}
	if listGroupAuditLogsEvents != "" {
		q.Set("events", listGroupAuditLogsEvents)
	}
	if listGroupAuditLogsExcludeEvents != "" {
		q.Set("exclude_events", listGroupAuditLogsExcludeEvents)
	}

	u.RawQuery = q.Encode()
	return u.String(), nil
}
