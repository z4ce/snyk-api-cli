package cmd

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// ListOrgAuditLogsCmd represents the list-org-audit-logs command
var ListOrgAuditLogsCmd = &cobra.Command{
	Use:   "list-org-audit-logs [org_id]",
	Short: "List audit logs for a specific organization from Snyk",
	Long: `List audit logs for a specific organization from the Snyk API.

This command retrieves audit logs for a specific organization by its ID. The organization ID must be provided as a required argument.
You can filter the results by date range, user, project, events, and other criteria.

Examples:
  snyk-api-cli list-org-audit-logs 12345678-1234-1234-1234-123456789012
  snyk-api-cli list-org-audit-logs 12345678-1234-1234-1234-123456789012 --from 2024-01-01T00:00:00Z --to 2024-01-31T23:59:59Z
  snyk-api-cli list-org-audit-logs 12345678-1234-1234-1234-123456789012 --user-id user-123 --size 50
  snyk-api-cli list-org-audit-logs 12345678-1234-1234-1234-123456789012 --events "user.created,user.updated" --sort-order DESC`,
	Args: cobra.ExactArgs(1),
	RunE: runListOrgAuditLogs,
}

var (
	listOrgAuditLogsCursor        string
	listOrgAuditLogsFrom          string
	listOrgAuditLogsTo            string
	listOrgAuditLogsSize          int
	listOrgAuditLogsSortOrder     string
	listOrgAuditLogsUserID        string
	listOrgAuditLogsProjectID     string
	listOrgAuditLogsEvents        string
	listOrgAuditLogsExcludeEvents string
	listOrgAuditLogsVerbose       bool
	listOrgAuditLogsSilent        bool
	listOrgAuditLogsIncludeResp   bool
	listOrgAuditLogsUserAgent     string
)

func init() {
	// Add flags for query parameters
	ListOrgAuditLogsCmd.Flags().StringVar(&listOrgAuditLogsCursor, "cursor", "", "Next page ID for pagination")
	ListOrgAuditLogsCmd.Flags().StringVar(&listOrgAuditLogsFrom, "from", "", "Start date in RFC3339 format (e.g., 2024-01-01T00:00:00Z)")
	ListOrgAuditLogsCmd.Flags().StringVar(&listOrgAuditLogsTo, "to", "", "End date in RFC3339 format (e.g., 2024-01-31T23:59:59Z)")
	ListOrgAuditLogsCmd.Flags().IntVar(&listOrgAuditLogsSize, "size", 0, "Number of results per page")
	ListOrgAuditLogsCmd.Flags().StringVar(&listOrgAuditLogsSortOrder, "sort-order", "", "Result order (ASC or DESC)")
	ListOrgAuditLogsCmd.Flags().StringVar(&listOrgAuditLogsUserID, "user-id", "", "Filter by user ID")
	ListOrgAuditLogsCmd.Flags().StringVar(&listOrgAuditLogsProjectID, "project-id", "", "Filter by project ID")
	ListOrgAuditLogsCmd.Flags().StringVar(&listOrgAuditLogsEvents, "events", "", "Filter by event types (comma-separated)")
	ListOrgAuditLogsCmd.Flags().StringVar(&listOrgAuditLogsExcludeEvents, "exclude-events", "", "Exclude specific event types (comma-separated)")

	// Add standard flags like other commands
	ListOrgAuditLogsCmd.Flags().BoolVarP(&listOrgAuditLogsVerbose, "verbose", "v", false, "Make the operation more talkative")
	ListOrgAuditLogsCmd.Flags().BoolVarP(&listOrgAuditLogsSilent, "silent", "s", false, "Silent mode")
	ListOrgAuditLogsCmd.Flags().BoolVarP(&listOrgAuditLogsIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	ListOrgAuditLogsCmd.Flags().StringVarP(&listOrgAuditLogsUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")
}

func runListOrgAuditLogs(cmd *cobra.Command, args []string) error {
	orgID := args[0]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Build the URL
	fullURL, err := buildListOrgAuditLogsURL(endpoint, version, orgID)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	if listOrgAuditLogsVerbose {
		fmt.Fprintf(os.Stderr, "* Requesting GET %s\n", fullURL)
	}

	// Create the HTTP request
	req, err := http.NewRequest("GET", fullURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Handle authentication with same precedence as curl: Authorization header > SNYK_TOKEN > OAuth
	if listOrgAuditLogsVerbose {
		fmt.Fprintf(os.Stderr, "* Checking authentication options\n")
	}

	authHeader, err := buildAuthHeader([]string{}) // No manual headers for this command
	if err != nil {
		if listOrgAuditLogsVerbose {
			fmt.Fprintf(os.Stderr, "* Warning: failed to get automatic auth: %v\n", err)
		}
		// Don't fail the request, just proceed without automatic auth
	} else if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
		if listOrgAuditLogsVerbose {
			fmt.Fprintf(os.Stderr, "* Added automatic authorization header\n")
		}
	} else if listOrgAuditLogsVerbose {
		fmt.Fprintf(os.Stderr, "* No automatic authorization available\n")
	}

	// Set user agent
	req.Header.Set("User-Agent", listOrgAuditLogsUserAgent)

	// Make the request
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	if listOrgAuditLogsVerbose {
		fmt.Fprintf(os.Stderr, "* Making request...\n")
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// Handle response using the same pattern as other commands
	return handleListOrgAuditLogsResponse(resp, listOrgAuditLogsIncludeResp, listOrgAuditLogsVerbose, listOrgAuditLogsSilent)
}

func buildListOrgAuditLogsURL(endpoint, version, orgID string) (string, error) {
	// Build base URL with org ID path parameter
	baseURL := fmt.Sprintf("https://%s/rest/orgs/%s/audit_logs/search", endpoint, orgID)

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
	if listOrgAuditLogsCursor != "" {
		q.Set("cursor", listOrgAuditLogsCursor)
	}
	if listOrgAuditLogsFrom != "" {
		q.Set("from", listOrgAuditLogsFrom)
	}
	if listOrgAuditLogsTo != "" {
		q.Set("to", listOrgAuditLogsTo)
	}
	if listOrgAuditLogsSize > 0 {
		q.Set("size", strconv.Itoa(listOrgAuditLogsSize))
	}
	if listOrgAuditLogsSortOrder != "" {
		q.Set("sort_order", listOrgAuditLogsSortOrder)
	}
	if listOrgAuditLogsUserID != "" {
		q.Set("user_id", listOrgAuditLogsUserID)
	}
	if listOrgAuditLogsProjectID != "" {
		q.Set("project_id", listOrgAuditLogsProjectID)
	}
	if listOrgAuditLogsEvents != "" {
		q.Set("events", listOrgAuditLogsEvents)
	}
	if listOrgAuditLogsExcludeEvents != "" {
		q.Set("exclude_events", listOrgAuditLogsExcludeEvents)
	}

	u.RawQuery = q.Encode()
	return u.String(), nil
}

func handleListOrgAuditLogsResponse(resp *http.Response, includeResp, verbose, silent bool) error {
	if verbose {
		fmt.Fprintf(os.Stderr, "* Response: %s\n", resp.Status)
	}

	// Print response headers if requested
	if includeResp {
		fmt.Printf("%s %s\n", resp.Proto, resp.Status)
		for key, values := range resp.Header {
			for _, value := range values {
				fmt.Printf("%s: %s\n", key, value)
			}
		}
		fmt.Println()
	}

	// Read and print response body
	if !silent {
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return fmt.Errorf("failed to read response body: %w", err)
		}
		fmt.Print(string(body))
	}

	// Return error for non-2xx status codes if verbose
	if verbose && (resp.StatusCode < 200 || resp.StatusCode >= 300) {
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, resp.Status)
	}

	return nil
}