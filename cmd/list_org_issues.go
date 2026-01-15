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

// ListOrgIssuesCmd represents the list-org-issues command
var ListOrgIssuesCmd = &cobra.Command{
	Use:   "list-org-issues [org_id]",
	Short: "List issues for a specific organization",
	Long: `List issues for a specific organization from the Snyk API.

This command retrieves a list of issues for the specified organization.
The results can be filtered and paginated using various parameters.

Required permissions:
- View Organization (org.read)
- View Projects (org.project.read) 
- View Project history (org.project.snapshot.read)

Examples:
  snyk-api-cli list-org-issues 12345678-1234-1234-1234-123456789012
  snyk-api-cli list-org-issues 12345678-1234-1234-1234-123456789012 --limit 10
  snyk-api-cli list-org-issues 12345678-1234-1234-1234-123456789012 --updated-after 2024-01-01T00:00:00Z
  snyk-api-cli list-org-issues 12345678-1234-1234-1234-123456789012 --created-before 2024-12-31T23:59:59Z
  snyk-api-cli list-org-issues 12345678-1234-1234-1234-123456789012 --type vulnerability --status open
  snyk-api-cli list-org-issues 12345678-1234-1234-1234-123456789012 --verbose`,
	Args: cobra.ExactArgs(1),
	RunE: runListOrgIssues,
}

var (
	listOrgIssuesStartingAfter          string
	listOrgIssuesEndingBefore           string
	listOrgIssuesLimit                  int
	listOrgIssuesScanItemID             string
	listOrgIssuesScanItemType           string
	listOrgIssuesType                   string
	listOrgIssuesUpdatedBefore          string
	listOrgIssuesUpdatedAfter           string
	listOrgIssuesCreatedBefore          string
	listOrgIssuesCreatedAfter           string
	listOrgIssuesEffectiveSeverityLevel []string
	listOrgIssuesStatus                 []string
	listOrgIssuesIgnored                bool
	listOrgIssuesVerbose                bool
	listOrgIssuesSilent                 bool
	listOrgIssuesIncludeResp            bool
	listOrgIssuesUserAgent              string
)

func init() {
	// Add flags for query parameters
	ListOrgIssuesCmd.Flags().StringVar(&listOrgIssuesStartingAfter, "starting-after", "", "Cursor for pagination, returns results after this point")
	ListOrgIssuesCmd.Flags().StringVar(&listOrgIssuesEndingBefore, "ending-before", "", "Cursor for pagination, returns results before this point")
	ListOrgIssuesCmd.Flags().IntVar(&listOrgIssuesLimit, "limit", 0, "Number of results per page")
	ListOrgIssuesCmd.Flags().StringVar(&listOrgIssuesScanItemID, "scan-item-id", "", "Filter by scan item ID (UUID)")
	ListOrgIssuesCmd.Flags().StringVar(&listOrgIssuesScanItemType, "scan-item-type", "", "Filter by scan item type (project or environment)")
	ListOrgIssuesCmd.Flags().StringVar(&listOrgIssuesType, "type", "", "Filter by issue type (e.g., vulnerability, license)")
	ListOrgIssuesCmd.Flags().StringVar(&listOrgIssuesUpdatedBefore, "updated-before", "", "Filter issues updated before this date-time (ISO 8601 format)")
	ListOrgIssuesCmd.Flags().StringVar(&listOrgIssuesUpdatedAfter, "updated-after", "", "Filter issues updated after this date-time (ISO 8601 format)")
	ListOrgIssuesCmd.Flags().StringVar(&listOrgIssuesCreatedBefore, "created-before", "", "Filter issues created before this date-time (ISO 8601 format)")
	ListOrgIssuesCmd.Flags().StringVar(&listOrgIssuesCreatedAfter, "created-after", "", "Filter issues created after this date-time (ISO 8601 format)")
	ListOrgIssuesCmd.Flags().StringSliceVar(&listOrgIssuesEffectiveSeverityLevel, "effective-severity-level", []string{}, "Filter by effective severity level (can be used multiple times)")
	ListOrgIssuesCmd.Flags().StringSliceVar(&listOrgIssuesStatus, "status", []string{}, "Filter by issue status (open, resolved) (can be used multiple times)")
	ListOrgIssuesCmd.Flags().BoolVar(&listOrgIssuesIgnored, "ignored", false, "Filter ignored issues")

	// Add standard flags like curl command
	ListOrgIssuesCmd.Flags().BoolVarP(&listOrgIssuesVerbose, "verbose", "v", false, "Make the operation more talkative")
	ListOrgIssuesCmd.Flags().BoolVarP(&listOrgIssuesSilent, "silent", "s", false, "Silent mode")
	ListOrgIssuesCmd.Flags().BoolVarP(&listOrgIssuesIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	ListOrgIssuesCmd.Flags().StringVarP(&listOrgIssuesUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")
}

func runListOrgIssues(cmd *cobra.Command, args []string) error {
	orgID := args[0]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Build the URL with query parameters
	fullURL, err := buildListOrgIssuesURL(endpoint, version, orgID, cmd)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	if listOrgIssuesVerbose {
		fmt.Fprintf(os.Stderr, "* Requesting GET %s\n", fullURL)
	}

	// Create the HTTP request
	req, err := http.NewRequest("GET", fullURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Handle authentication with same precedence as curl: Authorization header > SNYK_TOKEN > OAuth
	if listOrgIssuesVerbose {
		fmt.Fprintf(os.Stderr, "* Checking authentication options\n")
	}

	authHeader, err := buildAuthHeader([]string{}) // No manual headers for this command
	if err != nil {
		if listOrgIssuesVerbose {
			fmt.Fprintf(os.Stderr, "* Warning: failed to get automatic auth: %v\n", err)
		}
		// Don't fail the request, just proceed without automatic auth
	} else if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
		if listOrgIssuesVerbose {
			fmt.Fprintf(os.Stderr, "* Added automatic authorization header\n")
		}
	} else if listOrgIssuesVerbose {
		fmt.Fprintf(os.Stderr, "* No automatic authorization available\n")
	}

	// Set user agent
	req.Header.Set("User-Agent", listOrgIssuesUserAgent)

	// Make the request
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	if listOrgIssuesVerbose {
		fmt.Fprintf(os.Stderr, "* Making request...\n")
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// Handle response using the same pattern as other commands
	return handleListOrgIssuesResponse(resp, listOrgIssuesIncludeResp, listOrgIssuesVerbose, listOrgIssuesSilent)
}

func buildListOrgIssuesURL(endpoint, version, orgID string, cmd *cobra.Command) (string, error) {
	// Build base URL
	baseURL := fmt.Sprintf("https://%s/rest/orgs/%s/issues", endpoint, orgID)

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
	if listOrgIssuesStartingAfter != "" {
		q.Set("starting_after", listOrgIssuesStartingAfter)
	}
	if listOrgIssuesEndingBefore != "" {
		q.Set("ending_before", listOrgIssuesEndingBefore)
	}
	if listOrgIssuesLimit > 0 {
		q.Set("limit", strconv.Itoa(listOrgIssuesLimit))
	}
	if listOrgIssuesScanItemID != "" {
		q.Set("scan_item.id", listOrgIssuesScanItemID)
	}
	if listOrgIssuesScanItemType != "" {
		q.Set("scan_item.type", listOrgIssuesScanItemType)
	}
	if listOrgIssuesType != "" {
		q.Set("type", listOrgIssuesType)
	}
	if listOrgIssuesUpdatedBefore != "" {
		q.Set("updated_before", listOrgIssuesUpdatedBefore)
	}
	if listOrgIssuesUpdatedAfter != "" {
		q.Set("updated_after", listOrgIssuesUpdatedAfter)
	}
	if listOrgIssuesCreatedBefore != "" {
		q.Set("created_before", listOrgIssuesCreatedBefore)
	}
	if listOrgIssuesCreatedAfter != "" {
		q.Set("created_after", listOrgIssuesCreatedAfter)
	}

	// Handle array parameters
	for _, level := range listOrgIssuesEffectiveSeverityLevel {
		q.Add("effective_severity_level", level)
	}
	for _, status := range listOrgIssuesStatus {
		q.Add("status", status)
	}

	// Handle ignored parameter - only add if explicitly set
	if cmd.Flag("ignored").Changed {
		q.Set("ignored", strconv.FormatBool(listOrgIssuesIgnored))
	}

	u.RawQuery = q.Encode()
	return u.String(), nil
}

func handleListOrgIssuesResponse(resp *http.Response, includeResp, verbose, silent bool) error {
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