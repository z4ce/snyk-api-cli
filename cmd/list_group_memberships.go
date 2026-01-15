package cmd

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// ListGroupMembershipsCmd represents the list-group-memberships command
var ListGroupMembershipsCmd = &cobra.Command{
	Use:   "list-group-memberships [group_id]",
	Short: "List group memberships from Snyk",
	Long: `List group memberships from the Snyk API.

This command retrieves a list of memberships for a specific group.
The results can be paginated and filtered using various parameters.

Examples:
  snyk-api-cli list-group-memberships 12345678-1234-1234-1234-123456789012
  snyk-api-cli list-group-memberships 12345678-1234-1234-1234-123456789012 --limit 10
  snyk-api-cli list-group-memberships 12345678-1234-1234-1234-123456789012 --email user@example.com
  snyk-api-cli list-group-memberships 12345678-1234-1234-1234-123456789012 --role-name admin
  snyk-api-cli list-group-memberships 12345678-1234-1234-1234-123456789012 --sort-by username --sort-order ASC
  snyk-api-cli list-group-memberships 12345678-1234-1234-1234-123456789012 --verbose`,
	Args: cobra.ExactArgs(1),
	RunE: runListGroupMemberships,
}

var (
	listGroupMembershipsStartingAfter         string
	listGroupMembershipsEndingBefore          string
	listGroupMembershipsLimit                 int
	listGroupMembershipsSortBy                string
	listGroupMembershipsSortOrder             string
	listGroupMembershipsEmail                 string
	listGroupMembershipsUserID                string
	listGroupMembershipsUsername              string
	listGroupMembershipsRoleName              string
	listGroupMembershipsIncludeGroupMembershipCount bool
	listGroupMembershipsVerbose               bool
	listGroupMembershipsSilent                bool
	listGroupMembershipsIncludeResp           bool
	listGroupMembershipsUserAgent             string
)

func init() {
	// Add flags for query parameters
	ListGroupMembershipsCmd.Flags().StringVar(&listGroupMembershipsStartingAfter, "starting-after", "", "Cursor for pagination, returns results after this point")
	ListGroupMembershipsCmd.Flags().StringVar(&listGroupMembershipsEndingBefore, "ending-before", "", "Cursor for pagination, returns results before this point")
	ListGroupMembershipsCmd.Flags().IntVar(&listGroupMembershipsLimit, "limit", 0, "Number of results per page")
	ListGroupMembershipsCmd.Flags().StringVar(&listGroupMembershipsSortBy, "sort-by", "", "Column to sort results (options: username, user_display_name, email, login_method, role_name)")
	ListGroupMembershipsCmd.Flags().StringVar(&listGroupMembershipsSortOrder, "sort-order", "", "Sort direction (ASC or DESC)")
	ListGroupMembershipsCmd.Flags().StringVar(&listGroupMembershipsEmail, "email", "", "Filter by user email")
	ListGroupMembershipsCmd.Flags().StringVar(&listGroupMembershipsUserID, "user-id", "", "Filter by user ID")
	ListGroupMembershipsCmd.Flags().StringVar(&listGroupMembershipsUsername, "username", "", "Filter by username")
	ListGroupMembershipsCmd.Flags().StringVar(&listGroupMembershipsRoleName, "role-name", "", "Filter by specific role")
	ListGroupMembershipsCmd.Flags().BoolVar(&listGroupMembershipsIncludeGroupMembershipCount, "include-group-membership-count", false, "Include group membership count")

	// Add standard flags like curl command
	ListGroupMembershipsCmd.Flags().BoolVarP(&listGroupMembershipsVerbose, "verbose", "v", false, "Make the operation more talkative")
	ListGroupMembershipsCmd.Flags().BoolVarP(&listGroupMembershipsSilent, "silent", "s", false, "Silent mode")
	ListGroupMembershipsCmd.Flags().BoolVarP(&listGroupMembershipsIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	ListGroupMembershipsCmd.Flags().StringVarP(&listGroupMembershipsUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")
}

func runListGroupMemberships(cmd *cobra.Command, args []string) error {
	groupID := args[0]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Build the URL with query parameters
	fullURL, err := buildListGroupMembershipsURL(endpoint, groupID, version)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	if listGroupMembershipsVerbose {
		fmt.Fprintf(os.Stderr, "* Requesting GET %s\n", fullURL)
	}

	// Create the HTTP request
	req, err := http.NewRequest("GET", fullURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Handle authentication with same precedence as curl: Authorization header > SNYK_TOKEN > OAuth
	if listGroupMembershipsVerbose {
		fmt.Fprintf(os.Stderr, "* Checking authentication options\n")
	}

	authHeader, err := buildAuthHeader([]string{}) // No manual headers for this command
	if err != nil {
		if listGroupMembershipsVerbose {
			fmt.Fprintf(os.Stderr, "* Warning: failed to get automatic auth: %v\n", err)
		}
		// Don't fail the request, just proceed without automatic auth
	} else if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
		if listGroupMembershipsVerbose {
			fmt.Fprintf(os.Stderr, "* Added automatic authorization header\n")
		}
	} else if listGroupMembershipsVerbose {
		fmt.Fprintf(os.Stderr, "* No automatic authorization available\n")
	}

	// Set user agent
	req.Header.Set("User-Agent", listGroupMembershipsUserAgent)

	// Make the request
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	if listGroupMembershipsVerbose {
		fmt.Fprintf(os.Stderr, "* Making request...\n")
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// Handle response using the same pattern as other commands
	return handleListGroupMembershipsResponse(resp, listGroupMembershipsIncludeResp, listGroupMembershipsVerbose, listGroupMembershipsSilent)
}

func buildListGroupMembershipsURL(endpoint, groupID, version string) (string, error) {
	// Build base URL
	baseURL := fmt.Sprintf("https://%s/rest/groups/%s/memberships", endpoint, groupID)

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
	if listGroupMembershipsStartingAfter != "" {
		q.Set("starting_after", listGroupMembershipsStartingAfter)
	}
	if listGroupMembershipsEndingBefore != "" {
		q.Set("ending_before", listGroupMembershipsEndingBefore)
	}
	if listGroupMembershipsLimit > 0 {
		q.Set("limit", fmt.Sprintf("%d", listGroupMembershipsLimit))
	}
	if listGroupMembershipsSortBy != "" {
		q.Set("sort_by", listGroupMembershipsSortBy)
	}
	if listGroupMembershipsSortOrder != "" {
		q.Set("sort_order", listGroupMembershipsSortOrder)
	}
	if listGroupMembershipsEmail != "" {
		q.Set("email", listGroupMembershipsEmail)
	}
	if listGroupMembershipsUserID != "" {
		q.Set("user_id", listGroupMembershipsUserID)
	}
	if listGroupMembershipsUsername != "" {
		q.Set("username", listGroupMembershipsUsername)
	}
	if listGroupMembershipsRoleName != "" {
		q.Set("role_name", listGroupMembershipsRoleName)
	}
	if listGroupMembershipsIncludeGroupMembershipCount {
		q.Set("include_group_membership_count", "true")
	}

	u.RawQuery = q.Encode()
	return u.String(), nil
}

func handleListGroupMembershipsResponse(resp *http.Response, includeResp, verbose, silent bool) error {
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