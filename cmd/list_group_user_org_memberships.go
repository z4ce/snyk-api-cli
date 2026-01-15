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

// ListGroupUserOrgMembershipsCmd represents the list-group-user-org-memberships command
var ListGroupUserOrgMembershipsCmd = &cobra.Command{
	Use:   "list-group-user-org-memberships [group_id]",
	Short: "List group user org memberships from Snyk",
	Long: `List group user org memberships from the Snyk API.

This command retrieves a list of organization memberships for a specific user within a group.
The results can be paginated and filtered using various parameters.

Examples:
  snyk-api-cli list-group-user-org-memberships 12345678-1234-1234-1234-123456789012 --user-id 87654321-4321-4321-4321-210987654321
  snyk-api-cli list-group-user-org-memberships 12345678-1234-1234-1234-123456789012 --user-id 87654321-4321-4321-4321-210987654321 --limit 10
  snyk-api-cli list-group-user-org-memberships 12345678-1234-1234-1234-123456789012 --user-id 87654321-4321-4321-4321-210987654321 --org-name "MyOrg"
  snyk-api-cli list-group-user-org-memberships 12345678-1234-1234-1234-123456789012 --user-id 87654321-4321-4321-4321-210987654321 --role-name admin
  snyk-api-cli list-group-user-org-memberships 12345678-1234-1234-1234-123456789012 --user-id 87654321-4321-4321-4321-210987654321 --verbose`,
	Args: cobra.ExactArgs(1),
	RunE: runListGroupUserOrgMemberships,
}

var (
	listGroupUserOrgMembershipsUserID         string
	listGroupUserOrgMembershipsOrgName        string
	listGroupUserOrgMembershipsRoleName       string
	listGroupUserOrgMembershipsStartingAfter  string
	listGroupUserOrgMembershipsEndingBefore   string
	listGroupUserOrgMembershipsLimit          int
	listGroupUserOrgMembershipsVerbose        bool
	listGroupUserOrgMembershipsSilent         bool
	listGroupUserOrgMembershipsIncludeResp    bool
	listGroupUserOrgMembershipsUserAgent      string
)

func init() {
	// Add flags for query parameters
	ListGroupUserOrgMembershipsCmd.Flags().StringVar(&listGroupUserOrgMembershipsUserID, "user-id", "", "The ID of the User (required)")
	ListGroupUserOrgMembershipsCmd.Flags().StringVar(&listGroupUserOrgMembershipsOrgName, "org-name", "", "The Name of the org")
	ListGroupUserOrgMembershipsCmd.Flags().StringVar(&listGroupUserOrgMembershipsRoleName, "role-name", "", "Filter the response for results only with the specified role")
	ListGroupUserOrgMembershipsCmd.Flags().StringVar(&listGroupUserOrgMembershipsStartingAfter, "starting-after", "", "Return the page of results immediately after this cursor")
	ListGroupUserOrgMembershipsCmd.Flags().StringVar(&listGroupUserOrgMembershipsEndingBefore, "ending-before", "", "Return the page of results immediately before this cursor")
	ListGroupUserOrgMembershipsCmd.Flags().IntVar(&listGroupUserOrgMembershipsLimit, "limit", 0, "Number of results to return per page")

	// Add standard flags like curl command
	ListGroupUserOrgMembershipsCmd.Flags().BoolVarP(&listGroupUserOrgMembershipsVerbose, "verbose", "v", false, "Make the operation more talkative")
	ListGroupUserOrgMembershipsCmd.Flags().BoolVarP(&listGroupUserOrgMembershipsSilent, "silent", "s", false, "Silent mode")
	ListGroupUserOrgMembershipsCmd.Flags().BoolVarP(&listGroupUserOrgMembershipsIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	ListGroupUserOrgMembershipsCmd.Flags().StringVarP(&listGroupUserOrgMembershipsUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")

	// Mark user-id as required
	ListGroupUserOrgMembershipsCmd.MarkFlagRequired("user-id")
}

func runListGroupUserOrgMemberships(cmd *cobra.Command, args []string) error {
	groupID := args[0]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Build the URL with query parameters
	fullURL, err := buildListGroupUserOrgMembershipsURL(endpoint, groupID, version)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	if listGroupUserOrgMembershipsVerbose {
		fmt.Fprintf(os.Stderr, "* Requesting GET %s\n", fullURL)
	}

	// Create the HTTP request
	req, err := http.NewRequest("GET", fullURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Handle authentication with same precedence as curl: Authorization header > SNYK_TOKEN > OAuth
	if listGroupUserOrgMembershipsVerbose {
		fmt.Fprintf(os.Stderr, "* Checking authentication options\n")
	}

	authHeader, err := buildAuthHeader([]string{}) // No manual headers for this command
	if err != nil {
		if listGroupUserOrgMembershipsVerbose {
			fmt.Fprintf(os.Stderr, "* Warning: failed to get automatic auth: %v\n", err)
		}
		// Don't fail the request, just proceed without automatic auth
	} else if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
		if listGroupUserOrgMembershipsVerbose {
			fmt.Fprintf(os.Stderr, "* Added automatic authorization header\n")
		}
	} else if listGroupUserOrgMembershipsVerbose {
		fmt.Fprintf(os.Stderr, "* No automatic authorization available\n")
	}

	// Set user agent
	req.Header.Set("User-Agent", listGroupUserOrgMembershipsUserAgent)

	// Make the request
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	if listGroupUserOrgMembershipsVerbose {
		fmt.Fprintf(os.Stderr, "* Making request...\n")
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// Handle response using the same pattern as other commands
	return handleListGroupUserOrgMembershipsResponse(resp, listGroupUserOrgMembershipsIncludeResp, listGroupUserOrgMembershipsVerbose, listGroupUserOrgMembershipsSilent)
}

func buildListGroupUserOrgMembershipsURL(endpoint, groupID, version string) (string, error) {
	// Build base URL
	baseURL := fmt.Sprintf("https://%s/rest/groups/%s/org_memberships", endpoint, groupID)

	// Parse URL to handle query parameters properly
	u, err := url.Parse(baseURL)
	if err != nil {
		return "", err
	}

	// Add query parameters
	q := u.Query()

	// Version is required
	q.Set("version", version)

	// user_id is required
	if listGroupUserOrgMembershipsUserID != "" {
		q.Set("user_id", listGroupUserOrgMembershipsUserID)
	}

	// Add optional parameters if provided
	if listGroupUserOrgMembershipsOrgName != "" {
		q.Set("org_name", listGroupUserOrgMembershipsOrgName)
	}
	if listGroupUserOrgMembershipsRoleName != "" {
		q.Set("role_name", listGroupUserOrgMembershipsRoleName)
	}
	if listGroupUserOrgMembershipsStartingAfter != "" {
		q.Set("starting_after", listGroupUserOrgMembershipsStartingAfter)
	}
	if listGroupUserOrgMembershipsEndingBefore != "" {
		q.Set("ending_before", listGroupUserOrgMembershipsEndingBefore)
	}
	if listGroupUserOrgMembershipsLimit > 0 {
		q.Set("limit", fmt.Sprintf("%d", listGroupUserOrgMembershipsLimit))
	}

	u.RawQuery = q.Encode()
	return u.String(), nil
}

func handleListGroupUserOrgMembershipsResponse(resp *http.Response, includeResp, verbose, silent bool) error {
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