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

// ListGroupSsoConnectionUsersCmd represents the list-group-sso-connection-users command
var ListGroupSsoConnectionUsersCmd = &cobra.Command{
	Use:   "list-group-sso-connection-users [group_id] [sso_id]",
	Short: "List users for a specific SSO connection within a group from Snyk",
	Long: `List users for a specific SSO connection within a group from the Snyk API.

This command retrieves a list of users for a specific SSO connection within a group.
Both the group ID and SSO ID must be provided as required arguments.

Examples:
  snyk-api-cli list-group-sso-connection-users 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321
  snyk-api-cli list-group-sso-connection-users 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321 --limit 10
  snyk-api-cli list-group-sso-connection-users 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321 --starting-after "v1.eyJpZCI6IjEwMDAifQo="`,
	Args: cobra.ExactArgs(2),
	RunE: runListGroupSsoConnectionUsers,
}

var (
	listGroupSsoConnectionUsersStartingAfter string
	listGroupSsoConnectionUsersEndingBefore  string
	listGroupSsoConnectionUsersLimit         int
	listGroupSsoConnectionUsersVerbose       bool
	listGroupSsoConnectionUsersSilent        bool
	listGroupSsoConnectionUsersIncludeResp   bool
	listGroupSsoConnectionUsersUserAgent     string
)

func init() {
	// Add query parameter flags
	ListGroupSsoConnectionUsersCmd.Flags().StringVar(&listGroupSsoConnectionUsersStartingAfter, "starting-after", "", "Return the page of results immediately after this cursor")
	ListGroupSsoConnectionUsersCmd.Flags().StringVar(&listGroupSsoConnectionUsersEndingBefore, "ending-before", "", "Return the page of results immediately before this cursor")
	ListGroupSsoConnectionUsersCmd.Flags().IntVar(&listGroupSsoConnectionUsersLimit, "limit", 0, "Number of results to return per page")
	
	// Add standard flags like other commands
	ListGroupSsoConnectionUsersCmd.Flags().BoolVarP(&listGroupSsoConnectionUsersVerbose, "verbose", "v", false, "Make the operation more talkative")
	ListGroupSsoConnectionUsersCmd.Flags().BoolVarP(&listGroupSsoConnectionUsersSilent, "silent", "s", false, "Silent mode")
	ListGroupSsoConnectionUsersCmd.Flags().BoolVarP(&listGroupSsoConnectionUsersIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	ListGroupSsoConnectionUsersCmd.Flags().StringVarP(&listGroupSsoConnectionUsersUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")
}

func runListGroupSsoConnectionUsers(cmd *cobra.Command, args []string) error {
	groupID := args[0]
	ssoID := args[1]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Build the URL
	fullURL, err := buildListGroupSsoConnectionUsersURL(endpoint, version, groupID, ssoID)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	if listGroupSsoConnectionUsersVerbose {
		fmt.Fprintf(os.Stderr, "* Requesting GET %s\n", fullURL)
	}

	// Create the HTTP request
	req, err := http.NewRequest("GET", fullURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Handle authentication with same precedence as curl: Authorization header > SNYK_TOKEN > OAuth
	if listGroupSsoConnectionUsersVerbose {
		fmt.Fprintf(os.Stderr, "* Checking authentication options\n")
	}

	authHeader, err := buildAuthHeader([]string{}) // No manual headers for this command
	if err != nil {
		if listGroupSsoConnectionUsersVerbose {
			fmt.Fprintf(os.Stderr, "* Warning: failed to get automatic auth: %v\n", err)
		}
		// Don't fail the request, just proceed without automatic auth
	} else if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
		if listGroupSsoConnectionUsersVerbose {
			fmt.Fprintf(os.Stderr, "* Added automatic authorization header\n")
		}
	} else if listGroupSsoConnectionUsersVerbose {
		fmt.Fprintf(os.Stderr, "* No automatic authorization available\n")
	}

	// Set user agent
	req.Header.Set("User-Agent", listGroupSsoConnectionUsersUserAgent)

	// Make the request
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	if listGroupSsoConnectionUsersVerbose {
		fmt.Fprintf(os.Stderr, "* Making request...\n")
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// Handle response using the same pattern as other commands
	return handleListGroupSsoConnectionUsersResponse(resp, listGroupSsoConnectionUsersIncludeResp, listGroupSsoConnectionUsersVerbose, listGroupSsoConnectionUsersSilent)
}

func buildListGroupSsoConnectionUsersURL(endpoint, version, groupID, ssoID string) (string, error) {
	// Build base URL with group ID and SSO ID path parameters
	baseURL := fmt.Sprintf("https://%s/rest/groups/%s/sso_connections/%s/users", endpoint, groupID, ssoID)

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
	if listGroupSsoConnectionUsersStartingAfter != "" {
		q.Set("starting_after", listGroupSsoConnectionUsersStartingAfter)
	}
	if listGroupSsoConnectionUsersEndingBefore != "" {
		q.Set("ending_before", listGroupSsoConnectionUsersEndingBefore)
	}
	if listGroupSsoConnectionUsersLimit > 0 {
		q.Set("limit", strconv.Itoa(listGroupSsoConnectionUsersLimit))
	}

	u.RawQuery = q.Encode()
	return u.String(), nil
}

func handleListGroupSsoConnectionUsersResponse(resp *http.Response, includeResp, verbose, silent bool) error {
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