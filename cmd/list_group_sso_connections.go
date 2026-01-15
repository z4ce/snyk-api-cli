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

// ListGroupSsoConnectionsCmd represents the list-group-sso-connections command
var ListGroupSsoConnectionsCmd = &cobra.Command{
	Use:   "list-group-sso-connections [group_id]",
	Short: "List SSO connections for a group from Snyk",
	Long: `List SSO connections for a group from the Snyk API.

This command retrieves a list of SSO connections for a specific group by its ID.
The group ID must be provided as a required argument.

Examples:
  snyk-api-cli list-group-sso-connections 12345678-1234-1234-1234-123456789012
  snyk-api-cli list-group-sso-connections 12345678-1234-1234-1234-123456789012 --limit 10
  snyk-api-cli list-group-sso-connections 12345678-1234-1234-1234-123456789012 --starting-after "v1.eyJpZCI6IjEwMDAifQo="`,
	Args: cobra.ExactArgs(1),
	RunE: runListGroupSsoConnections,
}

var (
	listGroupSsoConnectionsStartingAfter string
	listGroupSsoConnectionsEndingBefore  string
	listGroupSsoConnectionsLimit         int
	listGroupSsoConnectionsVerbose       bool
	listGroupSsoConnectionsSilent        bool
	listGroupSsoConnectionsIncludeResp   bool
	listGroupSsoConnectionsUserAgent     string
)

func init() {
	// Add query parameter flags
	ListGroupSsoConnectionsCmd.Flags().StringVar(&listGroupSsoConnectionsStartingAfter, "starting-after", "", "Return the page of results immediately after this cursor")
	ListGroupSsoConnectionsCmd.Flags().StringVar(&listGroupSsoConnectionsEndingBefore, "ending-before", "", "Return the page of results immediately before this cursor")
	ListGroupSsoConnectionsCmd.Flags().IntVar(&listGroupSsoConnectionsLimit, "limit", 0, "Number of results to return per page")
	
	// Add standard flags like other commands
	ListGroupSsoConnectionsCmd.Flags().BoolVarP(&listGroupSsoConnectionsVerbose, "verbose", "v", false, "Make the operation more talkative")
	ListGroupSsoConnectionsCmd.Flags().BoolVarP(&listGroupSsoConnectionsSilent, "silent", "s", false, "Silent mode")
	ListGroupSsoConnectionsCmd.Flags().BoolVarP(&listGroupSsoConnectionsIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	ListGroupSsoConnectionsCmd.Flags().StringVarP(&listGroupSsoConnectionsUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")
}

func runListGroupSsoConnections(cmd *cobra.Command, args []string) error {
	groupID := args[0]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Build the URL
	fullURL, err := buildListGroupSsoConnectionsURL(endpoint, version, groupID)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	if listGroupSsoConnectionsVerbose {
		fmt.Fprintf(os.Stderr, "* Requesting GET %s\n", fullURL)
	}

	// Create the HTTP request
	req, err := http.NewRequest("GET", fullURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Handle authentication with same precedence as curl: Authorization header > SNYK_TOKEN > OAuth
	if listGroupSsoConnectionsVerbose {
		fmt.Fprintf(os.Stderr, "* Checking authentication options\n")
	}

	authHeader, err := buildAuthHeader([]string{}) // No manual headers for this command
	if err != nil {
		if listGroupSsoConnectionsVerbose {
			fmt.Fprintf(os.Stderr, "* Warning: failed to get automatic auth: %v\n", err)
		}
		// Don't fail the request, just proceed without automatic auth
	} else if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
		if listGroupSsoConnectionsVerbose {
			fmt.Fprintf(os.Stderr, "* Added automatic authorization header\n")
		}
	} else if listGroupSsoConnectionsVerbose {
		fmt.Fprintf(os.Stderr, "* No automatic authorization available\n")
	}

	// Set user agent
	req.Header.Set("User-Agent", listGroupSsoConnectionsUserAgent)

	// Make the request
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	if listGroupSsoConnectionsVerbose {
		fmt.Fprintf(os.Stderr, "* Making request...\n")
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// Handle response using the same pattern as other commands
	return handleListGroupSsoConnectionsResponse(resp, listGroupSsoConnectionsIncludeResp, listGroupSsoConnectionsVerbose, listGroupSsoConnectionsSilent)
}

func buildListGroupSsoConnectionsURL(endpoint, version, groupID string) (string, error) {
	// Build base URL with group ID path parameter
	baseURL := fmt.Sprintf("https://%s/rest/groups/%s/sso_connections", endpoint, groupID)

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
	if listGroupSsoConnectionsStartingAfter != "" {
		q.Set("starting_after", listGroupSsoConnectionsStartingAfter)
	}
	if listGroupSsoConnectionsEndingBefore != "" {
		q.Set("ending_before", listGroupSsoConnectionsEndingBefore)
	}
	if listGroupSsoConnectionsLimit > 0 {
		q.Set("limit", strconv.Itoa(listGroupSsoConnectionsLimit))
	}

	u.RawQuery = q.Encode()
	return u.String(), nil
}

func handleListGroupSsoConnectionsResponse(resp *http.Response, includeResp, verbose, silent bool) error {
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