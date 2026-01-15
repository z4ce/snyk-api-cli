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

// ListGroupsCmd represents the list-groups command
var ListGroupsCmd = &cobra.Command{
	Use:   "list-groups",
	Short: "List groups from Snyk",
	Long: `List groups from the Snyk API.

This command retrieves a list of groups that the authenticated user is a member of.
The results can be paginated using cursor-based pagination.

Examples:
  snyk-api-cli list-groups
  snyk-api-cli list-groups --limit 10
  snyk-api-cli list-groups --starting-after abc123
  snyk-api-cli list-groups --ending-before xyz789
  snyk-api-cli list-groups --verbose`,
	RunE: runListGroups,
}

var (
	listGroupsStartingAfter string
	listGroupsEndingBefore  string
	listGroupsLimit         int
	listGroupsVerbose       bool
	listGroupsSilent        bool
	listGroupsIncludeResp   bool
	listGroupsUserAgent     string
)

func init() {
	// Add flags for query parameters
	ListGroupsCmd.Flags().StringVar(&listGroupsStartingAfter, "starting-after", "", "Cursor for pagination, returns results after this point")
	ListGroupsCmd.Flags().StringVar(&listGroupsEndingBefore, "ending-before", "", "Cursor for pagination, returns results before this point")
	ListGroupsCmd.Flags().IntVar(&listGroupsLimit, "limit", 0, "Number of results per page")

	// Add standard flags like curl command
	ListGroupsCmd.Flags().BoolVarP(&listGroupsVerbose, "verbose", "v", false, "Make the operation more talkative")
	ListGroupsCmd.Flags().BoolVarP(&listGroupsSilent, "silent", "s", false, "Silent mode")
	ListGroupsCmd.Flags().BoolVarP(&listGroupsIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	ListGroupsCmd.Flags().StringVarP(&listGroupsUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")
}

func runListGroups(cmd *cobra.Command, args []string) error {
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Build the URL with query parameters
	fullURL, err := buildListGroupsURL(endpoint, version)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	if listGroupsVerbose {
		fmt.Fprintf(os.Stderr, "* Requesting GET %s\n", fullURL)
	}

	// Create the HTTP request
	req, err := http.NewRequest("GET", fullURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Handle authentication with same precedence as curl: Authorization header > SNYK_TOKEN > OAuth
	if listGroupsVerbose {
		fmt.Fprintf(os.Stderr, "* Checking authentication options\n")
	}

	authHeader, err := buildAuthHeader([]string{}) // No manual headers for this command
	if err != nil {
		if listGroupsVerbose {
			fmt.Fprintf(os.Stderr, "* Warning: failed to get automatic auth: %v\n", err)
		}
		// Don't fail the request, just proceed without automatic auth
	} else if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
		if listGroupsVerbose {
			fmt.Fprintf(os.Stderr, "* Added automatic authorization header\n")
		}
	} else if listGroupsVerbose {
		fmt.Fprintf(os.Stderr, "* No automatic authorization available\n")
	}

	// Set user agent
	req.Header.Set("User-Agent", listGroupsUserAgent)

	// Make the request
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	if listGroupsVerbose {
		fmt.Fprintf(os.Stderr, "* Making request...\n")
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// Handle response using the same pattern as other commands
	return handleListGroupsResponse(resp, listGroupsIncludeResp, listGroupsVerbose, listGroupsSilent)
}

func buildListGroupsURL(endpoint, version string) (string, error) {
	// Build base URL
	baseURL := fmt.Sprintf("https://%s/rest/groups", endpoint)

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
	if listGroupsStartingAfter != "" {
		q.Set("starting_after", listGroupsStartingAfter)
	}
	if listGroupsEndingBefore != "" {
		q.Set("ending_before", listGroupsEndingBefore)
	}
	if listGroupsLimit > 0 {
		q.Set("limit", fmt.Sprintf("%d", listGroupsLimit))
	}

	u.RawQuery = q.Encode()
	return u.String(), nil
}

func handleListGroupsResponse(resp *http.Response, includeResp, verbose, silent bool) error {
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