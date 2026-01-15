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

// GetAccessRequestsCmd represents the get-access-requests command
var GetAccessRequestsCmd = &cobra.Command{
	Use:   "get-access-requests",
	Short: "Get access requests from Snyk",
	Long: `Get access requests from the Snyk API.

This command retrieves a list of access requests for the authenticated user.
The results can be filtered and paginated using various query parameters.

Examples:
  snyk-api-cli get-access-requests
  snyk-api-cli get-access-requests --limit 10
  snyk-api-cli get-access-requests --org-ids org1,org2
  snyk-api-cli get-access-requests --starting-after abc123
  snyk-api-cli get-access-requests --ending-before xyz789
  snyk-api-cli get-access-requests --verbose`,
	Args: cobra.NoArgs,
	RunE: runGetAccessRequests,
}

var (
	getAccessRequestsOrgIDs        []string
	getAccessRequestsLimit         int
	getAccessRequestsStartingAfter string
	getAccessRequestsEndingBefore  string
	getAccessRequestsVerbose       bool
	getAccessRequestsSilent        bool
	getAccessRequestsIncludeResp   bool
	getAccessRequestsUserAgent     string
)

func init() {
	// Add flags for query parameters
	GetAccessRequestsCmd.Flags().StringSliceVar(&getAccessRequestsOrgIDs, "org-ids", []string{}, "Organization ID filter (can be used multiple times)")
	GetAccessRequestsCmd.Flags().IntVar(&getAccessRequestsLimit, "limit", 0, "Number of results per page")
	GetAccessRequestsCmd.Flags().StringVar(&getAccessRequestsStartingAfter, "starting-after", "", "Cursor for pagination, returns results after this point")
	GetAccessRequestsCmd.Flags().StringVar(&getAccessRequestsEndingBefore, "ending-before", "", "Cursor for pagination, returns results before this point")

	// Add standard flags like other commands
	GetAccessRequestsCmd.Flags().BoolVarP(&getAccessRequestsVerbose, "verbose", "v", false, "Make the operation more talkative")
	GetAccessRequestsCmd.Flags().BoolVarP(&getAccessRequestsSilent, "silent", "s", false, "Silent mode")
	GetAccessRequestsCmd.Flags().BoolVarP(&getAccessRequestsIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	GetAccessRequestsCmd.Flags().StringVarP(&getAccessRequestsUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")
}

func runGetAccessRequests(cmd *cobra.Command, args []string) error {
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Build the URL with query parameters
	fullURL, err := buildGetAccessRequestsURL(endpoint, version, cmd)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	if getAccessRequestsVerbose {
		fmt.Fprintf(os.Stderr, "* Requesting GET %s\n", fullURL)
	}

	// Create the HTTP request
	req, err := http.NewRequest("GET", fullURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Handle authentication with same precedence as curl: Authorization header > SNYK_TOKEN > OAuth
	if getAccessRequestsVerbose {
		fmt.Fprintf(os.Stderr, "* Checking authentication options\n")
	}

	authHeader, err := buildAuthHeader([]string{}) // No manual headers for this command
	if err != nil {
		if getAccessRequestsVerbose {
			fmt.Fprintf(os.Stderr, "* Warning: failed to get automatic auth: %v\n", err)
		}
		// Don't fail the request, just proceed without automatic auth
	} else if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
		if getAccessRequestsVerbose {
			fmt.Fprintf(os.Stderr, "* Added automatic authorization header\n")
		}
	} else if getAccessRequestsVerbose {
		fmt.Fprintf(os.Stderr, "* No automatic authorization available\n")
	}

	// Set user agent
	req.Header.Set("User-Agent", getAccessRequestsUserAgent)

	// Make the request
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	if getAccessRequestsVerbose {
		fmt.Fprintf(os.Stderr, "* Making request...\n")
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// Handle response using the same pattern as other commands
	return handleGetAccessRequestsResponse(resp, getAccessRequestsIncludeResp, getAccessRequestsVerbose, getAccessRequestsSilent)
}

func buildGetAccessRequestsURL(endpoint, version string, cmd *cobra.Command) (string, error) {
	// Build base URL
	baseURL := fmt.Sprintf("https://%s/rest/self/access_requests", endpoint)

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
	if len(getAccessRequestsOrgIDs) > 0 {
		// Handle org_id as an array parameter
		for _, orgID := range getAccessRequestsOrgIDs {
			q.Add("org_id", orgID)
		}
	}
	if getAccessRequestsLimit > 0 {
		q.Set("limit", fmt.Sprintf("%d", getAccessRequestsLimit))
	}
	if getAccessRequestsStartingAfter != "" {
		q.Set("starting_after", getAccessRequestsStartingAfter)
	}
	if getAccessRequestsEndingBefore != "" {
		q.Set("ending_before", getAccessRequestsEndingBefore)
	}

	u.RawQuery = q.Encode()
	return u.String(), nil
}

func handleGetAccessRequestsResponse(resp *http.Response, includeResp, verbose, silent bool) error {
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