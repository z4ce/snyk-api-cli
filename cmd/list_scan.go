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

// ListScanCmd represents the list-scan command
var ListScanCmd = &cobra.Command{
	Use:   "list-scan [org_id]",
	Short: "List cloud scans for an organization",
	Long: `List cloud scans for an organization from the Snyk API.

This command retrieves a list of cloud scans for the specified organization.
The results can be paginated using various query parameters.

Examples:
  snyk-api-cli list-scan 9a46d918-8764-458c-1234-0987abcd6543
  snyk-api-cli list-scan 9a46d918-8764-458c-1234-0987abcd6543 --limit 10
  snyk-api-cli list-scan 9a46d918-8764-458c-1234-0987abcd6543 --starting-after abc123
  snyk-api-cli list-scan 9a46d918-8764-458c-1234-0987abcd6543 --ending-before xyz789
  snyk-api-cli list-scan 9a46d918-8764-458c-1234-0987abcd6543 --verbose`,
	Args: cobra.ExactArgs(1),
	RunE: runListScan,
}

var (
	listScanStartingAfter string
	listScanEndingBefore  string
	listScanLimit         int
	listScanVerbose       bool
	listScanSilent        bool
	listScanIncludeResp   bool
	listScanUserAgent     string
)

func init() {
	// Add flags for query parameters
	ListScanCmd.Flags().StringVar(&listScanStartingAfter, "starting-after", "", "Pagination cursor for results after this point")
	ListScanCmd.Flags().StringVar(&listScanEndingBefore, "ending-before", "", "Pagination cursor for results before this point")
	ListScanCmd.Flags().IntVar(&listScanLimit, "limit", 0, "Number of results per page")

	// Add standard flags like other commands
	ListScanCmd.Flags().BoolVarP(&listScanVerbose, "verbose", "v", false, "Make the operation more talkative")
	ListScanCmd.Flags().BoolVarP(&listScanSilent, "silent", "s", false, "Silent mode")
	ListScanCmd.Flags().BoolVarP(&listScanIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	ListScanCmd.Flags().StringVarP(&listScanUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")
}

func runListScan(cmd *cobra.Command, args []string) error {
	orgID := args[0]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Build the URL with query parameters
	fullURL, err := buildListScanURL(endpoint, version, orgID, cmd)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	if listScanVerbose {
		fmt.Fprintf(os.Stderr, "* Requesting GET %s\n", fullURL)
	}

	// Create the HTTP request
	req, err := http.NewRequest("GET", fullURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Handle authentication with same precedence as curl: Authorization header > SNYK_TOKEN > OAuth
	if listScanVerbose {
		fmt.Fprintf(os.Stderr, "* Checking authentication options\n")
	}

	authHeader, err := buildAuthHeader([]string{}) // No manual headers for this command
	if err != nil {
		if listScanVerbose {
			fmt.Fprintf(os.Stderr, "* Warning: failed to get automatic auth: %v\n", err)
		}
		// Don't fail the request, just proceed without automatic auth
	} else if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
		if listScanVerbose {
			fmt.Fprintf(os.Stderr, "* Added automatic authorization header\n")
		}
	} else if listScanVerbose {
		fmt.Fprintf(os.Stderr, "* No automatic authorization available\n")
	}

	// Set user agent
	req.Header.Set("User-Agent", listScanUserAgent)

	// Make the request
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	if listScanVerbose {
		fmt.Fprintf(os.Stderr, "* Making request...\n")
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// Handle response using the same pattern as other commands
	return handleListScanResponse(resp, listScanIncludeResp, listScanVerbose, listScanSilent)
}

func buildListScanURL(endpoint, version, orgID string, cmd *cobra.Command) (string, error) {
	// Build base URL with org_id path parameter
	baseURL := fmt.Sprintf("https://%s/rest/orgs/%s/cloud/scans", endpoint, orgID)

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
	if listScanStartingAfter != "" {
		q.Set("starting_after", listScanStartingAfter)
	}
	if listScanEndingBefore != "" {
		q.Set("ending_before", listScanEndingBefore)
	}
	if listScanLimit > 0 {
		q.Set("limit", strconv.Itoa(listScanLimit))
	}

	u.RawQuery = q.Encode()
	return u.String(), nil
}

func handleListScanResponse(resp *http.Response, includeResp, verbose, silent bool) error {
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