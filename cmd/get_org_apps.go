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

// GetOrgAppsCmd represents the get-org-apps command
var GetOrgAppsCmd = &cobra.Command{
	Use:   "get-org-apps [org_id]",
	Short: "Get organization apps from Snyk",
	Long: `Get organization apps from the Snyk API.

This command retrieves a list of apps for the specified organization.
The results can be paginated using various query parameters.

Examples:
  snyk-api-cli get-org-apps 12345678-1234-1234-1234-123456789012
  snyk-api-cli get-org-apps 12345678-1234-1234-1234-123456789012 --limit 10
  snyk-api-cli get-org-apps 12345678-1234-1234-1234-123456789012 --starting-after abc123
  snyk-api-cli get-org-apps 12345678-1234-1234-1234-123456789012 --ending-before xyz789
  snyk-api-cli get-org-apps 12345678-1234-1234-1234-123456789012 --verbose`,
	Args: cobra.ExactArgs(1),
	RunE: runGetOrgApps,
}

var (
	getOrgAppsStartingAfter string
	getOrgAppsEndingBefore  string
	getOrgAppsLimit         int
	getOrgAppsVerbose       bool
	getOrgAppsSilent        bool
	getOrgAppsIncludeResp   bool
	getOrgAppsUserAgent     string
)

func init() {
	// Add flags for query parameters
	GetOrgAppsCmd.Flags().StringVar(&getOrgAppsStartingAfter, "starting-after", "", "Cursor for pagination, returns results after this point")
	GetOrgAppsCmd.Flags().StringVar(&getOrgAppsEndingBefore, "ending-before", "", "Cursor for pagination, returns results before this point")
	GetOrgAppsCmd.Flags().IntVar(&getOrgAppsLimit, "limit", 0, "Number of results per page")

	// Add standard flags like other commands
	GetOrgAppsCmd.Flags().BoolVarP(&getOrgAppsVerbose, "verbose", "v", false, "Make the operation more talkative")
	GetOrgAppsCmd.Flags().BoolVarP(&getOrgAppsSilent, "silent", "s", false, "Silent mode")
	GetOrgAppsCmd.Flags().BoolVarP(&getOrgAppsIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	GetOrgAppsCmd.Flags().StringVarP(&getOrgAppsUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")
}

func runGetOrgApps(cmd *cobra.Command, args []string) error {
	orgID := args[0]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Build the URL with query parameters
	fullURL, err := buildGetOrgAppsURL(endpoint, version, orgID, cmd)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	if getOrgAppsVerbose {
		fmt.Fprintf(os.Stderr, "* Requesting GET %s\n", fullURL)
	}

	// Create the HTTP request
	req, err := http.NewRequest("GET", fullURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Handle authentication with same precedence as curl: Authorization header > SNYK_TOKEN > OAuth
	if getOrgAppsVerbose {
		fmt.Fprintf(os.Stderr, "* Checking authentication options\n")
	}

	authHeader, err := buildAuthHeader([]string{}) // No manual headers for this command
	if err != nil {
		if getOrgAppsVerbose {
			fmt.Fprintf(os.Stderr, "* Warning: failed to get automatic auth: %v\n", err)
		}
		// Don't fail the request, just proceed without automatic auth
	} else if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
		if getOrgAppsVerbose {
			fmt.Fprintf(os.Stderr, "* Added automatic authorization header\n")
		}
	} else if getOrgAppsVerbose {
		fmt.Fprintf(os.Stderr, "* No automatic authorization available\n")
	}

	// Set user agent
	req.Header.Set("User-Agent", getOrgAppsUserAgent)

	// Make the request
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	if getOrgAppsVerbose {
		fmt.Fprintf(os.Stderr, "* Making request...\n")
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// Handle response using the same pattern as other commands
	return handleGetOrgAppsResponse(resp, getOrgAppsIncludeResp, getOrgAppsVerbose, getOrgAppsSilent)
}

func buildGetOrgAppsURL(endpoint, version, orgID string, cmd *cobra.Command) (string, error) {
	// Build base URL
	baseURL := fmt.Sprintf("https://%s/rest/orgs/%s/apps/creations", endpoint, orgID)

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
	if getOrgAppsStartingAfter != "" {
		q.Set("starting_after", getOrgAppsStartingAfter)
	}
	if getOrgAppsEndingBefore != "" {
		q.Set("ending_before", getOrgAppsEndingBefore)
	}
	if getOrgAppsLimit > 0 {
		q.Set("limit", fmt.Sprintf("%d", getOrgAppsLimit))
	}

	u.RawQuery = q.Encode()
	return u.String(), nil
}

func handleGetOrgAppsResponse(resp *http.Response, includeResp, verbose, silent bool) error {
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