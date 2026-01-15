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

// GetUserInstalledAppsCmd represents the get-user-installed-apps command
var GetUserInstalledAppsCmd = &cobra.Command{
	Use:   "get-user-installed-apps",
	Short: "Get a list of Snyk Apps that can act on your behalf",
	Long: `Get a list of Snyk Apps that can act on your behalf from the Snyk API.

This command retrieves a list of Snyk Apps that the authenticated user has installed
and that can act on the user's behalf. The results can be paginated using various
query parameters.

Examples:
  snyk-api-cli get-user-installed-apps
  snyk-api-cli get-user-installed-apps --limit 10
  snyk-api-cli get-user-installed-apps --starting-after abc123
  snyk-api-cli get-user-installed-apps --ending-before xyz789
  snyk-api-cli get-user-installed-apps --verbose`,
	Args: cobra.NoArgs,
	RunE: runGetUserInstalledApps,
}

var (
	getUserInstalledAppsLimit         int
	getUserInstalledAppsStartingAfter string
	getUserInstalledAppsEndingBefore  string
	getUserInstalledAppsVerbose       bool
	getUserInstalledAppsSilent        bool
	getUserInstalledAppsIncludeResp   bool
	getUserInstalledAppsUserAgent     string
)

func init() {
	// Add flags for query parameters
	GetUserInstalledAppsCmd.Flags().IntVar(&getUserInstalledAppsLimit, "limit", 0, "Number of results per page")
	GetUserInstalledAppsCmd.Flags().StringVar(&getUserInstalledAppsStartingAfter, "starting-after", "", "Cursor for pagination, returns results after this point")
	GetUserInstalledAppsCmd.Flags().StringVar(&getUserInstalledAppsEndingBefore, "ending-before", "", "Cursor for pagination, returns results before this point")

	// Add standard flags like other commands
	GetUserInstalledAppsCmd.Flags().BoolVarP(&getUserInstalledAppsVerbose, "verbose", "v", false, "Make the operation more talkative")
	GetUserInstalledAppsCmd.Flags().BoolVarP(&getUserInstalledAppsSilent, "silent", "s", false, "Silent mode")
	GetUserInstalledAppsCmd.Flags().BoolVarP(&getUserInstalledAppsIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	GetUserInstalledAppsCmd.Flags().StringVarP(&getUserInstalledAppsUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")
}

func runGetUserInstalledApps(cmd *cobra.Command, args []string) error {
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Build the URL with query parameters
	fullURL, err := buildGetUserInstalledAppsURL(endpoint, version, cmd)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	if getUserInstalledAppsVerbose {
		fmt.Fprintf(os.Stderr, "* Requesting GET %s\n", fullURL)
	}

	// Create the HTTP request
	req, err := http.NewRequest("GET", fullURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Handle authentication with same precedence as curl: Authorization header > SNYK_TOKEN > OAuth
	if getUserInstalledAppsVerbose {
		fmt.Fprintf(os.Stderr, "* Checking authentication options\n")
	}

	authHeader, err := buildAuthHeader([]string{}) // No manual headers for this command
	if err != nil {
		if getUserInstalledAppsVerbose {
			fmt.Fprintf(os.Stderr, "* Warning: failed to get automatic auth: %v\n", err)
		}
		// Don't fail the request, just proceed without automatic auth
	} else if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
		if getUserInstalledAppsVerbose {
			fmt.Fprintf(os.Stderr, "* Added automatic authorization header\n")
		}
	} else if getUserInstalledAppsVerbose {
		fmt.Fprintf(os.Stderr, "* No automatic authorization available\n")
	}

	// Set user agent
	req.Header.Set("User-Agent", getUserInstalledAppsUserAgent)

	// Make the request
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	if getUserInstalledAppsVerbose {
		fmt.Fprintf(os.Stderr, "* Making request...\n")
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// Handle response using the same pattern as other commands
	return handleGetUserInstalledAppsResponse(resp, getUserInstalledAppsIncludeResp, getUserInstalledAppsVerbose, getUserInstalledAppsSilent)
}

func buildGetUserInstalledAppsURL(endpoint, version string, cmd *cobra.Command) (string, error) {
	// Build base URL
	baseURL := fmt.Sprintf("https://%s/rest/self/apps", endpoint)

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
	if getUserInstalledAppsLimit > 0 {
		q.Set("limit", fmt.Sprintf("%d", getUserInstalledAppsLimit))
	}
	if getUserInstalledAppsStartingAfter != "" {
		q.Set("starting_after", getUserInstalledAppsStartingAfter)
	}
	if getUserInstalledAppsEndingBefore != "" {
		q.Set("ending_before", getUserInstalledAppsEndingBefore)
	}

	u.RawQuery = q.Encode()
	return u.String(), nil
}

func handleGetUserInstalledAppsResponse(resp *http.Response, includeResp, verbose, silent bool) error {
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