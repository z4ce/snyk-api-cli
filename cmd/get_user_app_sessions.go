package cmd

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// GetUserAppSessionsCmd represents the get-user-app-sessions command
var GetUserAppSessionsCmd = &cobra.Command{
	Use:   "get-user-app-sessions [app_id]",
	Short: "Get a list of active OAuth sessions by app ID",
	Long: `Get a list of active OAuth sessions by app ID from the Snyk API.

This command retrieves a list of active OAuth sessions for a specific Snyk App
that the authenticated user has access to. The app_id parameter is required
and must be a valid UUID. The results can be paginated using various query parameters.

Examples:
  snyk-api-cli get-user-app-sessions 12345678-1234-5678-9012-123456789012
  snyk-api-cli get-user-app-sessions 12345678-1234-5678-9012-123456789012 --limit 10
  snyk-api-cli get-user-app-sessions 12345678-1234-5678-9012-123456789012 --starting-after abc123
  snyk-api-cli get-user-app-sessions 12345678-1234-5678-9012-123456789012 --ending-before xyz789
  snyk-api-cli get-user-app-sessions 12345678-1234-5678-9012-123456789012 --verbose`,
	Args: cobra.ExactArgs(1),
	RunE: runGetUserAppSessions,
}

var (
	getUserAppSessionsLimit         int
	getUserAppSessionsStartingAfter string
	getUserAppSessionsEndingBefore  string
	getUserAppSessionsVerbose       bool
	getUserAppSessionsSilent        bool
	getUserAppSessionsIncludeResp   bool
	getUserAppSessionsUserAgent     string
)

func init() {
	// Add flags for query parameters
	GetUserAppSessionsCmd.Flags().IntVar(&getUserAppSessionsLimit, "limit", 0, "Number of results per page")
	GetUserAppSessionsCmd.Flags().StringVar(&getUserAppSessionsStartingAfter, "starting-after", "", "Cursor for pagination, returns results after this point")
	GetUserAppSessionsCmd.Flags().StringVar(&getUserAppSessionsEndingBefore, "ending-before", "", "Cursor for pagination, returns results before this point")

	// Add standard flags like other commands
	GetUserAppSessionsCmd.Flags().BoolVarP(&getUserAppSessionsVerbose, "verbose", "v", false, "Make the operation more talkative")
	GetUserAppSessionsCmd.Flags().BoolVarP(&getUserAppSessionsSilent, "silent", "s", false, "Silent mode")
	GetUserAppSessionsCmd.Flags().BoolVarP(&getUserAppSessionsIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	GetUserAppSessionsCmd.Flags().StringVarP(&getUserAppSessionsUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")
}

func runGetUserAppSessions(cmd *cobra.Command, args []string) error {
	appID := args[0]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Build the URL with path and query parameters
	fullURL, err := buildGetUserAppSessionsURL(endpoint, version, appID, cmd)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	if getUserAppSessionsVerbose {
		fmt.Fprintf(os.Stderr, "* Requesting GET %s\n", fullURL)
	}

	// Create the HTTP request
	req, err := http.NewRequest("GET", fullURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Handle authentication with same precedence as curl: Authorization header > SNYK_TOKEN > OAuth
	if getUserAppSessionsVerbose {
		fmt.Fprintf(os.Stderr, "* Checking authentication options\n")
	}

	authHeader, err := buildAuthHeader([]string{}) // No manual headers for this command
	if err != nil {
		if getUserAppSessionsVerbose {
			fmt.Fprintf(os.Stderr, "* Warning: failed to get automatic auth: %v\n", err)
		}
		// Don't fail the request, just proceed without automatic auth
	} else if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
		if getUserAppSessionsVerbose {
			fmt.Fprintf(os.Stderr, "* Added automatic authorization header\n")
		}
	} else if getUserAppSessionsVerbose {
		fmt.Fprintf(os.Stderr, "* No automatic authorization available\n")
	}

	// Set user agent
	req.Header.Set("User-Agent", getUserAppSessionsUserAgent)

	// Make the request
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	if getUserAppSessionsVerbose {
		fmt.Fprintf(os.Stderr, "* Making request...\n")
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// Handle response using the same pattern as other commands
	return handleGetUserAppSessionsResponse(resp, getUserAppSessionsIncludeResp, getUserAppSessionsVerbose, getUserAppSessionsSilent)
}

func buildGetUserAppSessionsURL(endpoint, version, appID string, cmd *cobra.Command) (string, error) {
	// Validate the required app_id parameter
	if strings.TrimSpace(appID) == "" {
		return "", fmt.Errorf("app_id cannot be empty")
	}

	// Build base URL with app_id path parameter
	baseURL := fmt.Sprintf("https://%s/rest/self/apps/%s/sessions", endpoint, appID)

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
	if getUserAppSessionsLimit > 0 {
		q.Set("limit", fmt.Sprintf("%d", getUserAppSessionsLimit))
	}
	if getUserAppSessionsStartingAfter != "" {
		q.Set("starting_after", getUserAppSessionsStartingAfter)
	}
	if getUserAppSessionsEndingBefore != "" {
		q.Set("ending_before", getUserAppSessionsEndingBefore)
	}

	u.RawQuery = q.Encode()
	return u.String(), nil
}

func handleGetUserAppSessionsResponse(resp *http.Response, includeResp, verbose, silent bool) error {
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