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

// GetAppInstallsForUserCmd represents the get-app-installs-for-user command
var GetAppInstallsForUserCmd = &cobra.Command{
	Use:   "get-app-installs-for-user",
	Short: "Get a list of Snyk Apps installed for a user",
	Long: `Get a list of Snyk Apps installed for a user from the Snyk API.

This command retrieves a list of app installations for the authenticated user,
including details about each installation and optionally expanding app information.
The results can be paginated using various query parameters.

Examples:
  snyk-api-cli get-app-installs-for-user
  snyk-api-cli get-app-installs-for-user --expand app
  snyk-api-cli get-app-installs-for-user --limit 10
  snyk-api-cli get-app-installs-for-user --starting-after abc123
  snyk-api-cli get-app-installs-for-user --ending-before xyz789
  snyk-api-cli get-app-installs-for-user --verbose`,
	Args: cobra.NoArgs,
	RunE: runGetAppInstallsForUser,
}

var (
	getAppInstallsForUserExpand        []string
	getAppInstallsForUserLimit         int
	getAppInstallsForUserStartingAfter string
	getAppInstallsForUserEndingBefore  string
	getAppInstallsForUserVerbose       bool
	getAppInstallsForUserSilent        bool
	getAppInstallsForUserIncludeResp   bool
	getAppInstallsForUserUserAgent     string
)

func init() {
	// Add flags for query parameters
	GetAppInstallsForUserCmd.Flags().StringSliceVar(&getAppInstallsForUserExpand, "expand", []string{}, "Comma-separated list of fields to expand (e.g., app)")
	GetAppInstallsForUserCmd.Flags().IntVar(&getAppInstallsForUserLimit, "limit", 0, "Number of results per page")
	GetAppInstallsForUserCmd.Flags().StringVar(&getAppInstallsForUserStartingAfter, "starting-after", "", "Cursor for pagination, returns results after this point")
	GetAppInstallsForUserCmd.Flags().StringVar(&getAppInstallsForUserEndingBefore, "ending-before", "", "Cursor for pagination, returns results before this point")

	// Add standard flags like other commands
	GetAppInstallsForUserCmd.Flags().BoolVarP(&getAppInstallsForUserVerbose, "verbose", "v", false, "Make the operation more talkative")
	GetAppInstallsForUserCmd.Flags().BoolVarP(&getAppInstallsForUserSilent, "silent", "s", false, "Silent mode")
	GetAppInstallsForUserCmd.Flags().BoolVarP(&getAppInstallsForUserIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	GetAppInstallsForUserCmd.Flags().StringVarP(&getAppInstallsForUserUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")
}

func runGetAppInstallsForUser(cmd *cobra.Command, args []string) error {
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Build the URL with query parameters
	fullURL, err := buildGetAppInstallsForUserURL(endpoint, version, cmd)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	if getAppInstallsForUserVerbose {
		fmt.Fprintf(os.Stderr, "* Requesting GET %s\n", fullURL)
	}

	// Create the HTTP request
	req, err := http.NewRequest("GET", fullURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Handle authentication with same precedence as curl: Authorization header > SNYK_TOKEN > OAuth
	if getAppInstallsForUserVerbose {
		fmt.Fprintf(os.Stderr, "* Checking authentication options\n")
	}

	authHeader, err := buildAuthHeader([]string{}) // No manual headers for this command
	if err != nil {
		if getAppInstallsForUserVerbose {
			fmt.Fprintf(os.Stderr, "* Warning: failed to get automatic auth: %v\n", err)
		}
		// Don't fail the request, just proceed without automatic auth
	} else if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
		if getAppInstallsForUserVerbose {
			fmt.Fprintf(os.Stderr, "* Added automatic authorization header\n")
		}
	} else if getAppInstallsForUserVerbose {
		fmt.Fprintf(os.Stderr, "* No automatic authorization available\n")
	}

	// Set user agent
	req.Header.Set("User-Agent", getAppInstallsForUserUserAgent)

	// Make the request
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	if getAppInstallsForUserVerbose {
		fmt.Fprintf(os.Stderr, "* Making request...\n")
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// Handle response using the same pattern as other commands
	return handleGetAppInstallsForUserResponse(resp, getAppInstallsForUserIncludeResp, getAppInstallsForUserVerbose, getAppInstallsForUserSilent)
}

func buildGetAppInstallsForUserURL(endpoint, version string, cmd *cobra.Command) (string, error) {
	// Build base URL
	baseURL := fmt.Sprintf("https://%s/rest/self/apps/installs", endpoint)

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
	if len(getAppInstallsForUserExpand) > 0 {
		// Handle expand as an array parameter
		for _, expand := range getAppInstallsForUserExpand {
			q.Add("expand", expand)
		}
	}
	if getAppInstallsForUserLimit > 0 {
		q.Set("limit", fmt.Sprintf("%d", getAppInstallsForUserLimit))
	}
	if getAppInstallsForUserStartingAfter != "" {
		q.Set("starting_after", getAppInstallsForUserStartingAfter)
	}
	if getAppInstallsForUserEndingBefore != "" {
		q.Set("ending_before", getAppInstallsForUserEndingBefore)
	}

	u.RawQuery = q.Encode()
	return u.String(), nil
}

func handleGetAppInstallsForUserResponse(resp *http.Response, includeResp, verbose, silent bool) error {
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