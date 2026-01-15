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

// GetAppInstallsForGroupCmd represents the get-app-installs-for-group command
var GetAppInstallsForGroupCmd = &cobra.Command{
	Use:   "get-app-installs-for-group [group_id]",
	Short: "Get app installations for a specific group from Snyk",
	Long: `Get app installations for a specific group from the Snyk API.

This command retrieves app installations that are associated with a specific group by its ID.
The group ID must be provided as a required argument.

Examples:
  snyk-api-cli get-app-installs-for-group 12345678-1234-1234-1234-123456789012
  snyk-api-cli get-app-installs-for-group 12345678-1234-1234-1234-123456789012 --expand app --limit 10
  snyk-api-cli get-app-installs-for-group 12345678-1234-1234-1234-123456789012 --verbose --include`,
	Args: cobra.ExactArgs(1),
	RunE: runGetAppInstallsForGroup,
}

var (
	getAppInstallsExpand          []string
	getAppInstallsStartingAfter   string
	getAppInstallsEndingBefore    string
	getAppInstallsLimit           int
	getAppInstallsVerbose         bool
	getAppInstallsSilent          bool
	getAppInstallsIncludeResp     bool
	getAppInstallsUserAgent       string
)

func init() {
	// Add flags for query parameters
	GetAppInstallsForGroupCmd.Flags().StringSliceVar(&getAppInstallsExpand, "expand", []string{}, "Expand relationships (can be used multiple times)")
	GetAppInstallsForGroupCmd.Flags().StringVar(&getAppInstallsStartingAfter, "starting-after", "", "Cursor for pagination")
	GetAppInstallsForGroupCmd.Flags().StringVar(&getAppInstallsEndingBefore, "ending-before", "", "Cursor for pagination")
	GetAppInstallsForGroupCmd.Flags().IntVar(&getAppInstallsLimit, "limit", 0, "Number of results per page")
	
	// Add standard flags like other commands
	GetAppInstallsForGroupCmd.Flags().BoolVarP(&getAppInstallsVerbose, "verbose", "v", false, "Make the operation more talkative")
	GetAppInstallsForGroupCmd.Flags().BoolVarP(&getAppInstallsSilent, "silent", "s", false, "Silent mode")
	GetAppInstallsForGroupCmd.Flags().BoolVarP(&getAppInstallsIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	GetAppInstallsForGroupCmd.Flags().StringVarP(&getAppInstallsUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")
}

func runGetAppInstallsForGroup(cmd *cobra.Command, args []string) error {
	groupID := args[0]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Build the URL
	fullURL, err := buildGetAppInstallsForGroupURL(endpoint, version, groupID)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	if getAppInstallsVerbose {
		fmt.Fprintf(os.Stderr, "* Requesting GET %s\n", fullURL)
	}

	// Create the HTTP request
	req, err := http.NewRequest("GET", fullURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Handle authentication with same precedence as curl: Authorization header > SNYK_TOKEN > OAuth
	if getAppInstallsVerbose {
		fmt.Fprintf(os.Stderr, "* Checking authentication options\n")
	}

	authHeader, err := buildAuthHeader([]string{}) // No manual headers for this command
	if err != nil {
		if getAppInstallsVerbose {
			fmt.Fprintf(os.Stderr, "* Warning: failed to get automatic auth: %v\n", err)
		}
		// Don't fail the request, just proceed without automatic auth
	} else if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
		if getAppInstallsVerbose {
			fmt.Fprintf(os.Stderr, "* Added automatic authorization header\n")
		}
	} else if getAppInstallsVerbose {
		fmt.Fprintf(os.Stderr, "* No automatic authorization available\n")
	}

	// Set user agent
	req.Header.Set("User-Agent", getAppInstallsUserAgent)

	// Make the request
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	if getAppInstallsVerbose {
		fmt.Fprintf(os.Stderr, "* Making request...\n")
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// Handle response using the same pattern as other commands
	return handleGetAppInstallsForGroupResponse(resp, getAppInstallsIncludeResp, getAppInstallsVerbose, getAppInstallsSilent)
}

func buildGetAppInstallsForGroupURL(endpoint, version, groupID string) (string, error) {
	// Build base URL with group ID path parameter
	baseURL := fmt.Sprintf("https://%s/rest/groups/%s/apps/installs", endpoint, groupID)

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
	if len(getAppInstallsExpand) > 0 {
		// Handle expand as an array parameter
		for _, expand := range getAppInstallsExpand {
			q.Add("expand", expand)
		}
	}
	if getAppInstallsStartingAfter != "" {
		q.Set("starting_after", getAppInstallsStartingAfter)
	}
	if getAppInstallsEndingBefore != "" {
		q.Set("ending_before", getAppInstallsEndingBefore)
	}
	if getAppInstallsLimit > 0 {
		q.Set("limit", fmt.Sprintf("%d", getAppInstallsLimit))
	}

	u.RawQuery = q.Encode()
	return u.String(), nil
}

func handleGetAppInstallsForGroupResponse(resp *http.Response, includeResp, verbose, silent bool) error {
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