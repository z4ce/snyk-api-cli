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

// GetAppInstallsForOrgCmd represents the get-app-installs-for-org command
var GetAppInstallsForOrgCmd = &cobra.Command{
	Use:   "get-app-installs-for-org [org_id]",
	Short: "Get app installations for a specific organization from Snyk",
	Long: `Get app installations for a specific organization from the Snyk API.

This command retrieves app installations that are associated with a specific organization by its ID.
The organization ID must be provided as a required argument.

Examples:
  snyk-api-cli get-app-installs-for-org 12345678-1234-1234-1234-123456789012
  snyk-api-cli get-app-installs-for-org 12345678-1234-1234-1234-123456789012 --expand app --limit 10
  snyk-api-cli get-app-installs-for-org 12345678-1234-1234-1234-123456789012 --verbose --include`,
	Args: cobra.ExactArgs(1),
	RunE: runGetAppInstallsForOrg,
}

var (
	getAppInstallsForOrgExpand          []string
	getAppInstallsForOrgStartingAfter   string
	getAppInstallsForOrgEndingBefore    string
	getAppInstallsForOrgLimit           int
	getAppInstallsForOrgVerbose         bool
	getAppInstallsForOrgSilent          bool
	getAppInstallsForOrgIncludeResp     bool
	getAppInstallsForOrgUserAgent       string
)

func init() {
	// Add flags for query parameters
	GetAppInstallsForOrgCmd.Flags().StringSliceVar(&getAppInstallsForOrgExpand, "expand", []string{}, "Expand relationships (allowed values: app)")
	GetAppInstallsForOrgCmd.Flags().StringVar(&getAppInstallsForOrgStartingAfter, "starting-after", "", "Return the page of results immediately after this cursor")
	GetAppInstallsForOrgCmd.Flags().StringVar(&getAppInstallsForOrgEndingBefore, "ending-before", "", "Return the page of results immediately before this cursor")
	GetAppInstallsForOrgCmd.Flags().IntVar(&getAppInstallsForOrgLimit, "limit", 0, "Number of results to return per page")
	
	// Add standard flags like other commands
	GetAppInstallsForOrgCmd.Flags().BoolVarP(&getAppInstallsForOrgVerbose, "verbose", "v", false, "Make the operation more talkative")
	GetAppInstallsForOrgCmd.Flags().BoolVarP(&getAppInstallsForOrgSilent, "silent", "s", false, "Silent mode")
	GetAppInstallsForOrgCmd.Flags().BoolVarP(&getAppInstallsForOrgIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	GetAppInstallsForOrgCmd.Flags().StringVarP(&getAppInstallsForOrgUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")
}

func runGetAppInstallsForOrg(cmd *cobra.Command, args []string) error {
	orgID := args[0]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Build the URL
	fullURL, err := buildGetAppInstallsForOrgURL(endpoint, version, orgID)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	if getAppInstallsForOrgVerbose {
		fmt.Fprintf(os.Stderr, "* Requesting GET %s\n", fullURL)
	}

	// Create the HTTP request
	req, err := http.NewRequest("GET", fullURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Handle authentication with same precedence as curl: Authorization header > SNYK_TOKEN > OAuth
	if getAppInstallsForOrgVerbose {
		fmt.Fprintf(os.Stderr, "* Checking authentication options\n")
	}

	authHeader, err := buildAuthHeader([]string{}) // No manual headers for this command
	if err != nil {
		if getAppInstallsForOrgVerbose {
			fmt.Fprintf(os.Stderr, "* Warning: failed to get automatic auth: %v\n", err)
		}
		// Don't fail the request, just proceed without automatic auth
	} else if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
		if getAppInstallsForOrgVerbose {
			fmt.Fprintf(os.Stderr, "* Added automatic authorization header\n")
		}
	} else if getAppInstallsForOrgVerbose {
		fmt.Fprintf(os.Stderr, "* No automatic authorization available\n")
	}

	// Set user agent
	req.Header.Set("User-Agent", getAppInstallsForOrgUserAgent)

	// Make the request
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	if getAppInstallsForOrgVerbose {
		fmt.Fprintf(os.Stderr, "* Making request...\n")
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// Handle response using the same pattern as other commands
	return handleGetAppInstallsForOrgResponse(resp, getAppInstallsForOrgIncludeResp, getAppInstallsForOrgVerbose, getAppInstallsForOrgSilent)
}

func buildGetAppInstallsForOrgURL(endpoint, version, orgID string) (string, error) {
	// Build base URL with organization ID path parameter
	baseURL := fmt.Sprintf("https://%s/rest/orgs/%s/apps/installs", endpoint, orgID)

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
	if len(getAppInstallsForOrgExpand) > 0 {
		// Handle expand as an array parameter
		for _, expand := range getAppInstallsForOrgExpand {
			q.Add("expand", expand)
		}
	}
	if getAppInstallsForOrgStartingAfter != "" {
		q.Set("starting_after", getAppInstallsForOrgStartingAfter)
	}
	if getAppInstallsForOrgEndingBefore != "" {
		q.Set("ending_before", getAppInstallsForOrgEndingBefore)
	}
	if getAppInstallsForOrgLimit > 0 {
		q.Set("limit", fmt.Sprintf("%d", getAppInstallsForOrgLimit))
	}

	u.RawQuery = q.Encode()
	return u.String(), nil
}

func handleGetAppInstallsForOrgResponse(resp *http.Response, includeResp, verbose, silent bool) error {
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