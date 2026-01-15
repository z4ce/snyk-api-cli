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

// ListTenantsCmd represents the list-tenants command
var ListTenantsCmd = &cobra.Command{
	Use:   "list-tenants",
	Short: "Get a list of all accessible tenants from Snyk",
	Long: `Get a list of all accessible tenants from the Snyk API.

This command retrieves a list of all tenants that the authenticated user has access to.
It supports pagination through cursor-based pagination and allows filtering results.

Examples:
  snyk-api-cli list-tenants
  snyk-api-cli list-tenants --limit 10
  snyk-api-cli list-tenants --starting-after abc123
  snyk-api-cli list-tenants --ending-before xyz789
  snyk-api-cli list-tenants --verbose`,
	RunE: runListTenants,
}

var (
	listTenantsVerbose       bool
	listTenantsSilent        bool
	listTenantsIncludeResp   bool
	listTenantsUserAgent     string
	listTenantsStartingAfter string
	listTenantsEndingBefore  string
	listTenantsLimit         int
)

func init() {
	// Add standard flags like other commands
	ListTenantsCmd.Flags().BoolVarP(&listTenantsVerbose, "verbose", "v", false, "Make the operation more talkative")
	ListTenantsCmd.Flags().BoolVarP(&listTenantsSilent, "silent", "s", false, "Silent mode")
	ListTenantsCmd.Flags().BoolVarP(&listTenantsIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	ListTenantsCmd.Flags().StringVarP(&listTenantsUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")
	
	// Add pagination flags based on API spec
	ListTenantsCmd.Flags().StringVar(&listTenantsStartingAfter, "starting-after", "", "Cursor for pagination, returns results after specified point")
	ListTenantsCmd.Flags().StringVar(&listTenantsEndingBefore, "ending-before", "", "Cursor for pagination, returns results before specified point")
	ListTenantsCmd.Flags().IntVar(&listTenantsLimit, "limit", 0, "Number of results per page")
}

func runListTenants(cmd *cobra.Command, args []string) error {
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Build the URL
	fullURL, err := buildListTenantsURL(endpoint, version, listTenantsStartingAfter, listTenantsEndingBefore, listTenantsLimit)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	if listTenantsVerbose {
		fmt.Fprintf(os.Stderr, "* Requesting GET %s\n", fullURL)
	}

	// Create the HTTP request
	req, err := http.NewRequest("GET", fullURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Handle authentication with same precedence as curl: Authorization header > SNYK_TOKEN > OAuth
	if listTenantsVerbose {
		fmt.Fprintf(os.Stderr, "* Checking authentication options\n")
	}

	authHeader, err := buildAuthHeader([]string{}) // No manual headers for this command
	if err != nil {
		if listTenantsVerbose {
			fmt.Fprintf(os.Stderr, "* Warning: failed to get automatic auth: %v\n", err)
		}
		// Don't fail the request, just proceed without automatic auth
	} else if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
		if listTenantsVerbose {
			fmt.Fprintf(os.Stderr, "* Added automatic authorization header\n")
		}
	} else if listTenantsVerbose {
		fmt.Fprintf(os.Stderr, "* No automatic authorization available\n")
	}

	// Set user agent
	req.Header.Set("User-Agent", listTenantsUserAgent)

	// Make the request
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	if listTenantsVerbose {
		fmt.Fprintf(os.Stderr, "* Making request...\n")
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// Handle response using the same pattern as other commands
	return handleListTenantsResponse(resp, listTenantsIncludeResp, listTenantsVerbose, listTenantsSilent)
}

func buildListTenantsURL(endpoint, version, startingAfter, endingBefore string, limit int) (string, error) {
	// Build base URL
	baseURL := fmt.Sprintf("https://%s/rest/tenants", endpoint)

	// Parse URL to handle query parameters properly
	u, err := url.Parse(baseURL)
	if err != nil {
		return "", err
	}

	// Add query parameters
	q := u.Query()

	// Version is required
	q.Set("version", version)

	// Add pagination parameters if specified
	if startingAfter != "" {
		q.Set("starting_after", startingAfter)
	}
	if endingBefore != "" {
		q.Set("ending_before", endingBefore)
	}
	if limit > 0 {
		q.Set("limit", strconv.Itoa(limit))
	}

	u.RawQuery = q.Encode()
	return u.String(), nil
}

func handleListTenantsResponse(resp *http.Response, includeResp, verbose, silent bool) error {
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