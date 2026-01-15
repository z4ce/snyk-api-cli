package cmd

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// FetchIssuesPerPurlCmd represents the fetch-issues-per-purl command
var FetchIssuesPerPurlCmd = &cobra.Command{
	Use:   "fetch-issues-per-purl [org_id] [purl]",
	Short: "Fetch issues for a specific package (PURL) in an organization",
	Long: `Fetch security issues for a specific package by its Package URL (PURL) in the Snyk API.

This command retrieves security issues for a specific package by providing its Package URL (PURL).
Both the organization ID and the Package URL must be provided as required arguments.

Package URL (PURL) supported types:
- apk, cargo, cocoapods, composer, conan, deb, gem, generic, golang, hex, maven, npm, nuget, pub, pypi, rpm, swift

Required permissions: View Organization (org.read)

Examples:
  snyk-api-cli fetch-issues-per-purl 12345678-1234-1234-1234-123456789012 "pkg:npm/lodash@4.17.21"
  snyk-api-cli fetch-issues-per-purl 12345678-1234-1234-1234-123456789012 "pkg:maven/org.apache.commons/commons-lang3@3.12.0" --verbose
  snyk-api-cli fetch-issues-per-purl 12345678-1234-1234-1234-123456789012 "pkg:pypi/django@3.2.0" --limit 100 --offset 0 --include`,
	Args: cobra.ExactArgs(2),
	RunE: runFetchIssuesPerPurl,
}

var (
	fetchIssuesPerPurlOffset      int
	fetchIssuesPerPurlLimit       int
	fetchIssuesPerPurlVerbose     bool
	fetchIssuesPerPurlSilent      bool
	fetchIssuesPerPurlIncludeResp bool
	fetchIssuesPerPurlUserAgent   string
)

func init() {
	// Add query parameter flags
	FetchIssuesPerPurlCmd.Flags().IntVar(&fetchIssuesPerPurlOffset, "offset", 0, "Number of results to skip before returning results (default: 0)")
	FetchIssuesPerPurlCmd.Flags().IntVar(&fetchIssuesPerPurlLimit, "limit", 1000, "Maximum number of results to return (default: 1000, max: 1000)")

	// Add standard flags like other commands
	FetchIssuesPerPurlCmd.Flags().BoolVarP(&fetchIssuesPerPurlVerbose, "verbose", "v", false, "Make the operation more talkative")
	FetchIssuesPerPurlCmd.Flags().BoolVarP(&fetchIssuesPerPurlSilent, "silent", "s", false, "Silent mode")
	FetchIssuesPerPurlCmd.Flags().BoolVarP(&fetchIssuesPerPurlIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	FetchIssuesPerPurlCmd.Flags().StringVarP(&fetchIssuesPerPurlUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")
}

func runFetchIssuesPerPurl(cmd *cobra.Command, args []string) error {
	orgID := args[0]
	purl := args[1]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Validate limit parameter
	if fetchIssuesPerPurlLimit <= 0 || fetchIssuesPerPurlLimit > 1000 {
		return fmt.Errorf("limit must be greater than 0 and less than or equal to 1000")
	}

	// Validate offset parameter
	if fetchIssuesPerPurlOffset < 0 {
		return fmt.Errorf("offset must be greater than or equal to 0")
	}

	// Build the URL
	fullURL, err := buildFetchIssuesPerPurlURL(endpoint, version, orgID, purl)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	if fetchIssuesPerPurlVerbose {
		fmt.Fprintf(os.Stderr, "* Requesting GET %s\n", fullURL)
	}

	// Create the HTTP request
	req, err := http.NewRequest("GET", fullURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Handle authentication with same precedence as curl: Authorization header > SNYK_TOKEN > OAuth
	if fetchIssuesPerPurlVerbose {
		fmt.Fprintf(os.Stderr, "* Checking authentication options\n")
	}

	authHeader, err := buildAuthHeader([]string{}) // No manual headers for this command
	if err != nil {
		if fetchIssuesPerPurlVerbose {
			fmt.Fprintf(os.Stderr, "* Warning: failed to get automatic auth: %v\n", err)
		}
		// Don't fail the request, just proceed without automatic auth
	} else if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
		if fetchIssuesPerPurlVerbose {
			fmt.Fprintf(os.Stderr, "* Added automatic authorization header\n")
		}
	} else if fetchIssuesPerPurlVerbose {
		fmt.Fprintf(os.Stderr, "* No automatic authorization available\n")
	}

	// Set user agent
	req.Header.Set("User-Agent", fetchIssuesPerPurlUserAgent)

	// Make the request
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	if fetchIssuesPerPurlVerbose {
		fmt.Fprintf(os.Stderr, "* Making request...\n")
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// Handle response using the same pattern as other commands
	return handleFetchIssuesPerPurlResponse(resp, fetchIssuesPerPurlIncludeResp, fetchIssuesPerPurlVerbose, fetchIssuesPerPurlSilent)
}

func buildFetchIssuesPerPurlURL(endpoint, version, orgID, purl string) (string, error) {
	// Validate the required parameters
	if strings.TrimSpace(orgID) == "" {
		return "", fmt.Errorf("org_id cannot be empty")
	}
	if strings.TrimSpace(purl) == "" {
		return "", fmt.Errorf("purl cannot be empty")
	}

	// URL encode the PURL since it contains special characters
	encodedPurl := url.PathEscape(purl)

	// Build base URL with organization ID and PURL path parameters
	baseURL := fmt.Sprintf("https://%s/rest/orgs/%s/packages/%s/issues", endpoint, orgID, encodedPurl)

	// Parse URL to handle query parameters properly
	u, err := url.Parse(baseURL)
	if err != nil {
		return "", err
	}

	// Add query parameters
	q := u.Query()

	// Version is required
	q.Set("version", version)

	// Add optional query parameters with their default values
	if fetchIssuesPerPurlOffset > 0 {
		q.Set("offset", strconv.Itoa(fetchIssuesPerPurlOffset))
	}

	if fetchIssuesPerPurlLimit != 1000 {
		q.Set("limit", strconv.Itoa(fetchIssuesPerPurlLimit))
	}

	u.RawQuery = q.Encode()
	return u.String(), nil
}

func handleFetchIssuesPerPurlResponse(resp *http.Response, includeResp, verbose, silent bool) error {
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