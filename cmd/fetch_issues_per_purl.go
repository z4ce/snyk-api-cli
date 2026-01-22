package cmd

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"

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

	return ExecuteAPIRequest(RequestOptions{
		Method:      "GET",
		URL:         fullURL,
		Verbose:     fetchIssuesPerPurlVerbose,
		Silent:      fetchIssuesPerPurlSilent,
		IncludeResp: fetchIssuesPerPurlIncludeResp,
		UserAgent:   fetchIssuesPerPurlUserAgent,
	})
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
