package cmd

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// ListIssuesForManyPurlsCmd represents the list-issues-for-many-purls command
var ListIssuesForManyPurlsCmd = &cobra.Command{
	Use:   "list-issues-for-many-purls [org_id]",
	Short: "List issues for a given set of packages (PURLs) in an organization",
	Long: `List issues for a given set of packages (Package URLs) in the Snyk API.

This command lists security issues for multiple packages by providing their Package URLs (PURLs).
The organization ID must be provided as a required argument, and the list of package URLs
must be provided as a flag.

Currently not available to all customers.

Package URL (PURL) supported types:
- apk, cargo, cocoapods, composer, conan, deb, gem, generic, golang, hex, maven, npm, nuget, pub, pypi, rpm, swift

Examples:
  snyk-api-cli list-issues-for-many-purls 12345678-1234-1234-1234-123456789012 --purls "pkg:npm/lodash@4.17.21,pkg:maven/org.apache.commons/commons-lang3@3.12.0"
  snyk-api-cli list-issues-for-many-purls 12345678-1234-1234-1234-123456789012 --purls "pkg:pypi/django@3.2.0" --verbose
  snyk-api-cli list-issues-for-many-purls 12345678-1234-1234-1234-123456789012 --purls "pkg:npm/react@17.0.0" --include`,
	Args: cobra.ExactArgs(1),
	RunE: runListIssuesForManyPurls,
}

var (
	listIssuesForManyPurlsPurls       []string
	listIssuesForManyPurlsType        string
	listIssuesForManyPurlsVerbose     bool
	listIssuesForManyPurlsSilent      bool
	listIssuesForManyPurlsIncludeResp bool
	listIssuesForManyPurlsUserAgent   string
)

func init() {
	// Add flags for request body attributes
	ListIssuesForManyPurlsCmd.Flags().StringSliceVar(&listIssuesForManyPurlsPurls, "purls", []string{}, "Package URLs (PURLs) to check for issues (required, comma-separated)")
	ListIssuesForManyPurlsCmd.Flags().StringVar(&listIssuesForManyPurlsType, "type", "package_issues", "Request type (default: package_issues)")

	// Add standard flags like other commands
	ListIssuesForManyPurlsCmd.Flags().BoolVarP(&listIssuesForManyPurlsVerbose, "verbose", "v", false, "Make the operation more talkative")
	ListIssuesForManyPurlsCmd.Flags().BoolVarP(&listIssuesForManyPurlsSilent, "silent", "s", false, "Silent mode")
	ListIssuesForManyPurlsCmd.Flags().BoolVarP(&listIssuesForManyPurlsIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	ListIssuesForManyPurlsCmd.Flags().StringVarP(&listIssuesForManyPurlsUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")

	// Mark required flags
	ListIssuesForManyPurlsCmd.MarkFlagRequired("purls")
}

func runListIssuesForManyPurls(cmd *cobra.Command, args []string) error {
	orgID := args[0]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Build the URL
	fullURL, err := buildListIssuesForManyPurlsURL(endpoint, version, orgID)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	// Build request body
	requestBody, err := buildListIssuesForManyPurlsRequestBody()
	if err != nil {
		return fmt.Errorf("failed to build request body: %w", err)
	}

	return ExecuteAPIRequest(RequestOptions{
		Method:      "POST",
		URL:         fullURL,
		Body:        requestBody,
		Verbose:     listIssuesForManyPurlsVerbose,
		Silent:      listIssuesForManyPurlsSilent,
		IncludeResp: listIssuesForManyPurlsIncludeResp,
		UserAgent:   listIssuesForManyPurlsUserAgent,
	})
}

func buildListIssuesForManyPurlsURL(endpoint, version, orgID string) (string, error) {
	// Validate the required parameters
	if strings.TrimSpace(orgID) == "" {
		return "", fmt.Errorf("org_id cannot be empty")
	}

	// Build base URL with organization ID path parameter
	baseURL := fmt.Sprintf("https://%s/rest/orgs/%s/packages/issues", endpoint, orgID)

	// Parse URL to handle query parameters properly
	u, err := url.Parse(baseURL)
	if err != nil {
		return "", err
	}

	// Add version parameter
	q := u.Query()
	q.Set("version", version)

	u.RawQuery = q.Encode()
	return u.String(), nil
}

func buildListIssuesForManyPurlsRequestBody() (string, error) {
	// Validate that we have PURLs
	if len(listIssuesForManyPurlsPurls) == 0 {
		return "", fmt.Errorf("at least one PURL must be provided")
	}

	// Build request body according to the API specification
	attributes := map[string]interface{}{
		"purls": listIssuesForManyPurlsPurls,
	}

	requestData := map[string]interface{}{
		"data": map[string]interface{}{
			"type":       listIssuesForManyPurlsType,
			"attributes": attributes,
		},
	}

	// Convert to JSON
	jsonData, err := json.Marshal(requestData)
	if err != nil {
		return "", fmt.Errorf("failed to marshal request body: %w", err)
	}

	return string(jsonData), nil
}
