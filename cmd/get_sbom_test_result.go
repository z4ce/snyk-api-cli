package cmd

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// GetSbomTestResultCmd represents the get-sbom-test-result command
var GetSbomTestResultCmd = &cobra.Command{
	Use:   "get-sbom-test-result [org_id] [job_id]",
	Short: "Get an SBOM test run result from Snyk",
	Long: `Get an SBOM test run result from the Snyk API.

This command retrieves the detailed results of an SBOM test run by its job ID within an organization.
Both the organization ID and job ID must be provided as required arguments.

Required permissions: Test Projects (org.project.test)

The results include information about affected packages and vulnerabilities found in the SBOM.
Results are paginated and support cursor-based pagination.

Examples:
  snyk-api-cli get-sbom-test-result 12345678-1234-1234-1234-123456789012 87654321-4321-8765-2109-876543210987
  snyk-api-cli get-sbom-test-result 12345678-1234-1234-1234-123456789012 87654321-4321-8765-2109-876543210987 --limit 10
  snyk-api-cli get-sbom-test-result 12345678-1234-1234-1234-123456789012 87654321-4321-8765-2109-876543210987 --starting-after "abc123"
  snyk-api-cli get-sbom-test-result 12345678-1234-1234-1234-123456789012 87654321-4321-8765-2109-876543210987 --ending-before "xyz789" --limit 50
  snyk-api-cli get-sbom-test-result 12345678-1234-1234-1234-123456789012 87654321-4321-8765-2109-876543210987 --verbose`,
	Args: cobra.ExactArgs(2),
	RunE: runGetSbomTestResult,
}

var (
	getSbomTestResultLimit         int
	getSbomTestResultStartingAfter string
	getSbomTestResultEndingBefore  string
	getSbomTestResultVerbose       bool
	getSbomTestResultSilent        bool
	getSbomTestResultIncludeResp   bool
	getSbomTestResultUserAgent     string
)

func init() {
	// Add flags for pagination parameters
	GetSbomTestResultCmd.Flags().IntVar(&getSbomTestResultLimit, "limit", 0, "Number of results per page")
	GetSbomTestResultCmd.Flags().StringVar(&getSbomTestResultStartingAfter, "starting-after", "", "Cursor for pagination, returns results after this point")
	GetSbomTestResultCmd.Flags().StringVar(&getSbomTestResultEndingBefore, "ending-before", "", "Cursor for pagination, returns results before this point")

	// Add standard flags like other commands
	GetSbomTestResultCmd.Flags().BoolVarP(&getSbomTestResultVerbose, "verbose", "v", false, "Make the operation more talkative")
	GetSbomTestResultCmd.Flags().BoolVarP(&getSbomTestResultSilent, "silent", "s", false, "Silent mode")
	GetSbomTestResultCmd.Flags().BoolVarP(&getSbomTestResultIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	GetSbomTestResultCmd.Flags().StringVarP(&getSbomTestResultUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")
}

func runGetSbomTestResult(cmd *cobra.Command, args []string) error {
	orgID := args[0]
	jobID := args[1]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Build the URL
	fullURL, err := buildGetSbomTestResultURL(endpoint, version, orgID, jobID)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	return ExecuteAPIRequest(RequestOptions{
		Method:      "GET",
		URL:         fullURL,
		Verbose:     getSbomTestResultVerbose,
		Silent:      getSbomTestResultSilent,
		IncludeResp: getSbomTestResultIncludeResp,
		UserAgent:   getSbomTestResultUserAgent,
	})
}

func buildGetSbomTestResultURL(endpoint, version, orgID, jobID string) (string, error) {
	// Validate the required parameters
	if strings.TrimSpace(orgID) == "" {
		return "", fmt.Errorf("org_id cannot be empty")
	}
	if strings.TrimSpace(jobID) == "" {
		return "", fmt.Errorf("job_id cannot be empty")
	}

	// Build base URL with organization ID and job ID path parameters
	baseURL := fmt.Sprintf("https://%s/rest/orgs/%s/sbom_tests/%s/results", endpoint, orgID, jobID)

	// Parse URL to handle query parameters properly
	u, err := url.Parse(baseURL)
	if err != nil {
		return "", err
	}

	// Add query parameters
	q := u.Query()

	// Version is required
	q.Set("version", version)

	// Add optional pagination parameters if provided
	if getSbomTestResultLimit > 0 {
		q.Set("limit", fmt.Sprintf("%d", getSbomTestResultLimit))
	}
	if getSbomTestResultStartingAfter != "" {
		q.Set("starting_after", getSbomTestResultStartingAfter)
	}
	if getSbomTestResultEndingBefore != "" {
		q.Set("ending_before", getSbomTestResultEndingBefore)
	}

	u.RawQuery = q.Encode()
	return u.String(), nil
}
