package cmd

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// GetSbomTestStatusCmd represents the get-sbom-test-status command
var GetSbomTestStatusCmd = &cobra.Command{
	Use:   "get-sbom-test-status [org_id] [job_id]",
	Short: "Get an SBOM test run status from Snyk",
	Long: `Get an SBOM test run status from the Snyk API.

This command retrieves the status of an SBOM test run by its job ID within an organization.
Both the organization ID and job ID must be provided as required arguments.

Required permissions: Test Projects (org.project.test)

Possible status values:
- processing: The test is currently running
- error: The test encountered an error
- finished: The test completed successfully

Examples:
  snyk-api-cli get-sbom-test-status 12345678-1234-1234-1234-123456789012 87654321-4321-8765-2109-876543210987
  snyk-api-cli get-sbom-test-status 12345678-1234-1234-1234-123456789012 87654321-4321-8765-2109-876543210987 --verbose
  snyk-api-cli get-sbom-test-status 12345678-1234-1234-1234-123456789012 87654321-4321-8765-2109-876543210987 --include`,
	Args: cobra.ExactArgs(2),
	RunE: runGetSbomTestStatus,
}

var (
	getSbomTestStatusVerbose     bool
	getSbomTestStatusSilent      bool
	getSbomTestStatusIncludeResp bool
	getSbomTestStatusUserAgent   string
)

func init() {
	// Add standard flags like other commands
	GetSbomTestStatusCmd.Flags().BoolVarP(&getSbomTestStatusVerbose, "verbose", "v", false, "Make the operation more talkative")
	GetSbomTestStatusCmd.Flags().BoolVarP(&getSbomTestStatusSilent, "silent", "s", false, "Silent mode")
	GetSbomTestStatusCmd.Flags().BoolVarP(&getSbomTestStatusIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	GetSbomTestStatusCmd.Flags().StringVarP(&getSbomTestStatusUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")
}

func runGetSbomTestStatus(cmd *cobra.Command, args []string) error {
	orgID := args[0]
	jobID := args[1]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Build the URL
	fullURL, err := buildGetSbomTestStatusURL(endpoint, version, orgID, jobID)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	return ExecuteAPIRequest(RequestOptions{
		Method:      "GET",
		URL:         fullURL,
		Verbose:     getSbomTestStatusVerbose,
		Silent:      getSbomTestStatusSilent,
		IncludeResp: getSbomTestStatusIncludeResp,
		UserAgent:   getSbomTestStatusUserAgent,
	})
}

func buildGetSbomTestStatusURL(endpoint, version, orgID, jobID string) (string, error) {
	// Validate the required parameters
	if strings.TrimSpace(orgID) == "" {
		return "", fmt.Errorf("org_id cannot be empty")
	}
	if strings.TrimSpace(jobID) == "" {
		return "", fmt.Errorf("job_id cannot be empty")
	}

	// Build base URL with organization ID and job ID path parameters
	baseURL := fmt.Sprintf("https://%s/rest/orgs/%s/sbom_tests/%s", endpoint, orgID, jobID)

	// Parse URL to handle query parameters properly
	u, err := url.Parse(baseURL)
	if err != nil {
		return "", err
	}

	// Add query parameters
	q := u.Query()

	// Version is required
	q.Set("version", version)

	u.RawQuery = q.Encode()
	return u.String(), nil
}
