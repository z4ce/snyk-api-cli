package cmd

import (
	"fmt"
	"net/url"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// GetScanCmd represents the get-scan command
var GetScanCmd = &cobra.Command{
	Use:   "get-scan [org_id] [scan_id]",
	Short: "Get details of a specific cloud scan from Snyk",
	Long: `Get details of a specific cloud scan from the Snyk API.

This command retrieves detailed information about a specific cloud scan by its ID within an organization.
Both the organization ID and scan ID must be provided as required arguments.

Examples:
  snyk-api-cli get-scan 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321
  snyk-api-cli get-scan 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321 --verbose
  snyk-api-cli get-scan 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321 --include`,
	Args: cobra.ExactArgs(2),
	RunE: runGetScan,
}

var (
	getScanVerbose     bool
	getScanSilent      bool
	getScanIncludeResp bool
	getScanUserAgent   string
)

func init() {
	// Add standard flags like other commands
	GetScanCmd.Flags().BoolVarP(&getScanVerbose, "verbose", "v", false, "Make the operation more talkative")
	GetScanCmd.Flags().BoolVarP(&getScanSilent, "silent", "s", false, "Silent mode")
	GetScanCmd.Flags().BoolVarP(&getScanIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	GetScanCmd.Flags().StringVarP(&getScanUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")
}

func runGetScan(cmd *cobra.Command, args []string) error {
	orgID := args[0]
	scanID := args[1]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Build the URL
	fullURL, err := buildGetScanURL(endpoint, version, orgID, scanID)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	return ExecuteAPIRequest(RequestOptions{
		Method:      "GET",
		URL:         fullURL,
		Verbose:     getScanVerbose,
		Silent:      getScanSilent,
		IncludeResp: getScanIncludeResp,
		UserAgent:   getScanUserAgent,
	})
}

func buildGetScanURL(endpoint, version, orgID, scanID string) (string, error) {
	// Build base URL with org ID and scan ID path parameters
	baseURL := fmt.Sprintf("https://%s/rest/orgs/%s/cloud/scans/%s", endpoint, orgID, scanID)

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
