package cmd

import (
	"fmt"
	"net/url"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// GetAssetInOrgCmd represents the get-asset-in-org command
var GetAssetInOrgCmd = &cobra.Command{
	Use:   "get-asset-in-org [org_id] [asset_id]",
	Short: "Get details of a specific asset in an organization from Snyk",
	Long: `Get details of a specific asset in an organization from the Snyk API.

This command retrieves detailed information about a specific asset by its ID within an organization.
Both the organization ID and asset ID must be provided as required arguments.

Required permissions: View Organization (org.read)

Examples:
  snyk-api-cli get-asset-in-org 12345678-1234-1234-1234-123456789012 87654321-8765-4321-8765-210987654321
  snyk-api-cli get-asset-in-org 12345678-1234-1234-1234-123456789012 87654321-8765-4321-8765-210987654321 --verbose
  snyk-api-cli get-asset-in-org 12345678-1234-1234-1234-123456789012 87654321-8765-4321-8765-210987654321 --include`,
	Args: cobra.ExactArgs(2),
	RunE: runGetAssetInOrg,
}

var (
	getAssetInOrgVerbose     bool
	getAssetInOrgSilent      bool
	getAssetInOrgIncludeResp bool
	getAssetInOrgUserAgent   string
)

func init() {
	// Add standard flags like other commands
	GetAssetInOrgCmd.Flags().BoolVarP(&getAssetInOrgVerbose, "verbose", "v", false, "Make the operation more talkative")
	GetAssetInOrgCmd.Flags().BoolVarP(&getAssetInOrgSilent, "silent", "s", false, "Silent mode")
	GetAssetInOrgCmd.Flags().BoolVarP(&getAssetInOrgIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	GetAssetInOrgCmd.Flags().StringVarP(&getAssetInOrgUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")
}

func runGetAssetInOrg(cmd *cobra.Command, args []string) error {
	orgID := args[0]
	assetID := args[1]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Build the URL
	fullURL, err := buildGetAssetInOrgURL(endpoint, version, orgID, assetID)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	return ExecuteAPIRequest(RequestOptions{
		Method:      "GET",
		URL:         fullURL,
		Verbose:     getAssetInOrgVerbose,
		Silent:      getAssetInOrgSilent,
		IncludeResp: getAssetInOrgIncludeResp,
		UserAgent:   getAssetInOrgUserAgent,
	})
}

func buildGetAssetInOrgURL(endpoint, version, orgID, assetID string) (string, error) {
	// Build base URL with organization ID and asset ID path parameters
	baseURL := fmt.Sprintf("https://%s/rest/orgs/%s/assets/%s", endpoint, orgID, assetID)

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
