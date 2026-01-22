package cmd

import (
	"fmt"
	"net/url"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// GetAssetCmd represents the get-asset command
var GetAssetCmd = &cobra.Command{
	Use:   "get-asset [group_id] [asset_id]",
	Short: "Get details of a specific asset from Snyk",
	Long: `Get details of a specific asset from the Snyk API.

This command retrieves detailed information about a specific asset by its ID within a group.
Both the group ID and asset ID must be provided as required arguments.

Required permissions: View Groups (group.read)

Examples:
  snyk-api-cli get-asset 12345678-1234-1234-1234-123456789012 87654321-8765-4321-8765-210987654321
  snyk-api-cli get-asset 12345678-1234-1234-1234-123456789012 87654321-8765-4321-8765-210987654321 --verbose
  snyk-api-cli get-asset 12345678-1234-1234-1234-123456789012 87654321-8765-4321-8765-210987654321 --include`,
	Args: cobra.ExactArgs(2),
	RunE: runGetAsset,
}

var (
	getAssetVerbose     bool
	getAssetSilent      bool
	getAssetIncludeResp bool
	getAssetUserAgent   string
)

func init() {
	// Add standard flags like other commands
	GetAssetCmd.Flags().BoolVarP(&getAssetVerbose, "verbose", "v", false, "Make the operation more talkative")
	GetAssetCmd.Flags().BoolVarP(&getAssetSilent, "silent", "s", false, "Silent mode")
	GetAssetCmd.Flags().BoolVarP(&getAssetIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	GetAssetCmd.Flags().StringVarP(&getAssetUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")
}

func runGetAsset(cmd *cobra.Command, args []string) error {
	groupID := args[0]
	assetID := args[1]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Build the URL
	fullURL, err := buildGetAssetURL(endpoint, version, groupID, assetID)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	return ExecuteAPIRequest(RequestOptions{
		Method:      "GET",
		URL:         fullURL,
		Verbose:     getAssetVerbose,
		Silent:      getAssetSilent,
		IncludeResp: getAssetIncludeResp,
		UserAgent:   getAssetUserAgent,
	})
}

func buildGetAssetURL(endpoint, version, groupID, assetID string) (string, error) {
	// Build base URL with group ID and asset ID path parameters
	baseURL := fmt.Sprintf("https://%s/rest/groups/%s/assets/%s", endpoint, groupID, assetID)

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
