package cmd

import (
	"fmt"
	"net/url"
	"strconv"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// ListRelatedAssetsCmd represents the list-related-assets command
var ListRelatedAssetsCmd = &cobra.Command{
	Use:   "list-related-assets [group_id] [asset_id]",
	Short: "List assets related to a specific asset in a group",
	Long: `List assets related to a specific asset in a group from the Snyk API.

This command retrieves assets that are related to a specific asset within a group.
Both the group ID and asset ID must be provided as required arguments.
Various query parameters can be used to filter and paginate the results.

Examples:
  snyk-api-cli list-related-assets 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321
  snyk-api-cli list-related-assets 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321 --limit 10
  snyk-api-cli list-related-assets 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321 --type repository
  snyk-api-cli list-related-assets 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321 --verbose --include`,
	Args: cobra.ExactArgs(2),
	RunE: runListRelatedAssets,
}

var (
	// Query parameters
	listRelatedAssetsStartingAfter string
	listRelatedAssetsEndingBefore  string
	listRelatedAssetsLimit         int
	listRelatedAssetsType          string
	
	// Standard flags
	listRelatedAssetsVerbose       bool
	listRelatedAssetsSilent        bool
	listRelatedAssetsIncludeResp   bool
	listRelatedAssetsUserAgent     string
)

func init() {
	// Add flags for query parameters
	ListRelatedAssetsCmd.Flags().StringVar(&listRelatedAssetsStartingAfter, "starting-after", "", "Cursor for pagination, return records after this position")
	ListRelatedAssetsCmd.Flags().StringVar(&listRelatedAssetsEndingBefore, "ending-before", "", "Cursor for pagination, return records before this position")
	ListRelatedAssetsCmd.Flags().IntVar(&listRelatedAssetsLimit, "limit", 0, "Number of records to return")
	ListRelatedAssetsCmd.Flags().StringVar(&listRelatedAssetsType, "type", "", "Filter by asset type (repository, package, image)")
	
	// Add standard flags like other commands
	ListRelatedAssetsCmd.Flags().BoolVarP(&listRelatedAssetsVerbose, "verbose", "v", false, "Make the operation more talkative")
	ListRelatedAssetsCmd.Flags().BoolVarP(&listRelatedAssetsSilent, "silent", "s", false, "Silent mode")
	ListRelatedAssetsCmd.Flags().BoolVarP(&listRelatedAssetsIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	ListRelatedAssetsCmd.Flags().StringVarP(&listRelatedAssetsUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")
}

func runListRelatedAssets(cmd *cobra.Command, args []string) error {
	groupID := args[0]
	assetID := args[1]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Build the URL
	fullURL, err := buildListRelatedAssetsURL(endpoint, version, groupID, assetID)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	return ExecuteAPIRequest(RequestOptions{
		Method:      "GET",
		URL:         fullURL,
		Verbose:     listRelatedAssetsVerbose,
		Silent:      listRelatedAssetsSilent,
		IncludeResp: listRelatedAssetsIncludeResp,
		UserAgent:   listRelatedAssetsUserAgent,
	})
}

func buildListRelatedAssetsURL(endpoint, version, groupID, assetID string) (string, error) {
	// Build base URL with group ID and asset ID path parameters
	baseURL := fmt.Sprintf("https://%s/rest/groups/%s/assets/%s/relationships/assets", endpoint, groupID, assetID)

	// Parse URL to handle query parameters properly
	u, err := url.Parse(baseURL)
	if err != nil {
		return "", err
	}

	// Add query parameters
	q := u.Query()
	q.Set("version", version)
	
	if listRelatedAssetsStartingAfter != "" {
		q.Set("starting_after", listRelatedAssetsStartingAfter)
	}
	if listRelatedAssetsEndingBefore != "" {
		q.Set("ending_before", listRelatedAssetsEndingBefore)
	}
	if listRelatedAssetsLimit > 0 {
		q.Set("limit", strconv.Itoa(listRelatedAssetsLimit))
	}
	if listRelatedAssetsType != "" {
		q.Set("type", listRelatedAssetsType)
	}
	
	u.RawQuery = q.Encode()

	return u.String(), nil
}
