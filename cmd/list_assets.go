package cmd

import (
	"encoding/json"
	"fmt"
	"net/url"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// ListAssetsCmd represents the list-assets command
var ListAssetsCmd = &cobra.Command{
	Use:   "list-assets [group_id]",
	Short: "Search for assets in a specific group from Snyk",
	Long: `Search for assets in a specific group from the Snyk API.

This command searches for assets (repositories, images, packages) within a specific group.
The group ID must be provided as a required argument. Various search filters can be
applied using flags to narrow down the results.

Examples:
  snyk-api-cli list-assets 12345678-1234-1234-1234-123456789012
  snyk-api-cli list-assets 12345678-1234-1234-1234-123456789012 --asset-type repository
  snyk-api-cli list-assets 12345678-1234-1234-1234-123456789012 --name "my-repo" --limit 10
  snyk-api-cli list-assets 12345678-1234-1234-1234-123456789012 --verbose --include`,
	Args: cobra.ExactArgs(1),
	RunE: runListAssets,
}

var (
	// Search filters
	listAssetsAssetType    string
	listAssetsName         string
	listAssetsRepository   string
	listAssetsImage        string
	listAssetsPackage      string
	listAssetsEnvironment  string
	listAssetsBusinessUnit string
	listAssetsOwner        string
	listAssetsTags         []string
	listAssetsRiskFactors  []string

	// Pagination
	listAssetsLimit         int
	listAssetsOffset        int
	listAssetsStartingAfter string
	listAssetsEndingBefore  string

	// Sorting
	listAssetsSortBy    string
	listAssetsSortOrder string

	// Standard flags
	listAssetsVerbose     bool
	listAssetsSilent      bool
	listAssetsIncludeResp bool
	listAssetsUserAgent   string
)

func init() {
	// Add flags for search filters
	ListAssetsCmd.Flags().StringVar(&listAssetsAssetType, "asset-type", "", "Filter by asset type (repository, image, package)")
	ListAssetsCmd.Flags().StringVar(&listAssetsName, "name", "", "Filter by asset name")
	ListAssetsCmd.Flags().StringVar(&listAssetsRepository, "repository", "", "Filter by repository name")
	ListAssetsCmd.Flags().StringVar(&listAssetsImage, "image", "", "Filter by image name")
	ListAssetsCmd.Flags().StringVar(&listAssetsPackage, "package", "", "Filter by package name")
	ListAssetsCmd.Flags().StringVar(&listAssetsEnvironment, "environment", "", "Filter by environment")
	ListAssetsCmd.Flags().StringVar(&listAssetsBusinessUnit, "business-unit", "", "Filter by business unit")
	ListAssetsCmd.Flags().StringVar(&listAssetsOwner, "owner", "", "Filter by owner")
	ListAssetsCmd.Flags().StringSliceVar(&listAssetsTags, "tags", []string{}, "Filter by tags (can be used multiple times)")
	ListAssetsCmd.Flags().StringSliceVar(&listAssetsRiskFactors, "risk-factors", []string{}, "Filter by risk factors (can be used multiple times)")

	// Add pagination flags
	ListAssetsCmd.Flags().IntVar(&listAssetsLimit, "limit", 0, "Number of results per page")
	ListAssetsCmd.Flags().IntVar(&listAssetsOffset, "offset", 0, "Number of results to skip")
	ListAssetsCmd.Flags().StringVar(&listAssetsStartingAfter, "starting-after", "", "Cursor for pagination, returns results after this point")
	ListAssetsCmd.Flags().StringVar(&listAssetsEndingBefore, "ending-before", "", "Cursor for pagination, returns results before this point")

	// Add sorting flags
	ListAssetsCmd.Flags().StringVar(&listAssetsSortBy, "sort-by", "", "Sort by field (name, type, created_at, updated_at)")
	ListAssetsCmd.Flags().StringVar(&listAssetsSortOrder, "sort-order", "", "Sort order (asc, desc)")

	// Add standard flags like other commands
	ListAssetsCmd.Flags().BoolVarP(&listAssetsVerbose, "verbose", "v", false, "Make the operation more talkative")
	ListAssetsCmd.Flags().BoolVarP(&listAssetsSilent, "silent", "s", false, "Silent mode")
	ListAssetsCmd.Flags().BoolVarP(&listAssetsIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	ListAssetsCmd.Flags().StringVarP(&listAssetsUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")
}

func runListAssets(cmd *cobra.Command, args []string) error {
	groupID := args[0]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Build the URL
	fullURL, err := buildListAssetsURL(endpoint, version, groupID)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	// Build request body
	requestBody, err := buildListAssetsRequestBody()
	if err != nil {
		return fmt.Errorf("failed to build request body: %w", err)
	}

	return ExecuteAPIRequest(RequestOptions{
		Method:      "POST",
		URL:         fullURL,
		Body:        requestBody,
		ContentType: "application/json",
		Verbose:     listAssetsVerbose,
		Silent:      listAssetsSilent,
		IncludeResp: listAssetsIncludeResp,
		UserAgent:   listAssetsUserAgent,
	})
}

func buildListAssetsURL(endpoint, version, groupID string) (string, error) {
	// Build base URL with group ID path parameter
	baseURL := fmt.Sprintf("https://%s/rest/groups/%s/assets/search", endpoint, groupID)

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

func buildListAssetsRequestBody() (string, error) {
	// Build request body with filters
	requestData := make(map[string]interface{})

	// Add filters if provided
	filters := make(map[string]interface{})

	if listAssetsAssetType != "" {
		filters["asset_type"] = listAssetsAssetType
	}
	if listAssetsName != "" {
		filters["name"] = listAssetsName
	}
	if listAssetsRepository != "" {
		filters["repository"] = listAssetsRepository
	}
	if listAssetsImage != "" {
		filters["image"] = listAssetsImage
	}
	if listAssetsPackage != "" {
		filters["package"] = listAssetsPackage
	}
	if listAssetsEnvironment != "" {
		filters["environment"] = listAssetsEnvironment
	}
	if listAssetsBusinessUnit != "" {
		filters["business_unit"] = listAssetsBusinessUnit
	}
	if listAssetsOwner != "" {
		filters["owner"] = listAssetsOwner
	}
	if len(listAssetsTags) > 0 {
		filters["tags"] = listAssetsTags
	}
	if len(listAssetsRiskFactors) > 0 {
		filters["risk_factors"] = listAssetsRiskFactors
	}

	if len(filters) > 0 {
		requestData["filters"] = filters
	}

	// Add pagination if provided
	pagination := make(map[string]interface{})
	if listAssetsLimit > 0 {
		pagination["limit"] = listAssetsLimit
	}
	if listAssetsOffset > 0 {
		pagination["offset"] = listAssetsOffset
	}
	if listAssetsStartingAfter != "" {
		pagination["starting_after"] = listAssetsStartingAfter
	}
	if listAssetsEndingBefore != "" {
		pagination["ending_before"] = listAssetsEndingBefore
	}

	if len(pagination) > 0 {
		requestData["pagination"] = pagination
	}

	// Add sorting if provided
	if listAssetsSortBy != "" || listAssetsSortOrder != "" {
		sort := make(map[string]interface{})
		if listAssetsSortBy != "" {
			sort["by"] = listAssetsSortBy
		}
		if listAssetsSortOrder != "" {
			sort["order"] = listAssetsSortOrder
		}
		requestData["sort"] = sort
	}

	// Convert to JSON
	jsonData, err := json.Marshal(requestData)
	if err != nil {
		return "", fmt.Errorf("failed to marshal request body: %w", err)
	}

	return string(jsonData), nil
}
