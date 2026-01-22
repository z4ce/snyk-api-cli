package cmd

import (
	"fmt"
	"net/url"
	"strconv"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// GetCollectionsCmd represents the get-collections command
var GetCollectionsCmd = &cobra.Command{
	Use:   "get-collections [org_id]",
	Short: "Get collections from Snyk",
	Long: `Get collections from the Snyk API for a specific organization.

This command retrieves collections that can be used to organize and manage projects.
You can filter, sort, and paginate the results.

Examples:
  snyk-api-cli get-collections 12345678-1234-5678-9012-123456789012
  snyk-api-cli get-collections 12345678-1234-5678-9012-123456789012 --sort name --direction ASC
  snyk-api-cli get-collections 12345678-1234-5678-9012-123456789012 --name "my-collection" --is-generated=false`,
	Args: cobra.ExactArgs(1),
	RunE: runGetCollections,
}

var (
	collectionsStartingAfter string
	collectionsEndingBefore  string
	collectionsLimit         int
	collectionsSort          string
	collectionsDirection     string
	collectionsName          string
	collectionsIsGenerated   string
	collectionsVerbose       bool
	collectionsSilent        bool
	collectionsIncludeResp   bool
	collectionsUserAgent     string
)

func init() {
	// Add flags for query parameters
	GetCollectionsCmd.Flags().StringVar(&collectionsStartingAfter, "starting-after", "", "Return the page of results immediately after this cursor")
	GetCollectionsCmd.Flags().StringVar(&collectionsEndingBefore, "ending-before", "", "Return the page of results immediately before this cursor")
	GetCollectionsCmd.Flags().IntVar(&collectionsLimit, "limit", 0, "Number of results to return per page")
	GetCollectionsCmd.Flags().StringVar(&collectionsSort, "sort", "", "Return collections sorted by the specified attributes (name, projectsCount, issues)")
	GetCollectionsCmd.Flags().StringVar(&collectionsDirection, "direction", "", "Return collections sorted in the specified direction (ASC, DESC)")
	GetCollectionsCmd.Flags().StringVar(&collectionsName, "name", "", "Return collections which names include the provided string")
	GetCollectionsCmd.Flags().StringVar(&collectionsIsGenerated, "is-generated", "", "Return collections where is_generated matches the provided boolean (true, false)")

	// Add standard flags like curl command
	GetCollectionsCmd.Flags().BoolVarP(&collectionsVerbose, "verbose", "v", false, "Make the operation more talkative")
	GetCollectionsCmd.Flags().BoolVarP(&collectionsSilent, "silent", "s", false, "Silent mode")
	GetCollectionsCmd.Flags().BoolVarP(&collectionsIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	GetCollectionsCmd.Flags().StringVarP(&collectionsUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")
}

func runGetCollections(cmd *cobra.Command, args []string) error {
	orgID := args[0]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Build the URL with query parameters
	fullURL, err := buildGetCollectionsURL(endpoint, orgID, version)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	return ExecuteAPIRequest(RequestOptions{
		Method:      "GET",
		URL:         fullURL,
		Verbose:     collectionsVerbose,
		Silent:      collectionsSilent,
		IncludeResp: collectionsIncludeResp,
		UserAgent:   collectionsUserAgent,
	})
}

func buildGetCollectionsURL(endpoint, orgID, version string) (string, error) {
	// Build base URL
	baseURL := fmt.Sprintf("https://%s/rest/orgs/%s/collections", endpoint, orgID)

	// Parse URL to handle query parameters properly
	u, err := url.Parse(baseURL)
	if err != nil {
		return "", err
	}

	// Add query parameters
	q := u.Query()

	// Version is required
	q.Set("version", version)

	// Add optional parameters if provided
	if collectionsStartingAfter != "" {
		q.Set("starting_after", collectionsStartingAfter)
	}
	if collectionsEndingBefore != "" {
		q.Set("ending_before", collectionsEndingBefore)
	}
	if collectionsLimit > 0 {
		q.Set("limit", strconv.Itoa(collectionsLimit))
	}
	if collectionsSort != "" {
		q.Set("sort", collectionsSort)
	}
	if collectionsDirection != "" {
		q.Set("direction", collectionsDirection)
	}
	if collectionsName != "" {
		q.Set("name", collectionsName)
	}
	if collectionsIsGenerated != "" {
		// Parse the string to validate it's a boolean
		if collectionsIsGenerated != "true" && collectionsIsGenerated != "false" {
			return "", fmt.Errorf("is-generated must be either 'true' or 'false', got: %s", collectionsIsGenerated)
		}
		q.Set("is_generated", collectionsIsGenerated)
	}

	u.RawQuery = q.Encode()
	return u.String(), nil
}
