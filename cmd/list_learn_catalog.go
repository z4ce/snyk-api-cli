package cmd

import (
	"fmt"
	"net/url"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// ListLearnCatalogCmd represents the list-learn-catalog command
var ListLearnCatalogCmd = &cobra.Command{
	Use:   "list-learn-catalog",
	Short: "List learn catalog from Snyk",
	Long: `List learn catalog resources from the Snyk API.

This command retrieves a list of educational resources from the Snyk Learn catalog.
The results can be filtered by content source and paginated using cursor-based pagination.

Examples:
  snyk-api-cli list-learn-catalog
  snyk-api-cli list-learn-catalog --limit 10
  snyk-api-cli list-learn-catalog --content-source source-preview
  snyk-api-cli list-learn-catalog --starting-after abc123
  snyk-api-cli list-learn-catalog --ending-before xyz789
  snyk-api-cli list-learn-catalog --verbose`,
	RunE: runListLearnCatalog,
}

var (
	listLearnCatalogContentSource string
	listLearnCatalogLimit         int
	listLearnCatalogStartingAfter string
	listLearnCatalogEndingBefore  string
	listLearnCatalogVerbose       bool
	listLearnCatalogSilent        bool
	listLearnCatalogIncludeResp   bool
	listLearnCatalogUserAgent     string
)

func init() {
	// Add flags for query parameters
	ListLearnCatalogCmd.Flags().StringVar(&listLearnCatalogContentSource, "content-source", "", "Source of educational resources (source-preview, cache)")
	ListLearnCatalogCmd.Flags().IntVar(&listLearnCatalogLimit, "limit", 0, "Number of results per page")
	ListLearnCatalogCmd.Flags().StringVar(&listLearnCatalogStartingAfter, "starting-after", "", "Cursor for pagination, returns results after this point")
	ListLearnCatalogCmd.Flags().StringVar(&listLearnCatalogEndingBefore, "ending-before", "", "Cursor for pagination, returns results before this point")

	// Add standard flags like curl command
	ListLearnCatalogCmd.Flags().BoolVarP(&listLearnCatalogVerbose, "verbose", "v", false, "Make the operation more talkative")
	ListLearnCatalogCmd.Flags().BoolVarP(&listLearnCatalogSilent, "silent", "s", false, "Silent mode")
	ListLearnCatalogCmd.Flags().BoolVarP(&listLearnCatalogIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	ListLearnCatalogCmd.Flags().StringVarP(&listLearnCatalogUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")
}

func runListLearnCatalog(cmd *cobra.Command, args []string) error {
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Build the URL with query parameters
	fullURL, err := buildListLearnCatalogURL(endpoint, version)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	return ExecuteAPIRequest(RequestOptions{
		Method:      "GET",
		URL:         fullURL,
		Verbose:     listLearnCatalogVerbose,
		Silent:      listLearnCatalogSilent,
		IncludeResp: listLearnCatalogIncludeResp,
		UserAgent:   listLearnCatalogUserAgent,
	})
}

func buildListLearnCatalogURL(endpoint, version string) (string, error) {
	// Build base URL
	baseURL := fmt.Sprintf("https://%s/learn/catalog", endpoint)

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
	if listLearnCatalogContentSource != "" {
		q.Set("content_source", listLearnCatalogContentSource)
	}
	if listLearnCatalogLimit > 0 {
		q.Set("limit", fmt.Sprintf("%d", listLearnCatalogLimit))
	}
	if listLearnCatalogStartingAfter != "" {
		q.Set("starting_after", listLearnCatalogStartingAfter)
	}
	if listLearnCatalogEndingBefore != "" {
		q.Set("ending_before", listLearnCatalogEndingBefore)
	}

	u.RawQuery = q.Encode()
	return u.String(), nil
}
