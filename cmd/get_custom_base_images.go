package cmd

import (
	"fmt"
	"net/url"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// GetCustomBaseImagesCmd represents the get-custom-base-images command
var GetCustomBaseImagesCmd = &cobra.Command{
	Use:   "get-custom-base-images",
	Short: "Get custom base images from Snyk",
	Long: `Get custom base images from the Snyk API.

This command retrieves custom base images that can be used as base image recommendations.
You can filter by project, organization, group, and sort the results.

Examples:
  snyk-api-cli get-custom-base-images --project-id 12345678-1234-5678-9012-123456789012
  snyk-api-cli get-custom-base-images --org-id 12345678-1234-5678-9012-123456789012 --sort-by repository
  snyk-api-cli get-custom-base-images --group-id 12345678-1234-5678-9012-123456789012 --sort-by tag --sort-direction DESC`,
	RunE: runGetCustomBaseImages,
}

var (
	projectID                string
	orgID                    string
	groupID                  string
	sortBy                   string
	sortDirection            string
	repository               string
	tag                      string
	includeInRecommendations bool
	startingAfter            string
	endingBefore             string
	limit                    int
	getVerbose               bool
	getSilent                bool
	getIncludeResp           bool
	getUserAgent             string
)

func init() {
	// Add flags for query parameters
	GetCustomBaseImagesCmd.Flags().StringVar(&projectID, "project-id", "", "Container project ID")
	GetCustomBaseImagesCmd.Flags().StringVar(&orgID, "org-id", "", "Organization ID")
	GetCustomBaseImagesCmd.Flags().StringVar(&groupID, "group-id", "", "Group ID")
	GetCustomBaseImagesCmd.Flags().StringVar(&sortBy, "sort-by", "", "Sort column (repository, tag, version)")
	GetCustomBaseImagesCmd.Flags().StringVar(&sortDirection, "sort-direction", "", "Sort direction (ASC, DESC)")
	GetCustomBaseImagesCmd.Flags().StringVar(&repository, "repository", "", "Image repository")
	GetCustomBaseImagesCmd.Flags().StringVar(&tag, "tag", "", "Image tag")
	GetCustomBaseImagesCmd.Flags().BoolVar(&includeInRecommendations, "include-in-recommendations", false, "Recommend as base image upgrade")
	GetCustomBaseImagesCmd.Flags().StringVar(&startingAfter, "starting-after", "", "Cursor for pagination")
	GetCustomBaseImagesCmd.Flags().StringVar(&endingBefore, "ending-before", "", "Cursor for pagination")
	GetCustomBaseImagesCmd.Flags().IntVar(&limit, "limit", 0, "Number of results per page")

	// Add standard flags like curl command
	GetCustomBaseImagesCmd.Flags().BoolVarP(&getVerbose, "verbose", "v", false, "Make the operation more talkative")
	GetCustomBaseImagesCmd.Flags().BoolVarP(&getSilent, "silent", "s", false, "Silent mode")
	GetCustomBaseImagesCmd.Flags().BoolVarP(&getIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	GetCustomBaseImagesCmd.Flags().StringVarP(&getUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")
}

func runGetCustomBaseImages(cmd *cobra.Command, args []string) error {
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Build the URL with query parameters
	fullURL, err := buildGetCustomBaseImagesURL(endpoint, version)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	return ExecuteAPIRequest(RequestOptions{
		Method:      "GET",
		URL:         fullURL,
		Verbose:     getVerbose,
		Silent:      getSilent,
		IncludeResp: getIncludeResp,
		UserAgent:   getUserAgent,
	})
}

func buildGetCustomBaseImagesURL(endpoint, version string) (string, error) {
	// Build base URL
	baseURL := fmt.Sprintf("https://%s/rest/custom_base_images", endpoint)

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
	if projectID != "" {
		q.Set("project_id", projectID)
	}
	if orgID != "" {
		q.Set("org_id", orgID)
	}
	if groupID != "" {
		q.Set("group_id", groupID)
	}
	if sortBy != "" {
		q.Set("sort_by", sortBy)
	}
	if sortDirection != "" {
		q.Set("sort_direction", sortDirection)
	}
	if repository != "" {
		q.Set("repository", repository)
	}
	if tag != "" {
		q.Set("tag", tag)
	}
	if includeInRecommendations {
		q.Set("include_in_recommendations", "true")
	}
	if startingAfter != "" {
		q.Set("starting_after", startingAfter)
	}
	if endingBefore != "" {
		q.Set("ending_before", endingBefore)
	}
	if limit > 0 {
		q.Set("limit", fmt.Sprintf("%d", limit))
	}

	u.RawQuery = q.Encode()
	return u.String(), nil
}
