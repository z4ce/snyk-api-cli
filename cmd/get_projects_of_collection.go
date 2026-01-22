package cmd

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// GetProjectsOfCollectionCmd represents the get-projects-of-collection command
var GetProjectsOfCollectionCmd = &cobra.Command{
	Use:   "get-projects-of-collection [org_id] [collection_id]",
	Short: "Get projects of a collection from Snyk",
	Long: `Get projects that belong to a specific collection from the Snyk API.

This command retrieves projects associated with a collection within an organization.
You can filter, sort, and paginate the results using various query parameters.

Examples:
  snyk-api-cli get-projects-of-collection 12345678-1234-5678-9012-123456789012 87654321-4321-8765-2109-876543210987
  snyk-api-cli get-projects-of-collection 12345678-1234-5678-9012-123456789012 87654321-4321-8765-2109-876543210987 --sort imported --direction ASC
  snyk-api-cli get-projects-of-collection 12345678-1234-5678-9012-123456789012 87654321-4321-8765-2109-876543210987 --limit 10 --show vuln-groups`,
	Args: cobra.ExactArgs(2),
	RunE: runGetProjectsOfCollection,
}

var (
	projectsStartingAfter string
	projectsEndingBefore  string
	projectsLimit         int
	projectsSort          string
	projectsDirection     string
	projectsTargetIds     []string
	projectsShow          []string
	projectsIntegration   []string
	projectsVerbose       bool
	projectsSilent        bool
	projectsIncludeResp   bool
	projectsUserAgent     string
)

func init() {
	// Add flags for query parameters
	GetProjectsOfCollectionCmd.Flags().StringVar(&projectsStartingAfter, "starting-after", "", "Return the page of results immediately after this cursor")
	GetProjectsOfCollectionCmd.Flags().StringVar(&projectsEndingBefore, "ending-before", "", "Return the page of results immediately before this cursor")
	GetProjectsOfCollectionCmd.Flags().IntVar(&projectsLimit, "limit", 0, "Number of results to return per page")
	GetProjectsOfCollectionCmd.Flags().StringVar(&projectsSort, "sort", "", "Return projects sorted by the specified attribute (imported, last_tested_at, issues)")
	GetProjectsOfCollectionCmd.Flags().StringVar(&projectsDirection, "direction", "", "Return projects sorted in the specified direction (ASC, DESC)")
	GetProjectsOfCollectionCmd.Flags().StringSliceVar(&projectsTargetIds, "target-id", []string{}, "Return projects that belong to the provided targets (can be used multiple times)")
	GetProjectsOfCollectionCmd.Flags().StringSliceVar(&projectsShow, "show", []string{}, "Additional data to show (vuln-groups, clean-groups) (can be used multiple times)")
	GetProjectsOfCollectionCmd.Flags().StringSliceVar(&projectsIntegration, "integration", []string{}, "Filter by integration type (can be used multiple times)")

	// Add standard flags like curl command
	GetProjectsOfCollectionCmd.Flags().BoolVarP(&projectsVerbose, "verbose", "v", false, "Make the operation more talkative")
	GetProjectsOfCollectionCmd.Flags().BoolVarP(&projectsSilent, "silent", "s", false, "Silent mode")
	GetProjectsOfCollectionCmd.Flags().BoolVarP(&projectsIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	GetProjectsOfCollectionCmd.Flags().StringVarP(&projectsUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")
}

func runGetProjectsOfCollection(cmd *cobra.Command, args []string) error {
	orgID := args[0]
	collectionID := args[1]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Build the URL with query parameters
	fullURL, err := buildGetProjectsOfCollectionURL(endpoint, orgID, collectionID, version)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	return ExecuteAPIRequest(RequestOptions{
		Method:      "GET",
		URL:         fullURL,
		Verbose:     projectsVerbose,
		Silent:      projectsSilent,
		IncludeResp: projectsIncludeResp,
		UserAgent:   projectsUserAgent,
	})
}

func buildGetProjectsOfCollectionURL(endpoint, orgID, collectionID, version string) (string, error) {
	// Build base URL
	baseURL := fmt.Sprintf("https://%s/rest/orgs/%s/collections/%s/relationships/projects", endpoint, orgID, collectionID)

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
	if projectsStartingAfter != "" {
		q.Set("starting_after", projectsStartingAfter)
	}
	if projectsEndingBefore != "" {
		q.Set("ending_before", projectsEndingBefore)
	}
	if projectsLimit > 0 {
		q.Set("limit", strconv.Itoa(projectsLimit))
	}
	if projectsSort != "" {
		// Validate sort parameter
		validSorts := []string{"imported", "last_tested_at", "issues"}
		if !containsString(validSorts, projectsSort) {
			return "", fmt.Errorf("invalid sort parameter: %s, must be one of: %s", projectsSort, strings.Join(validSorts, ", "))
		}
		q.Set("sort", projectsSort)
	}
	if projectsDirection != "" {
		// Validate direction parameter
		validDirections := []string{"ASC", "DESC"}
		if !containsString(validDirections, projectsDirection) {
			return "", fmt.Errorf("invalid direction parameter: %s, must be one of: %s", projectsDirection, strings.Join(validDirections, ", "))
		}
		q.Set("direction", projectsDirection)
	}

	// Handle array parameters
	if len(projectsTargetIds) > 0 {
		for _, targetID := range projectsTargetIds {
			q.Add("target_id", targetID)
		}
	}
	if len(projectsShow) > 0 {
		// Validate show parameters
		validShows := []string{"vuln-groups", "clean-groups"}
		for _, show := range projectsShow {
			if !containsString(validShows, show) {
				return "", fmt.Errorf("invalid show parameter: %s, must be one of: %s", show, strings.Join(validShows, ", "))
			}
		}
		for _, show := range projectsShow {
			q.Add("show", show)
		}
	}
	if len(projectsIntegration) > 0 {
		for _, integration := range projectsIntegration {
			q.Add("integration", integration)
		}
	}

	u.RawQuery = q.Encode()
	return u.String(), nil
}
