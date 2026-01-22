package cmd

import (
	"fmt"
	"net/url"
	"strconv"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// ListResourcesCmd represents the list-resources command
var ListResourcesCmd = &cobra.Command{
	Use:   "list-resources [org_id]",
	Short: "List cloud resources for an organization",
	Long: `List cloud resources for an organization from the Snyk API.

This command retrieves a list of cloud resources that belong to the specified organization.
The results can be filtered and paginated using various query parameters.

Examples:
  snyk-api-cli list-resources 12345678-1234-1234-1234-123456789012
  snyk-api-cli list-resources 12345678-1234-1234-1234-123456789012 --limit 10
  snyk-api-cli list-resources 12345678-1234-1234-1234-123456789012 --environment-id 87654321-4321-4321-4321-210987654321
  snyk-api-cli list-resources 12345678-1234-1234-1234-123456789012 --platform aws
  snyk-api-cli list-resources 12345678-1234-1234-1234-123456789012 --resource-type ec2-instance
  snyk-api-cli list-resources 12345678-1234-1234-1234-123456789012 --name "my-resource"
  snyk-api-cli list-resources 12345678-1234-1234-1234-123456789012 --kind cloud
  snyk-api-cli list-resources 12345678-1234-1234-1234-123456789012 --location us-east-1
  snyk-api-cli list-resources 12345678-1234-1234-1234-123456789012 --removed false
  snyk-api-cli list-resources 12345678-1234-1234-1234-123456789012 --verbose`,
	Args: cobra.ExactArgs(1),
	RunE: runListResources,
}

var (
	listResourcesEnvironmentID string
	listResourcesResourceType  string
	listResourcesResourceID    string
	listResourcesNativeID      string
	listResourcesID            string
	listResourcesPlatform      string
	listResourcesName          string
	listResourcesKind          string
	listResourcesLocation      string
	listResourcesRemoved       string
	listResourcesStartingAfter string
	listResourcesEndingBefore  string
	listResourcesLimit         int
	listResourcesVerbose       bool
	listResourcesSilent        bool
	listResourcesIncludeResp   bool
	listResourcesUserAgent     string
)

func init() {
	// Add flags for query parameters
	ListResourcesCmd.Flags().StringVar(&listResourcesEnvironmentID, "environment-id", "", "Filter by environment ID (UUID)")
	ListResourcesCmd.Flags().StringVar(&listResourcesResourceType, "resource-type", "", "Filter by resource type")
	ListResourcesCmd.Flags().StringVar(&listResourcesResourceID, "resource-id", "", "Filter by resource ID")
	ListResourcesCmd.Flags().StringVar(&listResourcesNativeID, "native-id", "", "Filter by native ID/AWS ARN")
	ListResourcesCmd.Flags().StringVar(&listResourcesID, "id", "", "Filter by resource UUID")
	ListResourcesCmd.Flags().StringVar(&listResourcesPlatform, "platform", "", "Filter by platform (e.g., aws)")
	ListResourcesCmd.Flags().StringVar(&listResourcesName, "name", "", "Filter by name")
	ListResourcesCmd.Flags().StringVar(&listResourcesKind, "kind", "", "Filter by kind (e.g., cloud)")
	ListResourcesCmd.Flags().StringVar(&listResourcesLocation, "location", "", "Filter by location/region")
	ListResourcesCmd.Flags().StringVar(&listResourcesRemoved, "removed", "", "Filter by removal status (true/false)")
	ListResourcesCmd.Flags().StringVar(&listResourcesStartingAfter, "starting-after", "", "Cursor for pagination, returns results after this point")
	ListResourcesCmd.Flags().StringVar(&listResourcesEndingBefore, "ending-before", "", "Cursor for pagination, returns results before this point")
	ListResourcesCmd.Flags().IntVar(&listResourcesLimit, "limit", 0, "Number of results per page")

	// Add standard flags like other commands
	ListResourcesCmd.Flags().BoolVarP(&listResourcesVerbose, "verbose", "v", false, "Make the operation more talkative")
	ListResourcesCmd.Flags().BoolVarP(&listResourcesSilent, "silent", "s", false, "Silent mode")
	ListResourcesCmd.Flags().BoolVarP(&listResourcesIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	ListResourcesCmd.Flags().StringVarP(&listResourcesUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")
}

func runListResources(cmd *cobra.Command, args []string) error {
	orgID := args[0]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Build the URL with query parameters
	fullURL, err := buildListResourcesURL(endpoint, version, orgID, cmd)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	return ExecuteAPIRequest(RequestOptions{
		Method:      "GET",
		URL:         fullURL,
		Verbose:     listResourcesVerbose,
		Silent:      listResourcesSilent,
		IncludeResp: listResourcesIncludeResp,
		UserAgent:   listResourcesUserAgent,
	})
}

func buildListResourcesURL(endpoint, version, orgID string, cmd *cobra.Command) (string, error) {
	// Build base URL
	baseURL := fmt.Sprintf("https://%s/rest/orgs/%s/cloud/resources", endpoint, orgID)

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
	if listResourcesEnvironmentID != "" {
		q.Set("environment_id", listResourcesEnvironmentID)
	}
	if listResourcesResourceType != "" {
		q.Set("resource_type", listResourcesResourceType)
	}
	if listResourcesResourceID != "" {
		q.Set("resource_id", listResourcesResourceID)
	}
	if listResourcesNativeID != "" {
		q.Set("native_id", listResourcesNativeID)
	}
	if listResourcesID != "" {
		q.Set("id", listResourcesID)
	}
	if listResourcesPlatform != "" {
		q.Set("platform", listResourcesPlatform)
	}
	if listResourcesName != "" {
		q.Set("name", listResourcesName)
	}
	if listResourcesKind != "" {
		q.Set("kind", listResourcesKind)
	}
	if listResourcesLocation != "" {
		q.Set("location", listResourcesLocation)
	}
	if listResourcesRemoved != "" {
		q.Set("removed", listResourcesRemoved)
	}
	if listResourcesStartingAfter != "" {
		q.Set("starting_after", listResourcesStartingAfter)
	}
	if listResourcesEndingBefore != "" {
		q.Set("ending_before", listResourcesEndingBefore)
	}
	if listResourcesLimit > 0 {
		q.Set("limit", strconv.Itoa(listResourcesLimit))
	}

	u.RawQuery = q.Encode()
	return u.String(), nil
}
