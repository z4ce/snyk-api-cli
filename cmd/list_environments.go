package cmd

import (
	"fmt"
	"net/url"
	"strconv"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// ListEnvironmentsCmd represents the list-environments command
var ListEnvironmentsCmd = &cobra.Command{
	Use:   "list-environments [org_id]",
	Short: "List cloud environments for an organization",
	Long: `List cloud environments for an organization from the Snyk API.

This command retrieves a list of cloud environments that belong to the specified organization.
The results can be filtered and paginated using various query parameters.

Examples:
  snyk-api-cli list-environments 12345678-1234-1234-1234-123456789012
  snyk-api-cli list-environments 12345678-1234-1234-1234-123456789012 --limit 10
  snyk-api-cli list-environments 12345678-1234-1234-1234-123456789012 --name "prod" --name "staging"
  snyk-api-cli list-environments 12345678-1234-1234-1234-123456789012 --kind aws
  snyk-api-cli list-environments 12345678-1234-1234-1234-123456789012 --status success
  snyk-api-cli list-environments 12345678-1234-1234-1234-123456789012 --project-id 87654321-4321-4321-4321-210987654321
  snyk-api-cli list-environments 12345678-1234-1234-1234-123456789012 --created-after 2023-01-01T00:00:00Z
  snyk-api-cli list-environments 12345678-1234-1234-1234-123456789012 --verbose`,
	Args: cobra.ExactArgs(1),
	RunE: runListEnvironments,
}

var (
	listEnvCreatedAfter  string
	listEnvCreatedBefore string
	listEnvUpdatedAfter  string
	listEnvUpdatedBefore string
	listEnvName          []string
	listEnvKind          string
	listEnvStatus        string
	listEnvID            []string
	listEnvProjectID     string
	listEnvStartingAfter string
	listEnvEndingBefore  string
	listEnvLimit         int
	listEnvVerbose       bool
	listEnvSilent        bool
	listEnvIncludeResp   bool
	listEnvUserAgent     string
)

func init() {
	// Add flags for query parameters
	ListEnvironmentsCmd.Flags().StringVar(&listEnvCreatedAfter, "created-after", "", "Environments created after date (date-time)")
	ListEnvironmentsCmd.Flags().StringVar(&listEnvCreatedBefore, "created-before", "", "Environments created before date (date-time)")
	ListEnvironmentsCmd.Flags().StringVar(&listEnvUpdatedAfter, "updated-after", "", "Environments updated after date (date-time)")
	ListEnvironmentsCmd.Flags().StringVar(&listEnvUpdatedBefore, "updated-before", "", "Environments updated before date (date-time)")
	ListEnvironmentsCmd.Flags().StringSliceVar(&listEnvName, "name", []string{}, "Filter environments by name (can be used multiple times)")
	ListEnvironmentsCmd.Flags().StringVar(&listEnvKind, "kind", "", "Filter environments by kind (aws, google, azure, scm, tfc, cli)")
	ListEnvironmentsCmd.Flags().StringVar(&listEnvStatus, "status", "", "Filter by latest scan status (queued, in_progress, success, error, null)")
	ListEnvironmentsCmd.Flags().StringSliceVar(&listEnvID, "id", []string{}, "Filter by environment ID (UUID, can be used multiple times)")
	ListEnvironmentsCmd.Flags().StringVar(&listEnvProjectID, "project-id", "", "Filter by project ID (UUID)")
	ListEnvironmentsCmd.Flags().StringVar(&listEnvStartingAfter, "starting-after", "", "Cursor for pagination, returns results after this point")
	ListEnvironmentsCmd.Flags().StringVar(&listEnvEndingBefore, "ending-before", "", "Cursor for pagination, returns results before this point")
	ListEnvironmentsCmd.Flags().IntVar(&listEnvLimit, "limit", 0, "Number of results per page")

	// Add standard flags like other commands
	ListEnvironmentsCmd.Flags().BoolVarP(&listEnvVerbose, "verbose", "v", false, "Make the operation more talkative")
	ListEnvironmentsCmd.Flags().BoolVarP(&listEnvSilent, "silent", "s", false, "Silent mode")
	ListEnvironmentsCmd.Flags().BoolVarP(&listEnvIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	ListEnvironmentsCmd.Flags().StringVarP(&listEnvUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")
}

func runListEnvironments(cmd *cobra.Command, args []string) error {
	orgID := args[0]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Build the URL with query parameters
	fullURL, err := buildListEnvironmentsURL(endpoint, version, orgID, cmd)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	return ExecuteAPIRequest(RequestOptions{
		Method:      "GET",
		URL:         fullURL,
		Verbose:     listEnvVerbose,
		Silent:      listEnvSilent,
		IncludeResp: listEnvIncludeResp,
		UserAgent:   listEnvUserAgent,
	})
}

func buildListEnvironmentsURL(endpoint, version, orgID string, cmd *cobra.Command) (string, error) {
	// Build base URL
	baseURL := fmt.Sprintf("https://%s/rest/orgs/%s/cloud/environments", endpoint, orgID)

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
	if listEnvCreatedAfter != "" {
		q.Set("created_after", listEnvCreatedAfter)
	}
	if listEnvCreatedBefore != "" {
		q.Set("created_before", listEnvCreatedBefore)
	}
	if listEnvUpdatedAfter != "" {
		q.Set("updated_after", listEnvUpdatedAfter)
	}
	if listEnvUpdatedBefore != "" {
		q.Set("updated_before", listEnvUpdatedBefore)
	}
	if len(listEnvName) > 0 {
		// Handle name as an array parameter
		for _, name := range listEnvName {
			q.Add("name", name)
		}
	}
	if listEnvKind != "" {
		q.Set("kind", listEnvKind)
	}
	if listEnvStatus != "" {
		q.Set("status", listEnvStatus)
	}
	if len(listEnvID) > 0 {
		// Handle id as an array parameter
		for _, id := range listEnvID {
			q.Add("id", id)
		}
	}
	if listEnvProjectID != "" {
		q.Set("project_id", listEnvProjectID)
	}
	if listEnvStartingAfter != "" {
		q.Set("starting_after", listEnvStartingAfter)
	}
	if listEnvEndingBefore != "" {
		q.Set("ending_before", listEnvEndingBefore)
	}
	if listEnvLimit > 0 {
		q.Set("limit", strconv.Itoa(listEnvLimit))
	}

	u.RawQuery = q.Encode()
	return u.String(), nil
}
