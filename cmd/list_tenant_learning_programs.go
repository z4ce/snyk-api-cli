package cmd

import (
	"fmt"
	"net/url"
	"strconv"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// ListTenantLearningProgramsCmd represents the list-tenant-learning-programs command
var ListTenantLearningProgramsCmd = &cobra.Command{
	Use:   "list-tenant-learning-programs [tenant_id]",
	Short: "List learning programs for a tenant from Snyk",
	Long: `List learning programs for a tenant from the Snyk API.

This command retrieves a list of learning programs for a specific tenant.
The tenant ID must be provided as a required argument.

Examples:
  snyk-api-cli list-tenant-learning-programs 12345678-1234-1234-1234-123456789012
  snyk-api-cli list-tenant-learning-programs 12345678-1234-1234-1234-123456789012 --limit 10
  snyk-api-cli list-tenant-learning-programs 12345678-1234-1234-1234-123456789012 --starting-after abc123
  snyk-api-cli list-tenant-learning-programs 12345678-1234-1234-1234-123456789012 --verbose`,
	Args: cobra.ExactArgs(1),
	RunE: runListTenantLearningPrograms,
}

var (
	listTenantLearningProgramsVerbose       bool
	listTenantLearningProgramsSilent        bool
	listTenantLearningProgramsIncludeResp   bool
	listTenantLearningProgramsUserAgent     string
	listTenantLearningProgramsStartingAfter string
	listTenantLearningProgramsEndingBefore  string
	listTenantLearningProgramsLimit         int
)

func init() {
	// Add standard flags like other commands
	ListTenantLearningProgramsCmd.Flags().BoolVarP(&listTenantLearningProgramsVerbose, "verbose", "v", false, "Make the operation more talkative")
	ListTenantLearningProgramsCmd.Flags().BoolVarP(&listTenantLearningProgramsSilent, "silent", "s", false, "Silent mode")
	ListTenantLearningProgramsCmd.Flags().BoolVarP(&listTenantLearningProgramsIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	ListTenantLearningProgramsCmd.Flags().StringVarP(&listTenantLearningProgramsUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")

	// Add pagination flags based on API spec
	ListTenantLearningProgramsCmd.Flags().StringVar(&listTenantLearningProgramsStartingAfter, "starting-after", "", "Cursor for pagination, returns results after specified point")
	ListTenantLearningProgramsCmd.Flags().StringVar(&listTenantLearningProgramsEndingBefore, "ending-before", "", "Cursor for pagination, returns results before specified point")
	ListTenantLearningProgramsCmd.Flags().IntVar(&listTenantLearningProgramsLimit, "limit", 0, "Number of results per page")
}

func runListTenantLearningPrograms(cmd *cobra.Command, args []string) error {
	tenantID := args[0]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Build the URL
	fullURL, err := buildListTenantLearningProgramsURL(endpoint, version, tenantID, listTenantLearningProgramsStartingAfter, listTenantLearningProgramsEndingBefore, listTenantLearningProgramsLimit)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	return ExecuteAPIRequest(RequestOptions{
		Method:      "GET",
		URL:         fullURL,
		Verbose:     listTenantLearningProgramsVerbose,
		Silent:      listTenantLearningProgramsSilent,
		IncludeResp: listTenantLearningProgramsIncludeResp,
		UserAgent:   listTenantLearningProgramsUserAgent,
	})
}

func buildListTenantLearningProgramsURL(endpoint, version, tenantID, startingAfter, endingBefore string, limit int) (string, error) {
	// Build base URL with tenant ID path parameter
	baseURL := fmt.Sprintf("https://%s/rest/tenants/%s/learn/learning_programs", endpoint, tenantID)

	// Parse URL to handle query parameters properly
	u, err := url.Parse(baseURL)
	if err != nil {
		return "", err
	}

	// Add query parameters
	q := u.Query()

	// Version is required
	q.Set("version", version)

	// Add pagination parameters if specified
	if startingAfter != "" {
		q.Set("starting_after", startingAfter)
	}
	if endingBefore != "" {
		q.Set("ending_before", endingBefore)
	}
	if limit > 0 {
		q.Set("limit", strconv.Itoa(limit))
	}

	u.RawQuery = q.Encode()
	return u.String(), nil
}
