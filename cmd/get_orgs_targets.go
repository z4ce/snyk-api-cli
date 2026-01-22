package cmd

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// GetOrgsTargetsCmd represents the get-orgs-targets command
var GetOrgsTargetsCmd = &cobra.Command{
	Use:   "get-orgs-targets [org_id]",
	Short: "Get targets by org ID from Snyk",
	Long: `Get targets by org ID from the Snyk API.

This command retrieves a list of targets within the specified organization.
The results can be filtered and paginated using various query parameters.

Required permissions: View Projects (org.project.read)

Examples:
  snyk-api-cli get-orgs-targets 12345678-1234-1234-1234-123456789012
  snyk-api-cli get-orgs-targets 12345678-1234-1234-1234-123456789012 --limit 10
  snyk-api-cli get-orgs-targets 12345678-1234-1234-1234-123456789012 --is-private true
  snyk-api-cli get-orgs-targets 12345678-1234-1234-1234-123456789012 --exclude-empty true
  snyk-api-cli get-orgs-targets 12345678-1234-1234-1234-123456789012 --url "github.com"
  snyk-api-cli get-orgs-targets 12345678-1234-1234-1234-123456789012 --source-types git,cli
  snyk-api-cli get-orgs-targets 12345678-1234-1234-1234-123456789012 --display-name "my-app"
  snyk-api-cli get-orgs-targets 12345678-1234-1234-1234-123456789012 --starting-after abc123
  snyk-api-cli get-orgs-targets 12345678-1234-1234-1234-123456789012 --ending-before xyz789
  snyk-api-cli get-orgs-targets 12345678-1234-1234-1234-123456789012 --verbose`,
	Args: cobra.ExactArgs(1),
	RunE: runGetOrgsTargets,
}

var (
	getOrgsTargetsStartingAfter string
	getOrgsTargetsEndingBefore  string
	getOrgsTargetsCount         bool
	getOrgsTargetsLimit         int
	getOrgsTargetsIsPrivate     string
	getOrgsTargetsExcludeEmpty  bool
	getOrgsTargetsURL           string
	getOrgsTargetsSourceTypes   []string
	getOrgsTargetsDisplayName   string
	getOrgsTargetsCreatedGte    string
	getOrgsTargetsVerbose       bool
	getOrgsTargetsSilent        bool
	getOrgsTargetsIncludeResp   bool
	getOrgsTargetsUserAgent     string
)

func init() {
	// Add flags for query parameters
	GetOrgsTargetsCmd.Flags().StringVar(&getOrgsTargetsStartingAfter, "starting-after", "", "Pagination cursor for results after a specific point")
	GetOrgsTargetsCmd.Flags().StringVar(&getOrgsTargetsEndingBefore, "ending-before", "", "Pagination cursor for results before a specific point")
	GetOrgsTargetsCmd.Flags().BoolVar(&getOrgsTargetsCount, "count", false, "Calculate total filtered results")
	GetOrgsTargetsCmd.Flags().IntVar(&getOrgsTargetsLimit, "limit", 0, "Number of results per page")
	GetOrgsTargetsCmd.Flags().StringVar(&getOrgsTargetsIsPrivate, "is-private", "", "Filter targets by private status (true/false)")
	GetOrgsTargetsCmd.Flags().BoolVar(&getOrgsTargetsExcludeEmpty, "exclude-empty", false, "Return only targets with projects")
	GetOrgsTargetsCmd.Flags().StringVar(&getOrgsTargetsURL, "url", "", "Filter by remote URL")
	GetOrgsTargetsCmd.Flags().StringSliceVar(&getOrgsTargetsSourceTypes, "source-types", []string{}, "Filter by source types (comma-separated)")
	GetOrgsTargetsCmd.Flags().StringVar(&getOrgsTargetsDisplayName, "display-name", "", "Filter by display name prefix")
	GetOrgsTargetsCmd.Flags().StringVar(&getOrgsTargetsCreatedGte, "created-gte", "", "Filter targets created on or after specified date (ISO 8601 format)")

	// Add standard flags like other commands
	GetOrgsTargetsCmd.Flags().BoolVarP(&getOrgsTargetsVerbose, "verbose", "v", false, "Make the operation more talkative")
	GetOrgsTargetsCmd.Flags().BoolVarP(&getOrgsTargetsSilent, "silent", "s", false, "Silent mode")
	GetOrgsTargetsCmd.Flags().BoolVarP(&getOrgsTargetsIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	GetOrgsTargetsCmd.Flags().StringVarP(&getOrgsTargetsUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")
}

func runGetOrgsTargets(cmd *cobra.Command, args []string) error {
	orgID := args[0]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Build the URL with query parameters
	fullURL, err := buildGetOrgsTargetsURL(endpoint, version, orgID, cmd)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	return ExecuteAPIRequest(RequestOptions{
		Method:      "GET",
		URL:         fullURL,
		Verbose:     getOrgsTargetsVerbose,
		Silent:      getOrgsTargetsSilent,
		IncludeResp: getOrgsTargetsIncludeResp,
		UserAgent:   getOrgsTargetsUserAgent,
	})
}

func buildGetOrgsTargetsURL(endpoint, version, orgID string, cmd *cobra.Command) (string, error) {
	// Validate the required parameters
	if strings.TrimSpace(orgID) == "" {
		return "", fmt.Errorf("org_id cannot be empty")
	}

	// Build base URL
	baseURL := fmt.Sprintf("https://%s/rest/orgs/%s/targets", endpoint, orgID)

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
	if getOrgsTargetsStartingAfter != "" {
		q.Set("starting_after", getOrgsTargetsStartingAfter)
	}
	if getOrgsTargetsEndingBefore != "" {
		q.Set("ending_before", getOrgsTargetsEndingBefore)
	}
	if getOrgsTargetsCount {
		q.Set("count", "true")
	}
	if getOrgsTargetsLimit > 0 {
		q.Set("limit", fmt.Sprintf("%d", getOrgsTargetsLimit))
	}
	if getOrgsTargetsIsPrivate != "" {
		q.Set("is_private", getOrgsTargetsIsPrivate)
	}
	if getOrgsTargetsExcludeEmpty {
		q.Set("exclude_empty", "true")
	}
	if getOrgsTargetsURL != "" {
		q.Set("url", getOrgsTargetsURL)
	}
	if len(getOrgsTargetsSourceTypes) > 0 {
		// Handle source_types as an array parameter
		for _, sourceType := range getOrgsTargetsSourceTypes {
			q.Add("source_types", sourceType)
		}
	}
	if getOrgsTargetsDisplayName != "" {
		q.Set("display_name", getOrgsTargetsDisplayName)
	}
	if getOrgsTargetsCreatedGte != "" {
		q.Set("created_gte", getOrgsTargetsCreatedGte)
	}

	u.RawQuery = q.Encode()
	return u.String(), nil
}
