package cmd

import (
	"fmt"
	"net/url"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// GetAppBotsCmd represents the get-app-bots command
var GetAppBotsCmd = &cobra.Command{
	Use:   "get-app-bots [org_id]",
	Short: "Get a list of app bots authorized to an organization",
	Long: `Get a list of app bots authorized to an organization from the Snyk API.

This command retrieves app bots that are authorized to the specified organization.
You can filter and paginate the results using the available flags.

Examples:
  snyk-api-cli get-app-bots 12345678-1234-5678-9012-123456789012
  snyk-api-cli get-app-bots 12345678-1234-5678-9012-123456789012 --expand app
  snyk-api-cli get-app-bots 12345678-1234-5678-9012-123456789012 --limit 10 --starting-after cursor123`,
	Args: cobra.ExactArgs(1),
	RunE: runGetAppBots,
}

var (
	getAppBotsExpand        []string
	getAppBotsStartingAfter string
	getAppBotsEndingBefore  string
	getAppBotsLimit         int
	getAppBotsVerbose       bool
	getAppBotsSilent        bool
	getAppBotsIncludeResp   bool
	getAppBotsUserAgent     string
)

func init() {
	// Add flags for query parameters
	GetAppBotsCmd.Flags().StringSliceVar(&getAppBotsExpand, "expand", []string{}, "Expand relationships (can be used multiple times)")
	GetAppBotsCmd.Flags().StringVar(&getAppBotsStartingAfter, "starting-after", "", "Pagination cursor for next page")
	GetAppBotsCmd.Flags().StringVar(&getAppBotsEndingBefore, "ending-before", "", "Pagination cursor for previous page")
	GetAppBotsCmd.Flags().IntVar(&getAppBotsLimit, "limit", 0, "Number of results per page")

	// Add standard flags like curl command
	GetAppBotsCmd.Flags().BoolVarP(&getAppBotsVerbose, "verbose", "v", false, "Make the operation more talkative")
	GetAppBotsCmd.Flags().BoolVarP(&getAppBotsSilent, "silent", "s", false, "Silent mode")
	GetAppBotsCmd.Flags().BoolVarP(&getAppBotsIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	GetAppBotsCmd.Flags().StringVarP(&getAppBotsUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")
}

func runGetAppBots(cmd *cobra.Command, args []string) error {
	orgID := args[0]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Build the URL with query parameters
	fullURL, err := buildGetAppBotsURL(endpoint, version, orgID)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	return ExecuteAPIRequest(RequestOptions{
		Method:      "GET",
		URL:         fullURL,
		Verbose:     getAppBotsVerbose,
		Silent:      getAppBotsSilent,
		IncludeResp: getAppBotsIncludeResp,
		UserAgent:   getAppBotsUserAgent,
	})
}

func buildGetAppBotsURL(endpoint, version, orgID string) (string, error) {
	// Build base URL
	baseURL := fmt.Sprintf("https://%s/rest/orgs/%s/app_bots", endpoint, orgID)

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
	if len(getAppBotsExpand) > 0 {
		for _, expand := range getAppBotsExpand {
			q.Add("expand", expand)
		}
	}
	if getAppBotsStartingAfter != "" {
		q.Set("starting_after", getAppBotsStartingAfter)
	}
	if getAppBotsEndingBefore != "" {
		q.Set("ending_before", getAppBotsEndingBefore)
	}
	if getAppBotsLimit > 0 {
		q.Set("limit", fmt.Sprintf("%d", getAppBotsLimit))
	}

	u.RawQuery = q.Encode()
	return u.String(), nil
}
