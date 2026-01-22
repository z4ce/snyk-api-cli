package cmd

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// GetUserAppSessionsCmd represents the get-user-app-sessions command
var GetUserAppSessionsCmd = &cobra.Command{
	Use:   "get-user-app-sessions [app_id]",
	Short: "Get a list of active OAuth sessions by app ID",
	Long: `Get a list of active OAuth sessions by app ID from the Snyk API.

This command retrieves a list of active OAuth sessions for a specific Snyk App
that the authenticated user has access to. The app_id parameter is required
and must be a valid UUID. The results can be paginated using various query parameters.

Examples:
  snyk-api-cli get-user-app-sessions 12345678-1234-5678-9012-123456789012
  snyk-api-cli get-user-app-sessions 12345678-1234-5678-9012-123456789012 --limit 10
  snyk-api-cli get-user-app-sessions 12345678-1234-5678-9012-123456789012 --starting-after abc123
  snyk-api-cli get-user-app-sessions 12345678-1234-5678-9012-123456789012 --ending-before xyz789
  snyk-api-cli get-user-app-sessions 12345678-1234-5678-9012-123456789012 --verbose`,
	Args: cobra.ExactArgs(1),
	RunE: runGetUserAppSessions,
}

var (
	getUserAppSessionsLimit         int
	getUserAppSessionsStartingAfter string
	getUserAppSessionsEndingBefore  string
	getUserAppSessionsVerbose       bool
	getUserAppSessionsSilent        bool
	getUserAppSessionsIncludeResp   bool
	getUserAppSessionsUserAgent     string
)

func init() {
	// Add flags for query parameters
	GetUserAppSessionsCmd.Flags().IntVar(&getUserAppSessionsLimit, "limit", 0, "Number of results per page")
	GetUserAppSessionsCmd.Flags().StringVar(&getUserAppSessionsStartingAfter, "starting-after", "", "Cursor for pagination, returns results after this point")
	GetUserAppSessionsCmd.Flags().StringVar(&getUserAppSessionsEndingBefore, "ending-before", "", "Cursor for pagination, returns results before this point")

	// Add standard flags like other commands
	GetUserAppSessionsCmd.Flags().BoolVarP(&getUserAppSessionsVerbose, "verbose", "v", false, "Make the operation more talkative")
	GetUserAppSessionsCmd.Flags().BoolVarP(&getUserAppSessionsSilent, "silent", "s", false, "Silent mode")
	GetUserAppSessionsCmd.Flags().BoolVarP(&getUserAppSessionsIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	GetUserAppSessionsCmd.Flags().StringVarP(&getUserAppSessionsUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")
}

func runGetUserAppSessions(cmd *cobra.Command, args []string) error {
	appID := args[0]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Build the URL with path and query parameters
	fullURL, err := buildGetUserAppSessionsURL(endpoint, version, appID, cmd)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	return ExecuteAPIRequest(RequestOptions{
		Method:      "GET",
		URL:         fullURL,
		Verbose:     getUserAppSessionsVerbose,
		Silent:      getUserAppSessionsSilent,
		IncludeResp: getUserAppSessionsIncludeResp,
		UserAgent:   getUserAppSessionsUserAgent,
	})
}

func buildGetUserAppSessionsURL(endpoint, version, appID string, cmd *cobra.Command) (string, error) {
	// Validate the required app_id parameter
	if strings.TrimSpace(appID) == "" {
		return "", fmt.Errorf("app_id cannot be empty")
	}

	// Build base URL with app_id path parameter
	baseURL := fmt.Sprintf("https://%s/rest/self/apps/%s/sessions", endpoint, appID)

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
	if getUserAppSessionsLimit > 0 {
		q.Set("limit", fmt.Sprintf("%d", getUserAppSessionsLimit))
	}
	if getUserAppSessionsStartingAfter != "" {
		q.Set("starting_after", getUserAppSessionsStartingAfter)
	}
	if getUserAppSessionsEndingBefore != "" {
		q.Set("ending_before", getUserAppSessionsEndingBefore)
	}

	u.RawQuery = q.Encode()
	return u.String(), nil
}
