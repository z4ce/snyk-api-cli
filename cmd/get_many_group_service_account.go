package cmd

import (
	"fmt"
	"net/url"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// GetManyGroupServiceAccountCmd represents the get-many-group-service-account command
var GetManyGroupServiceAccountCmd = &cobra.Command{
	Use:   "get-many-group-service-account <group_id>",
	Short: "Get service accounts for a group",
	Long: `Get service accounts for a group from the Snyk API.

This command retrieves a list of service accounts for a specific group.
The results can be paginated using cursor-based pagination.

Examples:
  snyk-api-cli get-many-group-service-account 12345678-1234-1234-1234-123456789012
  snyk-api-cli get-many-group-service-account 12345678-1234-1234-1234-123456789012 --limit 10
  snyk-api-cli get-many-group-service-account 12345678-1234-1234-1234-123456789012 --starting-after abc123
  snyk-api-cli get-many-group-service-account 12345678-1234-1234-1234-123456789012 --ending-before xyz789
  snyk-api-cli get-many-group-service-account 12345678-1234-1234-1234-123456789012 --verbose`,
	Args: cobra.ExactArgs(1),
	RunE: runGetManyGroupServiceAccount,
}

var (
	getManyGroupServiceAccountStartingAfter string
	getManyGroupServiceAccountEndingBefore  string
	getManyGroupServiceAccountLimit         int
	getManyGroupServiceAccountVerbose       bool
	getManyGroupServiceAccountSilent        bool
	getManyGroupServiceAccountIncludeResp   bool
	getManyGroupServiceAccountUserAgent     string
)

func init() {
	// Add flags for query parameters
	GetManyGroupServiceAccountCmd.Flags().StringVar(&getManyGroupServiceAccountStartingAfter, "starting-after", "", "Cursor for pagination, returns results after this point")
	GetManyGroupServiceAccountCmd.Flags().StringVar(&getManyGroupServiceAccountEndingBefore, "ending-before", "", "Cursor for pagination, returns results before this point")
	GetManyGroupServiceAccountCmd.Flags().IntVar(&getManyGroupServiceAccountLimit, "limit", 0, "Number of results per page")

	// Add standard flags like curl command
	GetManyGroupServiceAccountCmd.Flags().BoolVarP(&getManyGroupServiceAccountVerbose, "verbose", "v", false, "Make the operation more talkative")
	GetManyGroupServiceAccountCmd.Flags().BoolVarP(&getManyGroupServiceAccountSilent, "silent", "s", false, "Silent mode")
	GetManyGroupServiceAccountCmd.Flags().BoolVarP(&getManyGroupServiceAccountIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	GetManyGroupServiceAccountCmd.Flags().StringVarP(&getManyGroupServiceAccountUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")
}

func runGetManyGroupServiceAccount(cmd *cobra.Command, args []string) error {
	groupID := args[0]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Build the URL with query parameters
	fullURL, err := buildGetManyGroupServiceAccountURL(endpoint, version, groupID)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	return ExecuteAPIRequest(RequestOptions{
		Method:      "GET",
		URL:         fullURL,
		Verbose:     getManyGroupServiceAccountVerbose,
		Silent:      getManyGroupServiceAccountSilent,
		IncludeResp: getManyGroupServiceAccountIncludeResp,
		UserAgent:   getManyGroupServiceAccountUserAgent,
	})
}

func buildGetManyGroupServiceAccountURL(endpoint, version, groupID string) (string, error) {
	// Build base URL
	baseURL := fmt.Sprintf("https://%s/rest/groups/%s/service_accounts", endpoint, groupID)

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
	if getManyGroupServiceAccountStartingAfter != "" {
		q.Set("starting_after", getManyGroupServiceAccountStartingAfter)
	}
	if getManyGroupServiceAccountEndingBefore != "" {
		q.Set("ending_before", getManyGroupServiceAccountEndingBefore)
	}
	if getManyGroupServiceAccountLimit > 0 {
		q.Set("limit", fmt.Sprintf("%d", getManyGroupServiceAccountLimit))
	}

	u.RawQuery = q.Encode()
	return u.String(), nil
}
