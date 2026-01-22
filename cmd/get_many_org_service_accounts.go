package cmd

import (
	"fmt"
	"net/url"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// GetManyOrgServiceAccountsCmd represents the get-many-org-service-accounts command
var GetManyOrgServiceAccountsCmd = &cobra.Command{
	Use:   "get-many-org-service-accounts [org_id]",
	Short: "Get a list of organization service accounts",
	Long: `Get a list of organization service accounts from the Snyk API.

This command retrieves a list of service accounts that the authenticated user can access
within the specified organization. The results can be filtered and paginated using various
query parameters.

Required permissions: View service accounts (org.service_account.read)

Examples:
  snyk-api-cli get-many-org-service-accounts 12345678-1234-1234-1234-123456789012
  snyk-api-cli get-many-org-service-accounts 12345678-1234-1234-1234-123456789012 --limit 10
  snyk-api-cli get-many-org-service-accounts 12345678-1234-1234-1234-123456789012 --starting-after abc123
  snyk-api-cli get-many-org-service-accounts 12345678-1234-1234-1234-123456789012 --ending-before xyz789
  snyk-api-cli get-many-org-service-accounts 12345678-1234-1234-1234-123456789012 --verbose`,
	Args: cobra.ExactArgs(1),
	RunE: runGetManyOrgServiceAccounts,
}

var (
	getManyOrgServiceAccountsLimit         int
	getManyOrgServiceAccountsStartingAfter string
	getManyOrgServiceAccountsEndingBefore  string
	getManyOrgServiceAccountsVerbose       bool
	getManyOrgServiceAccountsSilent        bool
	getManyOrgServiceAccountsIncludeResp   bool
	getManyOrgServiceAccountsUserAgent     string
)

func init() {
	// Add flags for query parameters
	GetManyOrgServiceAccountsCmd.Flags().IntVar(&getManyOrgServiceAccountsLimit, "limit", 0, "Number of results per page")
	GetManyOrgServiceAccountsCmd.Flags().StringVar(&getManyOrgServiceAccountsStartingAfter, "starting-after", "", "Cursor for pagination, returns results after this point")
	GetManyOrgServiceAccountsCmd.Flags().StringVar(&getManyOrgServiceAccountsEndingBefore, "ending-before", "", "Cursor for pagination, returns results before this point")

	// Add standard flags like other commands
	GetManyOrgServiceAccountsCmd.Flags().BoolVarP(&getManyOrgServiceAccountsVerbose, "verbose", "v", false, "Make the operation more talkative")
	GetManyOrgServiceAccountsCmd.Flags().BoolVarP(&getManyOrgServiceAccountsSilent, "silent", "s", false, "Silent mode")
	GetManyOrgServiceAccountsCmd.Flags().BoolVarP(&getManyOrgServiceAccountsIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	GetManyOrgServiceAccountsCmd.Flags().StringVarP(&getManyOrgServiceAccountsUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")
}

func runGetManyOrgServiceAccounts(cmd *cobra.Command, args []string) error {
	orgID := args[0]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Build the URL with query parameters
	fullURL, err := buildGetManyOrgServiceAccountsURL(endpoint, version, orgID, cmd)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	return ExecuteAPIRequest(RequestOptions{
		Method:      "GET",
		URL:         fullURL,
		Verbose:     getManyOrgServiceAccountsVerbose,
		Silent:      getManyOrgServiceAccountsSilent,
		IncludeResp: getManyOrgServiceAccountsIncludeResp,
		UserAgent:   getManyOrgServiceAccountsUserAgent,
	})
}

func buildGetManyOrgServiceAccountsURL(endpoint, version, orgID string, cmd *cobra.Command) (string, error) {
	// Build base URL
	baseURL := fmt.Sprintf("https://%s/rest/orgs/%s/service_accounts", endpoint, orgID)

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
	if getManyOrgServiceAccountsLimit > 0 {
		q.Set("limit", fmt.Sprintf("%d", getManyOrgServiceAccountsLimit))
	}
	if getManyOrgServiceAccountsStartingAfter != "" {
		q.Set("starting_after", getManyOrgServiceAccountsStartingAfter)
	}
	if getManyOrgServiceAccountsEndingBefore != "" {
		q.Set("ending_before", getManyOrgServiceAccountsEndingBefore)
	}

	u.RawQuery = q.Encode()
	return u.String(), nil
}
