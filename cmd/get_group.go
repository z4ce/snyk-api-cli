package cmd

import (
	"fmt"
	"net/url"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// GetGroupCmd represents the get-group command
var GetGroupCmd = &cobra.Command{
	Use:   "get-group [group_id]",
	Short: "Get details of a specific group from Snyk",
	Long: `Get details of a specific group from the Snyk API.

This command retrieves detailed information about a specific group by its ID.
The group ID must be provided as a required argument.

Examples:
  snyk-api-cli get-group 12345678-1234-1234-1234-123456789012
  snyk-api-cli get-group 12345678-1234-1234-1234-123456789012 --verbose
  snyk-api-cli get-group 12345678-1234-1234-1234-123456789012 --include`,
	Args: cobra.ExactArgs(1),
	RunE: runGetGroup,
}

var (
	getGroupVerbose     bool
	getGroupSilent      bool
	getGroupIncludeResp bool
	getGroupUserAgent   string
)

func init() {
	// Add standard flags like other commands
	GetGroupCmd.Flags().BoolVarP(&getGroupVerbose, "verbose", "v", false, "Make the operation more talkative")
	GetGroupCmd.Flags().BoolVarP(&getGroupSilent, "silent", "s", false, "Silent mode")
	GetGroupCmd.Flags().BoolVarP(&getGroupIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	GetGroupCmd.Flags().StringVarP(&getGroupUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")
}

func runGetGroup(cmd *cobra.Command, args []string) error {
	groupID := args[0]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Build the URL
	fullURL, err := buildGetGroupURL(endpoint, version, groupID)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	return ExecuteAPIRequest(RequestOptions{
		Method:      "GET",
		URL:         fullURL,
		Verbose:     getGroupVerbose,
		Silent:      getGroupSilent,
		IncludeResp: getGroupIncludeResp,
		UserAgent:   getGroupUserAgent,
	})
}

func buildGetGroupURL(endpoint, version, groupID string) (string, error) {
	// Build base URL with group ID path parameter
	baseURL := fmt.Sprintf("https://%s/rest/groups/%s", endpoint, groupID)

	// Parse URL to handle query parameters properly
	u, err := url.Parse(baseURL)
	if err != nil {
		return "", err
	}

	// Add query parameters
	q := u.Query()

	// Version is required
	q.Set("version", version)

	u.RawQuery = q.Encode()
	return u.String(), nil
}
