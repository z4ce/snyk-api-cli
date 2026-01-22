package cmd

import (
	"fmt"
	"net/url"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// GetIacSettingsForGroupCmd represents the get-iac-settings-for-group command
var GetIacSettingsForGroupCmd = &cobra.Command{
	Use:   "get-iac-settings-for-group [group_id]",
	Short: "Get Infrastructure as Code settings for a group",
	Long: `Get Infrastructure as Code settings for a group from the Snyk API.

This command retrieves the Infrastructure as Code settings for a specific group by its ID.
The group ID must be provided as a required argument.

Examples:
  snyk-api-cli get-iac-settings-for-group 12345678-1234-1234-1234-123456789012
  snyk-api-cli get-iac-settings-for-group 12345678-1234-1234-1234-123456789012 --verbose
  snyk-api-cli get-iac-settings-for-group 12345678-1234-1234-1234-123456789012 --include`,
	Args: cobra.ExactArgs(1),
	RunE: runGetIacSettingsForGroup,
}

var (
	getIacSettingsForGroupVerbose     bool
	getIacSettingsForGroupSilent      bool
	getIacSettingsForGroupIncludeResp bool
	getIacSettingsForGroupUserAgent   string
)

func init() {
	// Add standard flags like other commands
	GetIacSettingsForGroupCmd.Flags().BoolVarP(&getIacSettingsForGroupVerbose, "verbose", "v", false, "Make the operation more talkative")
	GetIacSettingsForGroupCmd.Flags().BoolVarP(&getIacSettingsForGroupSilent, "silent", "s", false, "Silent mode")
	GetIacSettingsForGroupCmd.Flags().BoolVarP(&getIacSettingsForGroupIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	GetIacSettingsForGroupCmd.Flags().StringVarP(&getIacSettingsForGroupUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")
}

func runGetIacSettingsForGroup(cmd *cobra.Command, args []string) error {
	groupID := args[0]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Build the URL
	fullURL, err := buildGetIacSettingsForGroupURL(endpoint, version, groupID)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	return ExecuteAPIRequest(RequestOptions{
		Method:      "GET",
		URL:         fullURL,
		Verbose:     getIacSettingsForGroupVerbose,
		Silent:      getIacSettingsForGroupSilent,
		IncludeResp: getIacSettingsForGroupIncludeResp,
		UserAgent:   getIacSettingsForGroupUserAgent,
	})
}

func buildGetIacSettingsForGroupURL(endpoint, version, groupID string) (string, error) {
	// Build base URL with group ID path parameter
	baseURL := fmt.Sprintf("https://%s/rest/groups/%s/settings/iac", endpoint, groupID)

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
