package cmd

import (
	"fmt"
	"net/url"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// GetPullRequestTemplateCmd represents the get-pull-request-template command
var GetPullRequestTemplateCmd = &cobra.Command{
	Use:   "get-pull-request-template [group_id]",
	Short: "Get your groups pull request template",
	Long: `Get your groups pull request template from the Snyk API.

This command retrieves the pull request template for a specific group by its ID.
The group ID must be provided as a required argument.

Examples:
  snyk-api-cli get-pull-request-template 12345678-1234-1234-1234-123456789012
  snyk-api-cli get-pull-request-template 12345678-1234-1234-1234-123456789012 --verbose
  snyk-api-cli get-pull-request-template 12345678-1234-1234-1234-123456789012 --include`,
	Args: cobra.ExactArgs(1),
	RunE: runGetPullRequestTemplate,
}

var (
	getPullRequestTemplateVerbose     bool
	getPullRequestTemplateSilent      bool
	getPullRequestTemplateIncludeResp bool
	getPullRequestTemplateUserAgent   string
)

func init() {
	// Add standard flags like other commands
	GetPullRequestTemplateCmd.Flags().BoolVarP(&getPullRequestTemplateVerbose, "verbose", "v", false, "Make the operation more talkative")
	GetPullRequestTemplateCmd.Flags().BoolVarP(&getPullRequestTemplateSilent, "silent", "s", false, "Silent mode")
	GetPullRequestTemplateCmd.Flags().BoolVarP(&getPullRequestTemplateIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	GetPullRequestTemplateCmd.Flags().StringVarP(&getPullRequestTemplateUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")
}

func runGetPullRequestTemplate(cmd *cobra.Command, args []string) error {
	groupID := args[0]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Build the URL
	fullURL, err := buildGetPullRequestTemplateURL(endpoint, version, groupID)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	return ExecuteAPIRequest(RequestOptions{
		Method:      "GET",
		URL:         fullURL,
		Verbose:     getPullRequestTemplateVerbose,
		Silent:      getPullRequestTemplateSilent,
		IncludeResp: getPullRequestTemplateIncludeResp,
		UserAgent:   getPullRequestTemplateUserAgent,
	})
}

func buildGetPullRequestTemplateURL(endpoint, version, groupID string) (string, error) {
	// Build base URL with group ID path parameter
	baseURL := fmt.Sprintf("https://%s/rest/groups/%s/settings/pull_request_template", endpoint, groupID)

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
