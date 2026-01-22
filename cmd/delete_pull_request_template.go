package cmd

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// DeletePullRequestTemplateCmd represents the delete-pull-request-template command
var DeletePullRequestTemplateCmd = &cobra.Command{
	Use:   "delete-pull-request-template [group_id]",
	Short: "Delete a pull request template for a Snyk group",
	Long: `Delete a pull request template for a Snyk group from the Snyk API.

This command deletes the pull request template for a specific group using its unique identifier.
The group_id parameter is required and must be a valid UUID.

Examples:
  snyk-api-cli delete-pull-request-template 12345678-1234-5678-9012-123456789012
  snyk-api-cli delete-pull-request-template --verbose 12345678-1234-5678-9012-123456789012
  snyk-api-cli delete-pull-request-template --include 12345678-1234-5678-9012-123456789012`,
	Args: cobra.ExactArgs(1),
	RunE: runDeletePullRequestTemplate,
}

var (
	deletePullRequestTemplateVerbose     bool
	deletePullRequestTemplateSilent      bool
	deletePullRequestTemplateIncludeResp bool
	deletePullRequestTemplateUserAgent   string
)

func init() {
	// Add standard flags like curl command
	DeletePullRequestTemplateCmd.Flags().BoolVarP(&deletePullRequestTemplateVerbose, "verbose", "v", false, "Make the operation more talkative")
	DeletePullRequestTemplateCmd.Flags().BoolVarP(&deletePullRequestTemplateSilent, "silent", "s", false, "Silent mode")
	DeletePullRequestTemplateCmd.Flags().BoolVarP(&deletePullRequestTemplateIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	DeletePullRequestTemplateCmd.Flags().StringVarP(&deletePullRequestTemplateUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")
}

func runDeletePullRequestTemplate(cmd *cobra.Command, args []string) error {
	groupID := args[0]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Build the URL with the group_id path parameter
	fullURL, err := buildDeletePullRequestTemplateURL(endpoint, groupID, version)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	return ExecuteAPIRequest(RequestOptions{
		Method:      "DELETE",
		URL:         fullURL,
		Verbose:     deletePullRequestTemplateVerbose,
		Silent:      deletePullRequestTemplateSilent,
		IncludeResp: deletePullRequestTemplateIncludeResp,
		UserAgent:   deletePullRequestTemplateUserAgent,
	})
}

func buildDeletePullRequestTemplateURL(endpoint, groupID, version string) (string, error) {
	// Validate the group_id parameter
	if strings.TrimSpace(groupID) == "" {
		return "", fmt.Errorf("group_id cannot be empty")
	}

	// Build base URL with the path parameters
	baseURL := fmt.Sprintf("https://%s/rest/groups/%s/settings/pull_request_template", endpoint, groupID)

	// Parse URL to handle query parameters properly
	u, err := url.Parse(baseURL)
	if err != nil {
		return "", err
	}

	// Add required version query parameter
	q := u.Query()
	q.Set("version", version)
	u.RawQuery = q.Encode()

	return u.String(), nil
}
