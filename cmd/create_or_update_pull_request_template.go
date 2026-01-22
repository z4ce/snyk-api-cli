package cmd

import (
	"encoding/json"
	"fmt"
	"net/url"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// CreateOrUpdatePullRequestTemplateCmd represents the create-or-update-pull-request-template command
var CreateOrUpdatePullRequestTemplateCmd = &cobra.Command{
	Use:   "create-or-update-pull-request-template [group_id]",
	Short: "Create or update a pull request template for a group in Snyk",
	Long: `Create or update a pull request template for a group in the Snyk API.

This command creates or updates a pull request template by setting the title,
description, and commit message for the specified group. The group ID must be
provided as a required argument, and the template attributes must be provided as flags.

Examples:
  snyk-api-cli create-or-update-pull-request-template 7626925e-4b0f-11ee-be56-0242ac120002 --title "Security Fix" --description "This PR fixes security vulnerabilities" --commit-message "fix: address security vulnerabilities"
  snyk-api-cli create-or-update-pull-request-template 7626925e-4b0f-11ee-be56-0242ac120002 --title "Security Fix" --description "This PR fixes security vulnerabilities" --commit-message "fix: address security vulnerabilities" --verbose --include`,
	Args: cobra.ExactArgs(1),
	RunE: runCreateOrUpdatePullRequestTemplate,
}

var (
	createOrUpdatePullRequestTemplateTitle         string
	createOrUpdatePullRequestTemplateDescription   string
	createOrUpdatePullRequestTemplateCommitMessage string
	createOrUpdatePullRequestTemplateVerbose       bool
	createOrUpdatePullRequestTemplateSilent        bool
	createOrUpdatePullRequestTemplateIncludeResp   bool
	createOrUpdatePullRequestTemplateUserAgent     string
)

func init() {
	// Add flags for request body attributes
	CreateOrUpdatePullRequestTemplateCmd.Flags().StringVar(&createOrUpdatePullRequestTemplateTitle, "title", "", "Title for the pull request template (required)")
	CreateOrUpdatePullRequestTemplateCmd.Flags().StringVar(&createOrUpdatePullRequestTemplateDescription, "description", "", "Description for the pull request template (required)")
	CreateOrUpdatePullRequestTemplateCmd.Flags().StringVar(&createOrUpdatePullRequestTemplateCommitMessage, "commit-message", "", "Commit message for the pull request template (required)")

	// Add standard flags like other commands
	CreateOrUpdatePullRequestTemplateCmd.Flags().BoolVarP(&createOrUpdatePullRequestTemplateVerbose, "verbose", "v", false, "Make the operation more talkative")
	CreateOrUpdatePullRequestTemplateCmd.Flags().BoolVarP(&createOrUpdatePullRequestTemplateSilent, "silent", "s", false, "Silent mode")
	CreateOrUpdatePullRequestTemplateCmd.Flags().BoolVarP(&createOrUpdatePullRequestTemplateIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	CreateOrUpdatePullRequestTemplateCmd.Flags().StringVarP(&createOrUpdatePullRequestTemplateUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")

	// Mark required flags
	CreateOrUpdatePullRequestTemplateCmd.MarkFlagRequired("title")
	CreateOrUpdatePullRequestTemplateCmd.MarkFlagRequired("description")
	CreateOrUpdatePullRequestTemplateCmd.MarkFlagRequired("commit-message")
}

func runCreateOrUpdatePullRequestTemplate(cmd *cobra.Command, args []string) error {
	groupID := args[0]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Build the URL
	fullURL, err := buildCreateOrUpdatePullRequestTemplateURL(endpoint, version, groupID)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	// Build request body
	requestBody, err := buildCreateOrUpdatePullRequestTemplateRequestBody()
	if err != nil {
		return fmt.Errorf("failed to build request body: %w", err)
	}

	return ExecuteAPIRequest(RequestOptions{
		Method:      "POST",
		URL:         fullURL,
		Body:        requestBody,
		ContentType: "application/vnd.api+json",
		Verbose:     createOrUpdatePullRequestTemplateVerbose,
		Silent:      createOrUpdatePullRequestTemplateSilent,
		IncludeResp: createOrUpdatePullRequestTemplateIncludeResp,
		UserAgent:   createOrUpdatePullRequestTemplateUserAgent,
	})
}

func buildCreateOrUpdatePullRequestTemplateURL(endpoint, version, groupID string) (string, error) {
	// Build base URL with group ID path parameter
	baseURL := fmt.Sprintf("https://%s/rest/groups/%s/settings/pull_request_template", endpoint, groupID)

	// Parse URL to handle query parameters properly
	u, err := url.Parse(baseURL)
	if err != nil {
		return "", err
	}

	// Add version parameter
	q := u.Query()
	q.Set("version", version)
	u.RawQuery = q.Encode()

	return u.String(), nil
}

func buildCreateOrUpdatePullRequestTemplateRequestBody() (string, error) {
	// Build JSON:API format request body according to the specification
	requestData := map[string]interface{}{
		"data": map[string]interface{}{
			"type": "pull_request_template",
			"attributes": map[string]interface{}{
				"title":          createOrUpdatePullRequestTemplateTitle,
				"description":    createOrUpdatePullRequestTemplateDescription,
				"commit_message": createOrUpdatePullRequestTemplateCommitMessage,
			},
		},
	}

	// Convert to JSON
	jsonData, err := json.Marshal(requestData)
	if err != nil {
		return "", fmt.Errorf("failed to marshal request body: %w", err)
	}

	return string(jsonData), nil
}
