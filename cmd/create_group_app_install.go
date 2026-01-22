package cmd

import (
	"encoding/json"
	"fmt"
	"net/url"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// CreateGroupAppInstallCmd represents the create-group-app-install command
var CreateGroupAppInstallCmd = &cobra.Command{
	Use:   "create-group-app-install [group_id]",
	Short: "Create an app installation for a specific group in Snyk",
	Long: `Create an app installation for a specific group in the Snyk API.

This command creates an app installation for a specific group by its ID.
The group ID must be provided as a required argument, and the app ID 
must be provided as a flag.

Examples:
  snyk-api-cli create-group-app-install 12345678-1234-1234-1234-123456789012 --app-id 87654321-4321-4321-4321-210987654321
  snyk-api-cli create-group-app-install 12345678-1234-1234-1234-123456789012 --app-id 87654321-4321-4321-4321-210987654321 --verbose --include`,
	Args: cobra.ExactArgs(1),
	RunE: runCreateGroupAppInstall,
}

var (
	createGroupAppInstallAppID       string
	createGroupAppInstallVerbose     bool
	createGroupAppInstallSilent      bool
	createGroupAppInstallIncludeResp bool
	createGroupAppInstallUserAgent   string
)

func init() {
	// Add flags for request body attributes
	CreateGroupAppInstallCmd.Flags().StringVar(&createGroupAppInstallAppID, "app-id", "", "App ID to install (required)")

	// Add standard flags like other commands
	CreateGroupAppInstallCmd.Flags().BoolVarP(&createGroupAppInstallVerbose, "verbose", "v", false, "Make the operation more talkative")
	CreateGroupAppInstallCmd.Flags().BoolVarP(&createGroupAppInstallSilent, "silent", "s", false, "Silent mode")
	CreateGroupAppInstallCmd.Flags().BoolVarP(&createGroupAppInstallIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	CreateGroupAppInstallCmd.Flags().StringVarP(&createGroupAppInstallUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")

	// Mark required flags
	CreateGroupAppInstallCmd.MarkFlagRequired("app-id")
}

func runCreateGroupAppInstall(cmd *cobra.Command, args []string) error {
	groupID := args[0]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Build the URL
	fullURL, err := buildCreateGroupAppInstallURL(endpoint, version, groupID)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	// Build request body
	requestBody, err := buildCreateGroupAppInstallRequestBody()
	if err != nil {
		return fmt.Errorf("failed to build request body: %w", err)
	}

	return ExecuteAPIRequest(RequestOptions{
		Method:      "POST",
		URL:         fullURL,
		Body:        requestBody,
		ContentType: "application/vnd.api+json",
		Verbose:     createGroupAppInstallVerbose,
		Silent:      createGroupAppInstallSilent,
		IncludeResp: createGroupAppInstallIncludeResp,
		UserAgent:   createGroupAppInstallUserAgent,
	})
}

func buildCreateGroupAppInstallURL(endpoint, version, groupID string) (string, error) {
	// Build base URL with group ID path parameter
	baseURL := fmt.Sprintf("https://%s/rest/groups/%s/apps/installs", endpoint, groupID)

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

func buildCreateGroupAppInstallRequestBody() (string, error) {
	// Build JSON:API format request body according to the specification
	requestData := map[string]interface{}{
		"data": map[string]interface{}{
			"type": "app_install",
			"relationships": map[string]interface{}{
				"app": map[string]interface{}{
					"data": map[string]interface{}{
						"id":   createGroupAppInstallAppID,
						"type": "app",
					},
				},
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
