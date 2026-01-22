package cmd

import (
	"encoding/json"
	"fmt"
	"net/url"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// CreateOrgAppInstallCmd represents the create-org-app-install command
var CreateOrgAppInstallCmd = &cobra.Command{
	Use:   "create-org-app-install [org_id]",
	Short: "Create an app installation for a specific organization in Snyk",
	Long: `Create an app installation for a specific organization in the Snyk API.

This command creates an app installation for a specific organization by its ID.
The organization ID must be provided as a required argument, and the app ID 
must be provided as a flag.

Examples:
  snyk-api-cli create-org-app-install 12345678-1234-1234-1234-123456789012 --app-id 87654321-4321-4321-4321-210987654321
  snyk-api-cli create-org-app-install 12345678-1234-1234-1234-123456789012 --app-id 87654321-4321-4321-4321-210987654321 --verbose --include`,
	Args: cobra.ExactArgs(1),
	RunE: runCreateOrgAppInstall,
}

var (
	createOrgAppInstallAppID       string
	createOrgAppInstallVerbose     bool
	createOrgAppInstallSilent      bool
	createOrgAppInstallIncludeResp bool
	createOrgAppInstallUserAgent   string
)

func init() {
	// Add flags for request body attributes
	CreateOrgAppInstallCmd.Flags().StringVar(&createOrgAppInstallAppID, "app-id", "", "App ID to install (required)")

	// Add standard flags like other commands
	CreateOrgAppInstallCmd.Flags().BoolVarP(&createOrgAppInstallVerbose, "verbose", "v", false, "Make the operation more talkative")
	CreateOrgAppInstallCmd.Flags().BoolVarP(&createOrgAppInstallSilent, "silent", "s", false, "Silent mode")
	CreateOrgAppInstallCmd.Flags().BoolVarP(&createOrgAppInstallIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	CreateOrgAppInstallCmd.Flags().StringVarP(&createOrgAppInstallUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")

	// Mark required flags
	CreateOrgAppInstallCmd.MarkFlagRequired("app-id")
}

func runCreateOrgAppInstall(cmd *cobra.Command, args []string) error {
	orgID := args[0]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Build the URL
	fullURL, err := buildCreateOrgAppInstallURL(endpoint, version, orgID)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	// Build request body
	requestBody, err := buildCreateOrgAppInstallRequestBody()
	if err != nil {
		return fmt.Errorf("failed to build request body: %w", err)
	}

	return ExecuteAPIRequest(RequestOptions{
		Method:      "POST",
		URL:         fullURL,
		Body:        requestBody,
		ContentType: "application/vnd.api+json",
		Verbose:     createOrgAppInstallVerbose,
		Silent:      createOrgAppInstallSilent,
		IncludeResp: createOrgAppInstallIncludeResp,
		UserAgent:   createOrgAppInstallUserAgent,
	})
}

func buildCreateOrgAppInstallURL(endpoint, version, orgID string) (string, error) {
	// Build base URL with org ID path parameter
	baseURL := fmt.Sprintf("https://%s/rest/orgs/%s/apps/installs", endpoint, orgID)

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

func buildCreateOrgAppInstallRequestBody() (string, error) {
	// Build JSON:API format request body according to the specification
	requestData := map[string]interface{}{
		"data": map[string]interface{}{
			"type": "app_install",
			"relationships": map[string]interface{}{
				"app": map[string]interface{}{
					"data": map[string]interface{}{
						"id":   createOrgAppInstallAppID,
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
