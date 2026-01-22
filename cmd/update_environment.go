package cmd

import (
	"encoding/json"
	"fmt"
	"net/url"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// UpdateEnvironmentCmd represents the update-environment command
var UpdateEnvironmentCmd = &cobra.Command{
	Use:   "update-environment [org_id] [environment_id]",
	Short: "Update an environment",
	Long: `Update an environment in the Snyk API.

This command updates an environment's details by providing the organization ID
and environment ID as required arguments. The environment name can be updated
via the --name flag.

The environment-id flag specifies the environment's ID (defaults to the environment_id argument).
The type flag specifies the content type (defaults to "environment").

Examples:
  snyk-api-cli update-environment 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321 --name "Updated Environment"
  snyk-api-cli update-environment 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321 --name "New Environment Name" --verbose --include`,
	Args: cobra.ExactArgs(2),
	RunE: runUpdateEnvironment,
}

var (
	updateEnvironmentName        string
	updateEnvironmentEnvID       string
	updateEnvironmentType        string
	updateEnvironmentVerbose     bool
	updateEnvironmentSilent      bool
	updateEnvironmentIncludeResp bool
	updateEnvironmentUserAgent   string
)

func init() {
	// Add flags for request body attributes
	UpdateEnvironmentCmd.Flags().StringVar(&updateEnvironmentName, "name", "", "Environment name (required)")
	UpdateEnvironmentCmd.Flags().StringVar(&updateEnvironmentEnvID, "environment-id", "", "Environment's ID (optional, defaults to environment_id argument)")
	UpdateEnvironmentCmd.Flags().StringVar(&updateEnvironmentType, "type", "environment", "Content type for the environment (defaults to 'environment')")

	// Add standard flags like other commands
	UpdateEnvironmentCmd.Flags().BoolVarP(&updateEnvironmentVerbose, "verbose", "v", false, "Make the operation more talkative")
	UpdateEnvironmentCmd.Flags().BoolVarP(&updateEnvironmentSilent, "silent", "s", false, "Silent mode")
	UpdateEnvironmentCmd.Flags().BoolVarP(&updateEnvironmentIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	UpdateEnvironmentCmd.Flags().StringVarP(&updateEnvironmentUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")

	// Mark required flags
	UpdateEnvironmentCmd.MarkFlagRequired("name")
}

func runUpdateEnvironment(cmd *cobra.Command, args []string) error {
	orgID := args[0]
	environmentID := args[1]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Use environment ID from argument if not provided via flag
	if updateEnvironmentEnvID == "" {
		updateEnvironmentEnvID = environmentID
	}

	// Build the URL
	fullURL, err := buildUpdateEnvironmentURL(endpoint, version, orgID, environmentID)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	// Build request body
	requestBody, err := buildUpdateEnvironmentRequestBody()
	if err != nil {
		return fmt.Errorf("failed to build request body: %w", err)
	}

	return ExecuteAPIRequest(RequestOptions{
		Method:      "PATCH",
		URL:         fullURL,
		Body:        requestBody,
		Verbose:     updateEnvironmentVerbose,
		Silent:      updateEnvironmentSilent,
		IncludeResp: updateEnvironmentIncludeResp,
		UserAgent:   updateEnvironmentUserAgent,
	})
}

func buildUpdateEnvironmentURL(endpoint, version, orgID, environmentID string) (string, error) {
	// Build base URL with org ID and environment ID path parameters
	baseURL := fmt.Sprintf("https://%s/rest/orgs/%s/cloud/environments/%s", endpoint, orgID, environmentID)

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

func buildUpdateEnvironmentRequestBody() (string, error) {
	// Build JSON:API format request body according to the specification
	requestData := map[string]interface{}{
		"data": map[string]interface{}{
			"type": updateEnvironmentType,
			"id":   updateEnvironmentEnvID,
			"attributes": map[string]interface{}{
				"name":    updateEnvironmentName,
				"options": nil, // Required as per API spec but undefined
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
