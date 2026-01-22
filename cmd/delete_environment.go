package cmd

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// DeleteEnvironmentCmd represents the delete-environment command
var DeleteEnvironmentCmd = &cobra.Command{
	Use:   "delete-environment [org_id] [environment_id]",
	Short: "Delete an environment from Snyk",
	Long: `Delete an environment from the Snyk API.

This command deletes a specific environment using its unique identifier within an organization.
Both org_id and environment_id parameters are required and must be valid UUIDs.

Examples:
  snyk-api-cli delete-environment 12345678-1234-5678-9012-123456789012 87654321-4321-8765-2109-876543210987
  snyk-api-cli delete-environment --verbose 12345678-1234-5678-9012-123456789012 87654321-4321-8765-2109-876543210987
  snyk-api-cli delete-environment --include 12345678-1234-5678-9012-123456789012 87654321-4321-8765-2109-876543210987`,
	Args: cobra.ExactArgs(2),
	RunE: runDeleteEnvironment,
}

var (
	deleteEnvironmentVerbose     bool
	deleteEnvironmentSilent      bool
	deleteEnvironmentIncludeResp bool
	deleteEnvironmentUserAgent   string
)

func init() {
	// Add standard flags like curl command
	DeleteEnvironmentCmd.Flags().BoolVarP(&deleteEnvironmentVerbose, "verbose", "v", false, "Make the operation more talkative")
	DeleteEnvironmentCmd.Flags().BoolVarP(&deleteEnvironmentSilent, "silent", "s", false, "Silent mode")
	DeleteEnvironmentCmd.Flags().BoolVarP(&deleteEnvironmentIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	DeleteEnvironmentCmd.Flags().StringVarP(&deleteEnvironmentUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")
}

func runDeleteEnvironment(cmd *cobra.Command, args []string) error {
	orgID := args[0]
	environmentID := args[1]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Build the URL with the org_id and environment_id path parameters
	fullURL, err := buildDeleteEnvironmentURL(endpoint, orgID, environmentID, version)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	return ExecuteAPIRequest(RequestOptions{
		Method:      "DELETE",
		URL:         fullURL,
		Verbose:     deleteEnvironmentVerbose,
		Silent:      deleteEnvironmentSilent,
		IncludeResp: deleteEnvironmentIncludeResp,
		UserAgent:   deleteEnvironmentUserAgent,
	})
}

func buildDeleteEnvironmentURL(endpoint, orgID, environmentID, version string) (string, error) {
	// Validate the org_id parameter
	if strings.TrimSpace(orgID) == "" {
		return "", fmt.Errorf("org_id cannot be empty")
	}

	// Validate the environment_id parameter
	if strings.TrimSpace(environmentID) == "" {
		return "", fmt.Errorf("environment_id cannot be empty")
	}

	// Build base URL with the path parameters
	baseURL := fmt.Sprintf("https://%s/rest/orgs/%s/cloud/environments/%s", endpoint, orgID, environmentID)

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
