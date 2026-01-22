package cmd

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// DeleteOrgProjectCmd represents the delete-org-project command
var DeleteOrgProjectCmd = &cobra.Command{
	Use:   "delete-org-project [org_id] [project_id]",
	Short: "Delete a project by ID from a Snyk organization",
	Long: `Delete a project by ID from a Snyk organization.

This command deletes a specific project using its unique identifier within an organization.
Both org_id and project_id parameters are required and must be valid UUIDs.

Required permissions: View Organization, View Projects, Remove Projects

Examples:
  snyk-api-cli delete-org-project 12345678-1234-5678-9012-123456789012 87654321-4321-8765-2109-876543210987
  snyk-api-cli delete-org-project 12345678-1234-5678-9012-123456789012 87654321-4321-8765-2109-876543210987 --verbose
  snyk-api-cli delete-org-project 12345678-1234-5678-9012-123456789012 87654321-4321-8765-2109-876543210987 --include`,
	Args: cobra.ExactArgs(2),
	RunE: runDeleteOrgProject,
}

var (
	deleteOrgProjectVerbose     bool
	deleteOrgProjectSilent      bool
	deleteOrgProjectIncludeResp bool
	deleteOrgProjectUserAgent   string
)

func init() {
	// Add standard flags like other commands
	DeleteOrgProjectCmd.Flags().BoolVarP(&deleteOrgProjectVerbose, "verbose", "v", false, "Make the operation more talkative")
	DeleteOrgProjectCmd.Flags().BoolVarP(&deleteOrgProjectSilent, "silent", "s", false, "Silent mode")
	DeleteOrgProjectCmd.Flags().BoolVarP(&deleteOrgProjectIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	DeleteOrgProjectCmd.Flags().StringVarP(&deleteOrgProjectUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")
}

func runDeleteOrgProject(cmd *cobra.Command, args []string) error {
	orgID := args[0]
	projectID := args[1]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Build the URL with the org_id and project_id path parameters
	fullURL, err := buildDeleteOrgProjectURL(endpoint, orgID, projectID, version)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	return ExecuteAPIRequest(RequestOptions{
		Method:      "DELETE",
		URL:         fullURL,
		Verbose:     deleteOrgProjectVerbose,
		Silent:      deleteOrgProjectSilent,
		IncludeResp: deleteOrgProjectIncludeResp,
		UserAgent:   deleteOrgProjectUserAgent,
	})
}

func buildDeleteOrgProjectURL(endpoint, orgID, projectID, version string) (string, error) {
	// Validate the org_id parameter
	if strings.TrimSpace(orgID) == "" {
		return "", fmt.Errorf("org_id cannot be empty")
	}

	// Validate the project_id parameter
	if strings.TrimSpace(projectID) == "" {
		return "", fmt.Errorf("project_id cannot be empty")
	}

	// Build base URL with the path parameters
	baseURL := fmt.Sprintf("https://%s/rest/orgs/%s/projects/%s", endpoint, orgID, projectID)

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
