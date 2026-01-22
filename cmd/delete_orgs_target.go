package cmd

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// DeleteOrgsTargetCmd represents the delete-orgs-target command
var DeleteOrgsTargetCmd = &cobra.Command{
	Use:   "delete-orgs-target [org_id] [target_id]",
	Short: "Delete target by target ID from Snyk",
	Long: `Delete target by target ID from the Snyk API.

This command deletes a specific target using its unique identifier within an organization.
Both org_id and target_id parameters are required and must be valid UUIDs.

Required permissions: Remove Projects (org.project.delete)

Examples:
  snyk-api-cli delete-orgs-target 12345678-1234-1234-1234-123456789012 87654321-4321-8765-2109-876543210987
  snyk-api-cli delete-orgs-target 12345678-1234-1234-1234-123456789012 87654321-4321-8765-2109-876543210987 --verbose
  snyk-api-cli delete-orgs-target 12345678-1234-1234-1234-123456789012 87654321-4321-8765-2109-876543210987 --include`,
	Args: cobra.ExactArgs(2),
	RunE: runDeleteOrgsTarget,
}

var (
	deleteOrgsTargetVerbose     bool
	deleteOrgsTargetSilent      bool
	deleteOrgsTargetIncludeResp bool
	deleteOrgsTargetUserAgent   string
)

func init() {
	// Add standard flags like curl command
	DeleteOrgsTargetCmd.Flags().BoolVarP(&deleteOrgsTargetVerbose, "verbose", "v", false, "Make the operation more talkative")
	DeleteOrgsTargetCmd.Flags().BoolVarP(&deleteOrgsTargetSilent, "silent", "s", false, "Silent mode")
	DeleteOrgsTargetCmd.Flags().BoolVarP(&deleteOrgsTargetIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	DeleteOrgsTargetCmd.Flags().StringVarP(&deleteOrgsTargetUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")
}

func runDeleteOrgsTarget(cmd *cobra.Command, args []string) error {
	orgID := args[0]
	targetID := args[1]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Build the URL with the org_id and target_id path parameters
	fullURL, err := buildDeleteOrgsTargetURL(endpoint, orgID, targetID, version)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	return ExecuteAPIRequest(RequestOptions{
		Method:      "DELETE",
		URL:         fullURL,
		Verbose:     deleteOrgsTargetVerbose,
		Silent:      deleteOrgsTargetSilent,
		IncludeResp: deleteOrgsTargetIncludeResp,
		UserAgent:   deleteOrgsTargetUserAgent,
	})
}

func buildDeleteOrgsTargetURL(endpoint, orgID, targetID, version string) (string, error) {
	// Validate the org_id parameter
	if strings.TrimSpace(orgID) == "" {
		return "", fmt.Errorf("org_id cannot be empty")
	}

	// Validate the target_id parameter
	if strings.TrimSpace(targetID) == "" {
		return "", fmt.Errorf("target_id cannot be empty")
	}

	// Build base URL with the path parameters
	baseURL := fmt.Sprintf("https://%s/rest/orgs/%s/targets/%s", endpoint, orgID, targetID)

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
