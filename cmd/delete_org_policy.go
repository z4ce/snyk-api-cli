package cmd

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// DeleteOrgPolicyCmd represents the delete-org-policy command
var DeleteOrgPolicyCmd = &cobra.Command{
	Use:   "delete-org-policy [org_id] [policy_id]",
	Short: "Delete an organization-level policy by ID from Snyk",
	Long: `Delete an organization-level policy by ID from the Snyk API.

This command deletes a specific organization-level policy using its unique identifier within an organization.
Both org_id and policy_id parameters are required and must be valid UUIDs.

Note: Organization-level Policy APIs are only available for Code Consistent Ignores.

Required permissions: Remove Ignores (org.project.ignore.delete)

Examples:
  snyk-api-cli delete-org-policy 12345678-1234-5678-9012-123456789012 87654321-4321-8765-2109-876543210987
  snyk-api-cli delete-org-policy 12345678-1234-5678-9012-123456789012 87654321-4321-8765-2109-876543210987 --verbose
  snyk-api-cli delete-org-policy 12345678-1234-5678-9012-123456789012 87654321-4321-8765-2109-876543210987 --include`,
	Args: cobra.ExactArgs(2),
	RunE: runDeleteOrgPolicy,
}

var (
	deleteOrgPolicyVerbose     bool
	deleteOrgPolicySilent      bool
	deleteOrgPolicyIncludeResp bool
	deleteOrgPolicyUserAgent   string
)

func init() {
	// Add standard flags like other commands
	DeleteOrgPolicyCmd.Flags().BoolVarP(&deleteOrgPolicyVerbose, "verbose", "v", false, "Make the operation more talkative")
	DeleteOrgPolicyCmd.Flags().BoolVarP(&deleteOrgPolicySilent, "silent", "s", false, "Silent mode")
	DeleteOrgPolicyCmd.Flags().BoolVarP(&deleteOrgPolicyIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	DeleteOrgPolicyCmd.Flags().StringVarP(&deleteOrgPolicyUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")
}

func runDeleteOrgPolicy(cmd *cobra.Command, args []string) error {
	orgID := args[0]
	policyID := args[1]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Build the URL with the org_id and policy_id path parameters
	fullURL, err := buildDeleteOrgPolicyURL(endpoint, orgID, policyID, version)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	return ExecuteAPIRequest(RequestOptions{
		Method:      "DELETE",
		URL:         fullURL,
		Verbose:     deleteOrgPolicyVerbose,
		Silent:      deleteOrgPolicySilent,
		IncludeResp: deleteOrgPolicyIncludeResp,
		UserAgent:   deleteOrgPolicyUserAgent,
	})
}

func buildDeleteOrgPolicyURL(endpoint, orgID, policyID, version string) (string, error) {
	// Validate the org_id parameter
	if strings.TrimSpace(orgID) == "" {
		return "", fmt.Errorf("org_id cannot be empty")
	}

	// Validate the policy_id parameter
	if strings.TrimSpace(policyID) == "" {
		return "", fmt.Errorf("policy_id cannot be empty")
	}

	// Build base URL with the path parameters
	baseURL := fmt.Sprintf("https://%s/rest/orgs/%s/policies/%s", endpoint, orgID, policyID)

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
