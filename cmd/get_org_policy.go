package cmd

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// GetOrgPolicyCmd represents the get-org-policy command
var GetOrgPolicyCmd = &cobra.Command{
	Use:   "get-org-policy [org_id] [policy_id]",
	Short: "Get an organization-level policy by ID from Snyk",
	Long: `Get an organization-level policy by ID from the Snyk API.

This command retrieves detailed information about a specific organization-level policy by its ID within an organization.
Both the organization ID and policy ID must be provided as required arguments.

Note: Organization-level Policy APIs are only available for Code Consistent Ignores.

Required permissions: View Ignores (org.project.ignore.read)

Examples:
  snyk-api-cli get-org-policy 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-876543210987
  snyk-api-cli get-org-policy 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-876543210987 --verbose
  snyk-api-cli get-org-policy 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-876543210987 --include`,
	Args: cobra.ExactArgs(2),
	RunE: runGetOrgPolicy,
}

var (
	getOrgPolicyVerbose     bool
	getOrgPolicySilent      bool
	getOrgPolicyIncludeResp bool
	getOrgPolicyUserAgent   string
)

func init() {
	// Add standard flags like other commands
	GetOrgPolicyCmd.Flags().BoolVarP(&getOrgPolicyVerbose, "verbose", "v", false, "Make the operation more talkative")
	GetOrgPolicyCmd.Flags().BoolVarP(&getOrgPolicySilent, "silent", "s", false, "Silent mode")
	GetOrgPolicyCmd.Flags().BoolVarP(&getOrgPolicyIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	GetOrgPolicyCmd.Flags().StringVarP(&getOrgPolicyUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")
}

func runGetOrgPolicy(cmd *cobra.Command, args []string) error {
	orgID := args[0]
	policyID := args[1]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Build the URL
	fullURL, err := buildGetOrgPolicyURL(endpoint, version, orgID, policyID)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	return ExecuteAPIRequest(RequestOptions{
		Method:      "GET",
		URL:         fullURL,
		Verbose:     getOrgPolicyVerbose,
		Silent:      getOrgPolicySilent,
		IncludeResp: getOrgPolicyIncludeResp,
		UserAgent:   getOrgPolicyUserAgent,
	})
}

func buildGetOrgPolicyURL(endpoint, version, orgID, policyID string) (string, error) {
	// Validate the required parameters
	if strings.TrimSpace(orgID) == "" {
		return "", fmt.Errorf("org_id cannot be empty")
	}
	if strings.TrimSpace(policyID) == "" {
		return "", fmt.Errorf("policy_id cannot be empty")
	}

	// Build base URL with organization ID and policy ID path parameters
	baseURL := fmt.Sprintf("https://%s/rest/orgs/%s/policies/%s", endpoint, orgID, policyID)

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
