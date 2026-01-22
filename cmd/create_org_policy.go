package cmd

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// CreateOrgPolicyCmd represents the create-org-policy command
var CreateOrgPolicyCmd = &cobra.Command{
	Use:   "create-org-policy [org_id]",
	Short: "Create an organization-level policy in Snyk",
	Long: `Create an organization-level policy in the Snyk API.

This command creates an organization-level policy for a specific organization by its ID.
The policy name, action type, ignore type, and conditions must be provided as flags.

Note: Organization-level Policy APIs are only available for Code Consistent Ignores.

Examples:
  snyk-api-cli create-org-policy 12345678-1234-1234-1234-123456789012 --name "Security Policy" --ignore-type "wont-fix" --condition-value "finding123"
  snyk-api-cli create-org-policy 12345678-1234-1234-1234-123456789012 --name "Temp Ignore" --ignore-type "temporary-ignore" --condition-value "finding456" --expires "2024-12-31T23:59:59Z" --reason "Under review"
  snyk-api-cli create-org-policy 12345678-1234-1234-1234-123456789012 --name "Not Vulnerable" --ignore-type "not-vulnerable" --condition-value "finding789" --reason "False positive" --verbose`,
	Args: cobra.ExactArgs(1),
	RunE: runCreateOrgPolicy,
}

var (
	createOrgPolicyName           string
	createOrgPolicyIgnoreType     string
	createOrgPolicyExpires        string
	createOrgPolicyReason         string
	createOrgPolicyConditionValue string
	createOrgPolicyVerbose        bool
	createOrgPolicySilent         bool
	createOrgPolicyIncludeResp    bool
	createOrgPolicyUserAgent      string
)

func init() {
	// Add flags for request body attributes
	CreateOrgPolicyCmd.Flags().StringVar(&createOrgPolicyName, "name", "", "Name of the policy (required)")
	CreateOrgPolicyCmd.Flags().StringVar(&createOrgPolicyIgnoreType, "ignore-type", "", "Ignore type: wont-fix, not-vulnerable, or temporary-ignore (required)")
	CreateOrgPolicyCmd.Flags().StringVar(&createOrgPolicyExpires, "expires", "", "Expiration date and time (RFC3339 format, optional)")
	CreateOrgPolicyCmd.Flags().StringVar(&createOrgPolicyReason, "reason", "", "Reason for the policy (optional)")
	CreateOrgPolicyCmd.Flags().StringVar(&createOrgPolicyConditionValue, "condition-value", "", "Value for the condition field (required)")

	// Add standard flags like other commands
	CreateOrgPolicyCmd.Flags().BoolVarP(&createOrgPolicyVerbose, "verbose", "v", false, "Make the operation more talkative")
	CreateOrgPolicyCmd.Flags().BoolVarP(&createOrgPolicySilent, "silent", "s", false, "Silent mode")
	CreateOrgPolicyCmd.Flags().BoolVarP(&createOrgPolicyIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	CreateOrgPolicyCmd.Flags().StringVarP(&createOrgPolicyUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")

	// Mark required flags
	CreateOrgPolicyCmd.MarkFlagRequired("name")
	CreateOrgPolicyCmd.MarkFlagRequired("ignore-type")
	CreateOrgPolicyCmd.MarkFlagRequired("condition-value")
}

func runCreateOrgPolicy(cmd *cobra.Command, args []string) error {
	orgID := args[0]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Validate ignore type
	validIgnoreTypes := []string{"wont-fix", "not-vulnerable", "temporary-ignore"}
	if !contains(validIgnoreTypes, createOrgPolicyIgnoreType) {
		return fmt.Errorf("invalid ignore-type: %s. Must be one of: %s", createOrgPolicyIgnoreType, strings.Join(validIgnoreTypes, ", "))
	}

	// Build the URL
	fullURL, err := buildCreateOrgPolicyURL(endpoint, version, orgID)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	// Build request body
	requestBody, err := buildCreateOrgPolicyRequestBody()
	if err != nil {
		return fmt.Errorf("failed to build request body: %w", err)
	}

	return ExecuteAPIRequest(RequestOptions{
		Method:      "POST",
		URL:         fullURL,
		Body:        requestBody,
		Verbose:     createOrgPolicyVerbose,
		Silent:      createOrgPolicySilent,
		IncludeResp: createOrgPolicyIncludeResp,
		UserAgent:   createOrgPolicyUserAgent,
	})
}

func buildCreateOrgPolicyURL(endpoint, version, orgID string) (string, error) {
	// Build base URL with organization ID path parameter
	baseURL := fmt.Sprintf("https://%s/rest/orgs/%s/policies", endpoint, orgID)

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

func buildCreateOrgPolicyRequestBody() (string, error) {
	// Build action data
	actionData := map[string]interface{}{
		"ignore_type": createOrgPolicyIgnoreType,
	}

	// Add optional fields
	if createOrgPolicyExpires != "" {
		actionData["expires"] = createOrgPolicyExpires
	}
	if createOrgPolicyReason != "" {
		actionData["reason"] = createOrgPolicyReason
	}

	// Build attributes according to the API specification
	attributes := map[string]interface{}{
		"name":        createOrgPolicyName,
		"action_type": "ignore",
		"action": map[string]interface{}{
			"data": actionData,
		},
		"conditions_group": map[string]interface{}{
			"logical_operator": "and",
			"conditions": []map[string]interface{}{
				{
					"field":    "snyk/asset/finding/v1",
					"operator": "includes",
					"value":    createOrgPolicyConditionValue,
				},
			},
		},
	}

	requestData := map[string]interface{}{
		"data": map[string]interface{}{
			"type":       "policy",
			"attributes": attributes,
		},
	}

	// Convert to JSON
	jsonData, err := json.Marshal(requestData)
	if err != nil {
		return "", fmt.Errorf("failed to marshal request body: %w", err)
	}

	return string(jsonData), nil
}
