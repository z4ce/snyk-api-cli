package cmd

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// UpdateOrgPolicyCmd represents the update-org-policy command
var UpdateOrgPolicyCmd = &cobra.Command{
	Use:   "update-org-policy [org_id] [policy_id]",
	Short: "Update an organization-level policy in Snyk",
	Long: `Update an organization-level policy in the Snyk API.

This command updates an organization-level policy in the specified organization using the Snyk API.
Both org_id and policy_id parameters are required and should be valid UUIDs.
At least one update field (name, ignore-type, expires, reason, condition-value, or review) must be provided.

Note: Organization-level Policy APIs are only available for Code Consistent Ignores.

Required permissions: Edit Ignores (org.project.ignore.edit)

Examples:
  snyk-api-cli update-org-policy 12345678-1234-5678-9012-123456789012 87654321-4321-8765-2109-876543210987 --name "Updated Policy Name"
  snyk-api-cli update-org-policy 12345678-1234-5678-9012-123456789012 87654321-4321-8765-2109-876543210987 --ignore-type "wont-fix" --reason "Security review completed"
  snyk-api-cli update-org-policy 12345678-1234-5678-9012-123456789012 87654321-4321-8765-2109-876543210987 --expires "2024-12-31T23:59:59Z"
  snyk-api-cli update-org-policy 12345678-1234-5678-9012-123456789012 87654321-4321-8765-2109-876543210987 --review "approved"
  snyk-api-cli update-org-policy 12345678-1234-5678-9012-123456789012 87654321-4321-8765-2109-876543210987 --condition-value "new-finding-value" --verbose`,
	Args: cobra.ExactArgs(2),
	RunE: runUpdateOrgPolicy,
}

var (
	updateOrgPolicyName           string
	updateOrgPolicyIgnoreType     string
	updateOrgPolicyExpires        string
	updateOrgPolicyReason         string
	updateOrgPolicyConditionValue string
	updateOrgPolicyReview         string
	updateOrgPolicyVerbose        bool
	updateOrgPolicySilent         bool
	updateOrgPolicyIncludeResp    bool
	updateOrgPolicyUserAgent      string
)

func init() {
	// Add flags for request body attributes
	UpdateOrgPolicyCmd.Flags().StringVar(&updateOrgPolicyName, "name", "", "Name of the policy")
	UpdateOrgPolicyCmd.Flags().StringVar(&updateOrgPolicyIgnoreType, "ignore-type", "", "Ignore type: wont-fix, not-vulnerable, or temporary-ignore")
	UpdateOrgPolicyCmd.Flags().StringVar(&updateOrgPolicyExpires, "expires", "", "Expiration date and time (RFC3339 format)")
	UpdateOrgPolicyCmd.Flags().StringVar(&updateOrgPolicyReason, "reason", "", "Reason for the policy")
	UpdateOrgPolicyCmd.Flags().StringVar(&updateOrgPolicyConditionValue, "condition-value", "", "Value for the condition field")
	UpdateOrgPolicyCmd.Flags().StringVar(&updateOrgPolicyReview, "review", "", "Policy review state: pending, approved, or rejected")

	// Add standard flags like other commands
	UpdateOrgPolicyCmd.Flags().BoolVarP(&updateOrgPolicyVerbose, "verbose", "v", false, "Make the operation more talkative")
	UpdateOrgPolicyCmd.Flags().BoolVarP(&updateOrgPolicySilent, "silent", "s", false, "Silent mode")
	UpdateOrgPolicyCmd.Flags().BoolVarP(&updateOrgPolicyIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	UpdateOrgPolicyCmd.Flags().StringVarP(&updateOrgPolicyUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")
}

func runUpdateOrgPolicy(cmd *cobra.Command, args []string) error {
	orgID := args[0]
	policyID := args[1]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Check that at least one update field is provided
	if updateOrgPolicyName == "" && updateOrgPolicyIgnoreType == "" && updateOrgPolicyExpires == "" && 
	   updateOrgPolicyReason == "" && updateOrgPolicyConditionValue == "" && updateOrgPolicyReview == "" {
		return fmt.Errorf("at least one update field must be provided: --name, --ignore-type, --expires, --reason, --condition-value, or --review")
	}

	// Validate ignore type if provided
	if updateOrgPolicyIgnoreType != "" {
		validIgnoreTypes := []string{"wont-fix", "not-vulnerable", "temporary-ignore"}
		if !contains(validIgnoreTypes, updateOrgPolicyIgnoreType) {
			return fmt.Errorf("invalid ignore-type: %s. Must be one of: %s", updateOrgPolicyIgnoreType, strings.Join(validIgnoreTypes, ", "))
		}
	}

	// Validate review state if provided
	if updateOrgPolicyReview != "" {
		validReviewStates := []string{"pending", "approved", "rejected"}
		if !contains(validReviewStates, updateOrgPolicyReview) {
			return fmt.Errorf("invalid review state: %s. Must be one of: %s", updateOrgPolicyReview, strings.Join(validReviewStates, ", "))
		}
	}

	// Build the URL
	fullURL, err := buildUpdateOrgPolicyURL(endpoint, version, orgID, policyID)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	// Build request body
	requestBody, err := buildUpdateOrgPolicyRequestBody(policyID)
	if err != nil {
		return fmt.Errorf("failed to build request body: %w", err)
	}

	return ExecuteAPIRequest(RequestOptions{
		Method:      "PATCH",
		URL:         fullURL,
		Body:        requestBody,
		Verbose:     updateOrgPolicyVerbose,
		Silent:      updateOrgPolicySilent,
		IncludeResp: updateOrgPolicyIncludeResp,
		UserAgent:   updateOrgPolicyUserAgent,
	})
}

func buildUpdateOrgPolicyURL(endpoint, version, orgID, policyID string) (string, error) {
	// Build base URL
	baseURL := fmt.Sprintf("https://%s/rest/orgs/%s/policies/%s", endpoint, orgID, policyID)

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

func buildUpdateOrgPolicyRequestBody(policyID string) (string, error) {
	// Build JSON:API format request body
	data := map[string]interface{}{
		"type": "policy",
		"id":   policyID,
	}

	// Build attributes object with only provided fields
	attributes := make(map[string]interface{})

	if updateOrgPolicyName != "" {
		attributes["name"] = updateOrgPolicyName
	}

	if updateOrgPolicyReview != "" {
		attributes["review"] = updateOrgPolicyReview
	}

	// Build action object if any action-related fields are provided
	if updateOrgPolicyIgnoreType != "" || updateOrgPolicyExpires != "" || updateOrgPolicyReason != "" {
		actionData := make(map[string]interface{})
		
		if updateOrgPolicyIgnoreType != "" {
			actionData["ignore_type"] = updateOrgPolicyIgnoreType
		}
		if updateOrgPolicyExpires != "" {
			actionData["expires"] = updateOrgPolicyExpires
		}
		if updateOrgPolicyReason != "" {
			actionData["reason"] = updateOrgPolicyReason
		}

		attributes["action"] = map[string]interface{}{
			"data": actionData,
		}
	}

	// Build conditions_group if condition value is provided
	if updateOrgPolicyConditionValue != "" {
		attributes["conditions_group"] = map[string]interface{}{
			"logical_operator": "and",
			"conditions": []map[string]interface{}{
				{
					"field":    "snyk/asset/finding/v1",
					"operator": "includes",
					"value":    updateOrgPolicyConditionValue,
				},
			},
		}
	}

	// Add attributes if any were provided
	if len(attributes) > 0 {
		data["attributes"] = attributes
	}

	requestData := map[string]interface{}{
		"data": data,
	}

	// Convert to JSON
	jsonData, err := json.Marshal(requestData)
	if err != nil {
		return "", fmt.Errorf("failed to marshal request body: %w", err)
	}

	return string(jsonData), nil
}
