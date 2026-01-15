package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

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

	if createOrgPolicyVerbose {
		fmt.Fprintf(os.Stderr, "* Requesting POST %s\n", fullURL)
	}

	// Build request body
	requestBody, err := buildCreateOrgPolicyRequestBody()
	if err != nil {
		return fmt.Errorf("failed to build request body: %w", err)
	}

	if createOrgPolicyVerbose {
		fmt.Fprintf(os.Stderr, "* Request body: %s\n", requestBody)
	}

	// Create the HTTP request
	req, err := http.NewRequest("POST", fullURL, strings.NewReader(requestBody))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Set content type for JSON:API
	req.Header.Set("Content-Type", "application/vnd.api+json")

	// Handle authentication with same precedence as curl: Authorization header > SNYK_TOKEN > OAuth
	if createOrgPolicyVerbose {
		fmt.Fprintf(os.Stderr, "* Checking authentication options\n")
	}

	authHeader, err := buildAuthHeader([]string{}) // No manual headers for this command
	if err != nil {
		if createOrgPolicyVerbose {
			fmt.Fprintf(os.Stderr, "* Warning: failed to get automatic auth: %v\n", err)
		}
		// Don't fail the request, just proceed without automatic auth
	} else if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
		if createOrgPolicyVerbose {
			fmt.Fprintf(os.Stderr, "* Added automatic authorization header\n")
		}
	} else if createOrgPolicyVerbose {
		fmt.Fprintf(os.Stderr, "* No automatic authorization available\n")
	}

	// Set user agent
	req.Header.Set("User-Agent", createOrgPolicyUserAgent)

	// Make the request
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	if createOrgPolicyVerbose {
		fmt.Fprintf(os.Stderr, "* Making request...\n")
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// Handle response using the same pattern as other commands
	return handleCreateOrgPolicyResponse(resp, createOrgPolicyIncludeResp, createOrgPolicyVerbose, createOrgPolicySilent)
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

func handleCreateOrgPolicyResponse(resp *http.Response, includeResp, verbose, silent bool) error {
	if verbose {
		fmt.Fprintf(os.Stderr, "* Response: %s\n", resp.Status)
	}

	// Print response headers if requested
	if includeResp {
		fmt.Printf("%s %s\n", resp.Proto, resp.Status)
		for key, values := range resp.Header {
			for _, value := range values {
				fmt.Printf("%s: %s\n", key, value)
			}
		}
		fmt.Println()
	}

	// Read and print response body
	if !silent {
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return fmt.Errorf("failed to read response body: %w", err)
		}
		fmt.Print(string(body))
	}

	// Return error for non-2xx status codes if verbose
	if verbose && (resp.StatusCode < 200 || resp.StatusCode >= 300) {
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, resp.Status)
	}

	return nil
}

