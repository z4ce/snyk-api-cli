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

// UpdateIacSettingsForGroupCmd represents the update-iac-settings-for-group command
var UpdateIacSettingsForGroupCmd = &cobra.Command{
	Use:   "update-iac-settings-for-group [group_id]",
	Short: "Update Infrastructure as Code settings for a group",
	Long: `Update Infrastructure as Code settings for a group using the Snyk API.

This command updates the Infrastructure as Code settings for a specific group by its ID.
The group ID must be provided as a required argument.

Examples:
  snyk-api-cli update-iac-settings-for-group 12345678-1234-1234-1234-123456789012 --type group_settings --custom-rules-enabled=true
  snyk-api-cli update-iac-settings-for-group 12345678-1234-1234-1234-123456789012 --type group_settings --custom-rules-enabled=false --custom-rules-oci-registry-url=https://example.com --custom-rules-oci-registry-tag=latest
  snyk-api-cli update-iac-settings-for-group 12345678-1234-1234-1234-123456789012 --type group_settings --custom-rules-enabled=true --verbose`,
	Args: cobra.ExactArgs(1),
	RunE: runUpdateIacSettingsForGroup,
}

var (
	updateIacSettingsForGroupVerbose                bool
	updateIacSettingsForGroupSilent                 bool
	updateIacSettingsForGroupIncludeResp            bool
	updateIacSettingsForGroupUserAgent              string
	updateIacSettingsForGroupDataType               string
	updateIacSettingsForGroupCustomRulesEnabled     *bool
	updateIacSettingsForGroupCustomRulesOciURL      string
	updateIacSettingsForGroupCustomRulesOciTag      string
)

func init() {
	// Add standard flags like other commands
	UpdateIacSettingsForGroupCmd.Flags().BoolVarP(&updateIacSettingsForGroupVerbose, "verbose", "v", false, "Make the operation more talkative")
	UpdateIacSettingsForGroupCmd.Flags().BoolVarP(&updateIacSettingsForGroupSilent, "silent", "s", false, "Silent mode")
	UpdateIacSettingsForGroupCmd.Flags().BoolVarP(&updateIacSettingsForGroupIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	UpdateIacSettingsForGroupCmd.Flags().StringVarP(&updateIacSettingsForGroupUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")
	
	// Add request body flags
	UpdateIacSettingsForGroupCmd.Flags().StringVar(&updateIacSettingsForGroupDataType, "type", "group_settings", "The type field for the data object")
	
	// Custom rules flags
	var customRulesEnabled bool
	UpdateIacSettingsForGroupCmd.Flags().BoolVar(&customRulesEnabled, "custom-rules-enabled", false, "Enable or disable custom rules")
	UpdateIacSettingsForGroupCmd.Flags().StringVar(&updateIacSettingsForGroupCustomRulesOciURL, "custom-rules-oci-registry-url", "", "OCI registry URL for custom rules")
	UpdateIacSettingsForGroupCmd.Flags().StringVar(&updateIacSettingsForGroupCustomRulesOciTag, "custom-rules-oci-registry-tag", "", "OCI registry tag for custom rules")
	
	// Handle the boolean pointer for custom rules enabled
	UpdateIacSettingsForGroupCmd.Flags().Lookup("custom-rules-enabled").Changed = false
	UpdateIacSettingsForGroupCmd.PreRunE = func(cmd *cobra.Command, args []string) error {
		if cmd.Flags().Changed("custom-rules-enabled") {
			updateIacSettingsForGroupCustomRulesEnabled = &customRulesEnabled
		}
		return nil
	}
}

func runUpdateIacSettingsForGroup(cmd *cobra.Command, args []string) error {
	groupID := args[0]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Build the URL
	fullURL, err := buildUpdateIacSettingsForGroupURL(endpoint, version, groupID)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	if updateIacSettingsForGroupVerbose {
		fmt.Fprintf(os.Stderr, "* Requesting PATCH %s\n", fullURL)
	}

	// Build request body
	requestBody, err := buildUpdateIacSettingsForGroupRequestBody()
	if err != nil {
		return fmt.Errorf("failed to build request body: %w", err)
	}

	if updateIacSettingsForGroupVerbose {
		fmt.Fprintf(os.Stderr, "* Request body: %s\n", requestBody)
	}

	// Create the HTTP request
	req, err := http.NewRequest("PATCH", fullURL, strings.NewReader(requestBody))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Set content type for JSON
	req.Header.Set("Content-Type", "application/json")

	// Handle authentication with same precedence as curl: Authorization header > SNYK_TOKEN > OAuth
	if updateIacSettingsForGroupVerbose {
		fmt.Fprintf(os.Stderr, "* Checking authentication options\n")
	}

	authHeader, err := buildAuthHeader([]string{}) // No manual headers for this command
	if err != nil {
		if updateIacSettingsForGroupVerbose {
			fmt.Fprintf(os.Stderr, "* Warning: failed to get automatic auth: %v\n", err)
		}
		// Don't fail the request, just proceed without automatic auth
	} else if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
		if updateIacSettingsForGroupVerbose {
			fmt.Fprintf(os.Stderr, "* Added automatic authorization header\n")
		}
	} else if updateIacSettingsForGroupVerbose {
		fmt.Fprintf(os.Stderr, "* No automatic authorization available\n")
	}

	// Set user agent
	req.Header.Set("User-Agent", updateIacSettingsForGroupUserAgent)

	// Make the request
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	if updateIacSettingsForGroupVerbose {
		fmt.Fprintf(os.Stderr, "* Making request...\n")
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// Handle response using the same pattern as other commands
	return handleUpdateIacSettingsForGroupResponse(resp, updateIacSettingsForGroupIncludeResp, updateIacSettingsForGroupVerbose, updateIacSettingsForGroupSilent)
}

func buildUpdateIacSettingsForGroupURL(endpoint, version, groupID string) (string, error) {
	// Build base URL with group ID path parameter
	baseURL := fmt.Sprintf("https://%s/rest/groups/%s/settings/iac", endpoint, groupID)

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

func buildUpdateIacSettingsForGroupRequestBody() (string, error) {
	// Build the request body according to the API specification
	requestBody := map[string]interface{}{
		"data": map[string]interface{}{
			"type": updateIacSettingsForGroupDataType,
			"attributes": map[string]interface{}{
				"custom_rules": map[string]interface{}{},
			},
		},
	}

	// Add custom rules attributes if provided
	customRules := requestBody["data"].(map[string]interface{})["attributes"].(map[string]interface{})["custom_rules"].(map[string]interface{})
	
	if updateIacSettingsForGroupCustomRulesEnabled != nil {
		customRules["is_enabled"] = *updateIacSettingsForGroupCustomRulesEnabled
	}
	
	if updateIacSettingsForGroupCustomRulesOciURL != "" {
		customRules["oci_registry_url"] = updateIacSettingsForGroupCustomRulesOciURL
	}
	
	if updateIacSettingsForGroupCustomRulesOciTag != "" {
		customRules["oci_registry_tag"] = updateIacSettingsForGroupCustomRulesOciTag
	}

	// Convert to JSON
	jsonData, err := json.Marshal(requestBody)
	if err != nil {
		return "", fmt.Errorf("failed to marshal request body: %w", err)
	}

	return string(jsonData), nil
}

func handleUpdateIacSettingsForGroupResponse(resp *http.Response, includeResp, verbose, silent bool) error {
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