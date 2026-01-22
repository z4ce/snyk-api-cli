package cmd

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// UpdateGroupAppInstallSecretCmd represents the update-group-app-install-secret command
var UpdateGroupAppInstallSecretCmd = &cobra.Command{
	Use:   "update-group-app-install-secret [group_id] [install_id]",
	Short: "Update the client secret for a specific app installation in a group",
	Long: `Update the client secret for a specific app installation in a group in the Snyk API.

This command updates the client secret for a specific app installation by its ID within a group.
Both the group ID and install ID must be provided as required arguments.

The mode flag specifies the operation to perform:
- "replace": Replace the existing secret with a new one
- "create": Create a new secret
- "delete": Delete the existing secret

Examples:
  snyk-api-cli update-group-app-install-secret 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321 --mode replace --secret "new-secret-value"
  snyk-api-cli update-group-app-install-secret 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321 --mode delete --verbose --include`,
	Args: cobra.ExactArgs(2),
	RunE: runUpdateGroupAppInstallSecret,
}

var (
	updateGroupAppInstallSecretMode        string
	updateGroupAppInstallSecretSecret      string
	updateGroupAppInstallSecretVerbose     bool
	updateGroupAppInstallSecretSilent      bool
	updateGroupAppInstallSecretIncludeResp bool
	updateGroupAppInstallSecretUserAgent   string
)

func init() {
	// Add flags for request body attributes
	UpdateGroupAppInstallSecretCmd.Flags().StringVar(&updateGroupAppInstallSecretMode, "mode", "", "Operation mode: replace, create, or delete (required)")
	UpdateGroupAppInstallSecretCmd.Flags().StringVar(&updateGroupAppInstallSecretSecret, "secret", "", "Secret value (required for replace and create modes)")
	
	// Add standard flags like other commands
	UpdateGroupAppInstallSecretCmd.Flags().BoolVarP(&updateGroupAppInstallSecretVerbose, "verbose", "v", false, "Make the operation more talkative")
	UpdateGroupAppInstallSecretCmd.Flags().BoolVarP(&updateGroupAppInstallSecretSilent, "silent", "s", false, "Silent mode")
	UpdateGroupAppInstallSecretCmd.Flags().BoolVarP(&updateGroupAppInstallSecretIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	UpdateGroupAppInstallSecretCmd.Flags().StringVarP(&updateGroupAppInstallSecretUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")

	// Mark required flags
	UpdateGroupAppInstallSecretCmd.MarkFlagRequired("mode")
}

func runUpdateGroupAppInstallSecret(cmd *cobra.Command, args []string) error {
	groupID := args[0]
	installID := args[1]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Validate mode
	validModes := []string{"replace", "create", "delete"}
	modeValid := false
	for _, validMode := range validModes {
		if updateGroupAppInstallSecretMode == validMode {
			modeValid = true
			break
		}
	}
	if !modeValid {
		return fmt.Errorf("invalid mode '%s'. Must be one of: %s", updateGroupAppInstallSecretMode, strings.Join(validModes, ", "))
	}

	// Validate secret requirement based on mode
	if (updateGroupAppInstallSecretMode == "replace" || updateGroupAppInstallSecretMode == "create") && updateGroupAppInstallSecretSecret == "" {
		return fmt.Errorf("secret flag is required for mode '%s'", updateGroupAppInstallSecretMode)
	}

	// Build the URL
	fullURL, err := buildUpdateGroupAppInstallSecretURL(endpoint, version, groupID, installID)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	// Build request body
	requestBody, err := buildUpdateGroupAppInstallSecretRequestBody()
	if err != nil {
		return fmt.Errorf("failed to build request body: %w", err)
	}

	return ExecuteAPIRequest(RequestOptions{
		Method:      "POST",
		URL:         fullURL,
		Body:        requestBody,
		Verbose:     updateGroupAppInstallSecretVerbose,
		Silent:      updateGroupAppInstallSecretSilent,
		IncludeResp: updateGroupAppInstallSecretIncludeResp,
		UserAgent:   updateGroupAppInstallSecretUserAgent,
	})
}

func buildUpdateGroupAppInstallSecretURL(endpoint, version, groupID, installID string) (string, error) {
	// Build base URL with group ID and install ID path parameters
	baseURL := fmt.Sprintf("https://%s/rest/groups/%s/apps/installs/%s/secrets", endpoint, groupID, installID)

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

func buildUpdateGroupAppInstallSecretRequestBody() (string, error) {
	// Build JSON:API format request body according to the specification
	attributes := map[string]interface{}{
		"mode": updateGroupAppInstallSecretMode,
	}

	// Add secret only if provided (not required for delete mode)
	if updateGroupAppInstallSecretSecret != "" {
		attributes["secret"] = updateGroupAppInstallSecretSecret
	}

	requestData := map[string]interface{}{
		"data": map[string]interface{}{
			"type":       "app",
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
