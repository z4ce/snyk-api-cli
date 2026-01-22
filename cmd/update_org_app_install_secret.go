package cmd

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// UpdateOrgAppInstallSecretCmd represents the update-org-app-install-secret command
var UpdateOrgAppInstallSecretCmd = &cobra.Command{
	Use:   "update-org-app-install-secret [org_id] [install_id]",
	Short: "Update the client secret for a specific app installation in an organization",
	Long: `Update the client secret for a specific app installation in an organization in the Snyk API.

This command updates the client secret for a specific app installation by its ID within an organization.
Both the organization ID and install ID must be provided as required arguments.

The mode flag specifies the operation to perform:
- "replace": Replace the existing secret with a new one
- "create": Create a new secret
- "delete": Delete the existing secret

Examples:
  snyk-api-cli update-org-app-install-secret 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321 --mode replace --secret "new-secret-value"
  snyk-api-cli update-org-app-install-secret 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321 --mode delete --verbose --include`,
	Args: cobra.ExactArgs(2),
	RunE: runUpdateOrgAppInstallSecret,
}

var (
	updateOrgAppInstallSecretMode        string
	updateOrgAppInstallSecretSecret      string
	updateOrgAppInstallSecretVerbose     bool
	updateOrgAppInstallSecretSilent      bool
	updateOrgAppInstallSecretIncludeResp bool
	updateOrgAppInstallSecretUserAgent   string
)

func init() {
	// Add flags for request body attributes
	UpdateOrgAppInstallSecretCmd.Flags().StringVar(&updateOrgAppInstallSecretMode, "mode", "", "Operation mode: replace, create, or delete (required)")
	UpdateOrgAppInstallSecretCmd.Flags().StringVar(&updateOrgAppInstallSecretSecret, "secret", "", "Secret value (required for replace and create modes)")
	
	// Add standard flags like other commands
	UpdateOrgAppInstallSecretCmd.Flags().BoolVarP(&updateOrgAppInstallSecretVerbose, "verbose", "v", false, "Make the operation more talkative")
	UpdateOrgAppInstallSecretCmd.Flags().BoolVarP(&updateOrgAppInstallSecretSilent, "silent", "s", false, "Silent mode")
	UpdateOrgAppInstallSecretCmd.Flags().BoolVarP(&updateOrgAppInstallSecretIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	UpdateOrgAppInstallSecretCmd.Flags().StringVarP(&updateOrgAppInstallSecretUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")

	// Mark required flags
	UpdateOrgAppInstallSecretCmd.MarkFlagRequired("mode")
}

func runUpdateOrgAppInstallSecret(cmd *cobra.Command, args []string) error {
	orgID := args[0]
	installID := args[1]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Validate mode
	validModes := []string{"replace", "create", "delete"}
	modeValid := false
	for _, validMode := range validModes {
		if updateOrgAppInstallSecretMode == validMode {
			modeValid = true
			break
		}
	}
	if !modeValid {
		return fmt.Errorf("invalid mode '%s'. Must be one of: %s", updateOrgAppInstallSecretMode, strings.Join(validModes, ", "))
	}

	// Validate secret requirement based on mode
	if (updateOrgAppInstallSecretMode == "replace" || updateOrgAppInstallSecretMode == "create") && updateOrgAppInstallSecretSecret == "" {
		return fmt.Errorf("secret flag is required for mode '%s'", updateOrgAppInstallSecretMode)
	}

	// Build the URL
	fullURL, err := buildUpdateOrgAppInstallSecretURL(endpoint, version, orgID, installID)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	// Build request body
	requestBody, err := buildUpdateOrgAppInstallSecretRequestBody()
	if err != nil {
		return fmt.Errorf("failed to build request body: %w", err)
	}

	return ExecuteAPIRequest(RequestOptions{
		Method:      "POST",
		URL:         fullURL,
		Body:        requestBody,
		Verbose:     updateOrgAppInstallSecretVerbose,
		Silent:      updateOrgAppInstallSecretSilent,
		IncludeResp: updateOrgAppInstallSecretIncludeResp,
		UserAgent:   updateOrgAppInstallSecretUserAgent,
	})
}

func buildUpdateOrgAppInstallSecretURL(endpoint, version, orgID, installID string) (string, error) {
	// Build base URL with org ID and install ID path parameters
	baseURL := fmt.Sprintf("https://%s/rest/orgs/%s/apps/installs/%s/secrets", endpoint, orgID, installID)

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

func buildUpdateOrgAppInstallSecretRequestBody() (string, error) {
	// Build JSON:API format request body according to the specification
	attributes := map[string]interface{}{
		"mode": updateOrgAppInstallSecretMode,
	}

	// Add secret only if provided (not required for delete mode)
	if updateOrgAppInstallSecretSecret != "" {
		attributes["secret"] = updateOrgAppInstallSecretSecret
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
