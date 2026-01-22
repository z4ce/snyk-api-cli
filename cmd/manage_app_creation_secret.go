package cmd

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// ManageAppCreationSecretCmd represents the manage-app-creation-secret command
var ManageAppCreationSecretCmd = &cobra.Command{
	Use:   "manage-app-creation-secret [org_id] [app_id]",
	Short: "Manage client secret for a specific app creation in an organization",
	Long: `Manage client secret for a specific app creation in an organization in the Snyk API.

This command manages the client secret for a specific app creation by its ID within an organization.
Both the organization ID and app ID must be provided as required arguments.

The mode flag specifies the operation to perform:
- "replace": Replace the existing secret with a new one
- "create": Create a new secret
- "delete": Delete the existing secret

Examples:
  snyk-api-cli manage-app-creation-secret 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321 --mode replace
  snyk-api-cli manage-app-creation-secret 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321 --mode create --verbose --include
  snyk-api-cli manage-app-creation-secret 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321 --mode delete --secret "existing-secret-value"`,
	Args: cobra.ExactArgs(2),
	RunE: runManageAppCreationSecret,
}

var (
	manageAppCreationSecretMode        string
	manageAppCreationSecretSecret      string
	manageAppCreationSecretVerbose     bool
	manageAppCreationSecretSilent      bool
	manageAppCreationSecretIncludeResp bool
	manageAppCreationSecretUserAgent   string
)

func init() {
	// Add flags for request body attributes
	ManageAppCreationSecretCmd.Flags().StringVar(&manageAppCreationSecretMode, "mode", "", "Operation mode: replace, create, or delete (required)")
	ManageAppCreationSecretCmd.Flags().StringVar(&manageAppCreationSecretSecret, "secret", "", "Secret value (required for delete mode)")

	// Add standard flags like other commands
	ManageAppCreationSecretCmd.Flags().BoolVarP(&manageAppCreationSecretVerbose, "verbose", "v", false, "Make the operation more talkative")
	ManageAppCreationSecretCmd.Flags().BoolVarP(&manageAppCreationSecretSilent, "silent", "s", false, "Silent mode")
	ManageAppCreationSecretCmd.Flags().BoolVarP(&manageAppCreationSecretIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	ManageAppCreationSecretCmd.Flags().StringVarP(&manageAppCreationSecretUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")

	// Mark required flags
	ManageAppCreationSecretCmd.MarkFlagRequired("mode")
}

func runManageAppCreationSecret(cmd *cobra.Command, args []string) error {
	orgID := args[0]
	appID := args[1]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Validate mode
	validModes := []string{"replace", "create", "delete"}
	modeValid := false
	for _, validMode := range validModes {
		if manageAppCreationSecretMode == validMode {
			modeValid = true
			break
		}
	}
	if !modeValid {
		return fmt.Errorf("invalid mode '%s'. Must be one of: %s", manageAppCreationSecretMode, strings.Join(validModes, ", "))
	}

	// Validate secret requirement based on mode
	if manageAppCreationSecretMode == "delete" && manageAppCreationSecretSecret == "" {
		return fmt.Errorf("secret flag is required for mode '%s'", manageAppCreationSecretMode)
	}

	// Build the URL
	fullURL, err := buildManageAppCreationSecretURL(endpoint, version, orgID, appID)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	// Build request body
	requestBody, err := buildManageAppCreationSecretRequestBody()
	if err != nil {
		return fmt.Errorf("failed to build request body: %w", err)
	}

	return ExecuteAPIRequest(RequestOptions{
		Method:      "POST",
		URL:         fullURL,
		Body:        requestBody,
		Verbose:     manageAppCreationSecretVerbose,
		Silent:      manageAppCreationSecretSilent,
		IncludeResp: manageAppCreationSecretIncludeResp,
		UserAgent:   manageAppCreationSecretUserAgent,
	})
}

func buildManageAppCreationSecretURL(endpoint, version, orgID, appID string) (string, error) {
	// Build base URL with organization ID and app ID path parameters
	baseURL := fmt.Sprintf("https://%s/rest/orgs/%s/apps/creations/%s/secrets", endpoint, orgID, appID)

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

func buildManageAppCreationSecretRequestBody() (string, error) {
	// Build JSON:API format request body according to the specification
	attributes := map[string]interface{}{
		"mode": manageAppCreationSecretMode,
	}

	// Add secret only if provided (only used for delete mode)
	if manageAppCreationSecretSecret != "" {
		attributes["secret"] = manageAppCreationSecretSecret
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
