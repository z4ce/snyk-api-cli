package cmd

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// UpdateServiceAccountSecretCmd represents the update-service-account-secret command
var UpdateServiceAccountSecretCmd = &cobra.Command{
	Use:   "update-service-account-secret [group_id] [serviceaccount_id]",
	Short: "Update a service account secret in Snyk",
	Long: `Update a service account secret in the Snyk API.

This command allows you to manage service account secrets by creating, replacing, or deleting them.
Both group_id and serviceaccount_id must be provided as required arguments.

Mode options:
- replace: Generate a new secret (replaces existing)
- create: Add a new secret (max 2 secrets allowed)
- delete: Remove an existing secret (requires --secret flag)

Examples:
  snyk-api-cli update-service-account-secret 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321 --mode replace
  snyk-api-cli update-service-account-secret 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321 --mode create --verbose
  snyk-api-cli update-service-account-secret 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321 --mode delete --secret "secret-to-delete"`,
	Args: cobra.ExactArgs(2),
	RunE: runUpdateServiceAccountSecret,
}

var (
	updateServiceAccountSecretMode        string
	updateServiceAccountSecretSecret      string
	updateServiceAccountSecretVerbose     bool
	updateServiceAccountSecretSilent      bool
	updateServiceAccountSecretIncludeResp bool
	updateServiceAccountSecretUserAgent   string
)

func init() {
	// Add flags for request body attributes
	UpdateServiceAccountSecretCmd.Flags().StringVar(&updateServiceAccountSecretMode, "mode", "", "Secret management mode: replace, create, or delete (required)")
	UpdateServiceAccountSecretCmd.Flags().StringVar(&updateServiceAccountSecretSecret, "secret", "", "Secret to delete (required when mode is 'delete')")

	// Add standard flags like other commands
	UpdateServiceAccountSecretCmd.Flags().BoolVarP(&updateServiceAccountSecretVerbose, "verbose", "v", false, "Make the operation more talkative")
	UpdateServiceAccountSecretCmd.Flags().BoolVarP(&updateServiceAccountSecretSilent, "silent", "s", false, "Silent mode")
	UpdateServiceAccountSecretCmd.Flags().BoolVarP(&updateServiceAccountSecretIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	UpdateServiceAccountSecretCmd.Flags().StringVarP(&updateServiceAccountSecretUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")

	// Mark required flags
	UpdateServiceAccountSecretCmd.MarkFlagRequired("mode")
}

func runUpdateServiceAccountSecret(cmd *cobra.Command, args []string) error {
	groupID := args[0]
	serviceAccountID := args[1]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Validate mode
	validModes := []string{"replace", "create", "delete"}
	if !contains(validModes, updateServiceAccountSecretMode) {
		return fmt.Errorf("invalid mode: %s. Valid options are: %s", updateServiceAccountSecretMode, strings.Join(validModes, ", "))
	}

	// Validate that secret is provided when mode is delete
	if updateServiceAccountSecretMode == "delete" && updateServiceAccountSecretSecret == "" {
		return fmt.Errorf("--secret flag is required when mode is 'delete'")
	}

	// Build the URL
	fullURL, err := buildUpdateServiceAccountSecretURL(endpoint, version, groupID, serviceAccountID)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	// Build request body
	requestBody, err := buildUpdateServiceAccountSecretRequestBody()
	if err != nil {
		return fmt.Errorf("failed to build request body: %w", err)
	}

	return ExecuteAPIRequest(RequestOptions{
		Method:      "POST",
		URL:         fullURL,
		Body:        requestBody,
		Verbose:     updateServiceAccountSecretVerbose,
		Silent:      updateServiceAccountSecretSilent,
		IncludeResp: updateServiceAccountSecretIncludeResp,
		UserAgent:   updateServiceAccountSecretUserAgent,
	})
}

func buildUpdateServiceAccountSecretURL(endpoint, version, groupID, serviceAccountID string) (string, error) {
	// Build base URL with group ID and service account ID path parameters
	baseURL := fmt.Sprintf("https://%s/rest/groups/%s/service_accounts/%s/secrets", endpoint, groupID, serviceAccountID)

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

func buildUpdateServiceAccountSecretRequestBody() (string, error) {
	// Build attributes object
	attributes := map[string]interface{}{
		"mode": updateServiceAccountSecretMode,
	}

	// Add secret field if provided (required for delete mode)
	if updateServiceAccountSecretSecret != "" {
		attributes["secret"] = updateServiceAccountSecretSecret
	}

	// Build JSON:API format request body according to the specification
	requestData := map[string]interface{}{
		"data": map[string]interface{}{
			"type":       "service_account",
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
