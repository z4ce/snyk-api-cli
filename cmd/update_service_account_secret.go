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

	if updateServiceAccountSecretVerbose {
		fmt.Fprintf(os.Stderr, "* Requesting POST %s\n", fullURL)
	}

	// Build request body
	requestBody, err := buildUpdateServiceAccountSecretRequestBody()
	if err != nil {
		return fmt.Errorf("failed to build request body: %w", err)
	}

	if updateServiceAccountSecretVerbose {
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
	if updateServiceAccountSecretVerbose {
		fmt.Fprintf(os.Stderr, "* Checking authentication options\n")
	}

	authHeader, err := buildAuthHeader([]string{}) // No manual headers for this command
	if err != nil {
		if updateServiceAccountSecretVerbose {
			fmt.Fprintf(os.Stderr, "* Warning: failed to get automatic auth: %v\n", err)
		}
		// Don't fail the request, just proceed without automatic auth
	} else if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
		if updateServiceAccountSecretVerbose {
			fmt.Fprintf(os.Stderr, "* Added automatic authorization header\n")
		}
	} else if updateServiceAccountSecretVerbose {
		fmt.Fprintf(os.Stderr, "* No automatic authorization available\n")
	}

	// Set user agent
	req.Header.Set("User-Agent", updateServiceAccountSecretUserAgent)

	// Make the request
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	if updateServiceAccountSecretVerbose {
		fmt.Fprintf(os.Stderr, "* Making request...\n")
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// Handle response using the same pattern as other commands
	return handleUpdateServiceAccountSecretResponse(resp, updateServiceAccountSecretIncludeResp, updateServiceAccountSecretVerbose, updateServiceAccountSecretSilent)
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

func handleUpdateServiceAccountSecretResponse(resp *http.Response, includeResp, verbose, silent bool) error {
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