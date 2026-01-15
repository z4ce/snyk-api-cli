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

// ManageSecretsCmd represents the manage-secrets command
var ManageSecretsCmd = &cobra.Command{
	Use:   "manage-secrets [org_id] [client_id]",
	Short: "Manage client secrets for a specific app in an organization",
	Long: `Manage client secrets for a specific app in an organization in the Snyk API.

This command manages the client secrets for a specific app by its client ID within an organization.
Both the organization ID and client ID must be provided as required arguments.

The mode flag specifies the operation to perform:
- "replace": Replace existing secrets with a new generated secret
- "create": Add a new secret, preserving existing secrets
- "delete": Remove an existing secret by value

Examples:
  snyk-api-cli manage-secrets 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321 --mode replace
  snyk-api-cli manage-secrets 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321 --mode create --verbose --include
  snyk-api-cli manage-secrets 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321 --mode delete --secret "existing-secret-value"`,
	Args: cobra.ExactArgs(2),
	RunE: runManageSecrets,
}

var (
	manageSecretsMode         string
	manageSecretsSecret       string
	manageSecretsVerbose      bool
	manageSecretsSilent       bool
	manageSecretsIncludeResp  bool
	manageSecretsUserAgent    string
)

func init() {
	// Add flags for request body attributes
	ManageSecretsCmd.Flags().StringVar(&manageSecretsMode, "mode", "", "Operation mode: replace, create, or delete (required)")
	ManageSecretsCmd.Flags().StringVar(&manageSecretsSecret, "secret", "", "Secret value (required for delete mode)")
	
	// Add standard flags like other commands
	ManageSecretsCmd.Flags().BoolVarP(&manageSecretsVerbose, "verbose", "v", false, "Make the operation more talkative")
	ManageSecretsCmd.Flags().BoolVarP(&manageSecretsSilent, "silent", "s", false, "Silent mode")
	ManageSecretsCmd.Flags().BoolVarP(&manageSecretsIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	ManageSecretsCmd.Flags().StringVarP(&manageSecretsUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")

	// Mark required flags
	ManageSecretsCmd.MarkFlagRequired("mode")
}

func runManageSecrets(cmd *cobra.Command, args []string) error {
	orgID := args[0]
	clientID := args[1]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Validate mode
	validModes := []string{"replace", "create", "delete"}
	modeValid := false
	for _, validMode := range validModes {
		if manageSecretsMode == validMode {
			modeValid = true
			break
		}
	}
	if !modeValid {
		return fmt.Errorf("invalid mode '%s'. Must be one of: %s", manageSecretsMode, strings.Join(validModes, ", "))
	}

	// Validate secret requirement based on mode
	if manageSecretsMode == "delete" && manageSecretsSecret == "" {
		return fmt.Errorf("secret flag is required for mode '%s'", manageSecretsMode)
	}

	// Build the URL
	fullURL, err := buildManageSecretsURL(endpoint, version, orgID, clientID)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	if manageSecretsVerbose {
		fmt.Fprintf(os.Stderr, "* Requesting POST %s\n", fullURL)
	}

	// Build request body
	requestBody, err := buildManageSecretsRequestBody()
	if err != nil {
		return fmt.Errorf("failed to build request body: %w", err)
	}

	if manageSecretsVerbose {
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
	if manageSecretsVerbose {
		fmt.Fprintf(os.Stderr, "* Checking authentication options\n")
	}

	authHeader, err := buildAuthHeader([]string{}) // No manual headers for this command
	if err != nil {
		if manageSecretsVerbose {
			fmt.Fprintf(os.Stderr, "* Warning: failed to get automatic auth: %v\n", err)
		}
		// Don't fail the request, just proceed without automatic auth
	} else if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
		if manageSecretsVerbose {
			fmt.Fprintf(os.Stderr, "* Added automatic authorization header\n")
		}
	} else if manageSecretsVerbose {
		fmt.Fprintf(os.Stderr, "* No automatic authorization available\n")
	}

	// Set user agent
	req.Header.Set("User-Agent", manageSecretsUserAgent)

	// Make the request
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	if manageSecretsVerbose {
		fmt.Fprintf(os.Stderr, "* Making request...\n")
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// Handle response using the same pattern as other commands
	return handleManageSecretsResponse(resp, manageSecretsIncludeResp, manageSecretsVerbose, manageSecretsSilent)
}

func buildManageSecretsURL(endpoint, version, orgID, clientID string) (string, error) {
	// Build base URL with organization ID and client ID path parameters
	baseURL := fmt.Sprintf("https://%s/rest/orgs/%s/apps/%s/secrets", endpoint, orgID, clientID)

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

func buildManageSecretsRequestBody() (string, error) {
	// Build JSON:API format request body according to the specification
	attributes := map[string]interface{}{
		"mode": manageSecretsMode,
	}

	// Add secret only if provided (only used for delete mode)
	if manageSecretsSecret != "" {
		attributes["secret"] = manageSecretsSecret
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

func handleManageSecretsResponse(resp *http.Response, includeResp, verbose, silent bool) error {
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