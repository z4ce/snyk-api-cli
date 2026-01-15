package cmd

import (
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

// UpdateDeploymentCredentialCmd represents the update-deployment-credential command
var UpdateDeploymentCredentialCmd = &cobra.Command{
	Use:   "update-deployment-credential [tenant_id] [install_id] [deployment_id] [credential_id]",
	Short: "Updates Deployment credential",
	Long: `Updates Deployment credential from the Snyk API.

This command updates an existing deployment credential for a specific tenant, install ID, deployment ID, and credential ID.
The request data should be provided in JSON format with deployment_id, environment_variable_name, and type attributes.

Examples:
  snyk-api-cli update-deployment-credential 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321 11111111-1111-1111-1111-111111111111 22222222-2222-2222-2222-222222222222 --data '{"data":{"attributes":{"deployment_id":"11111111-1111-1111-1111-111111111111","environment_variable_name":"GITHUB_TOKEN","type":"github"},"id":"22222222-2222-2222-2222-222222222222"}}'
  snyk-api-cli update-deployment-credential 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321 11111111-1111-1111-1111-111111111111 22222222-2222-2222-2222-222222222222 --data '{"data":{"attributes":{"deployment_id":"11111111-1111-1111-1111-111111111111","environment_variable_name":"GITHUB_TOKEN","type":"github","comment":"Updated GitHub token"},"id":"22222222-2222-2222-2222-222222222222"}}' --verbose`,
	Args: cobra.ExactArgs(4),
	RunE: runUpdateDeploymentCredential,
}

var (
	updateDeploymentCredentialData        string
	updateDeploymentCredentialVerbose     bool
	updateDeploymentCredentialSilent      bool
	updateDeploymentCredentialIncludeResp bool
	updateDeploymentCredentialUserAgent   string
)

func init() {
	// Add flags for request data
	UpdateDeploymentCredentialCmd.Flags().StringVarP(&updateDeploymentCredentialData, "data", "d", "", "JSON data to send in request body")

	// Add standard flags like other commands
	UpdateDeploymentCredentialCmd.Flags().BoolVarP(&updateDeploymentCredentialVerbose, "verbose", "v", false, "Make the operation more talkative")
	UpdateDeploymentCredentialCmd.Flags().BoolVarP(&updateDeploymentCredentialSilent, "silent", "s", false, "Silent mode")
	UpdateDeploymentCredentialCmd.Flags().BoolVarP(&updateDeploymentCredentialIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	UpdateDeploymentCredentialCmd.Flags().StringVarP(&updateDeploymentCredentialUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")

	// Mark data flag as required
	UpdateDeploymentCredentialCmd.MarkFlagRequired("data")
}

func runUpdateDeploymentCredential(cmd *cobra.Command, args []string) error {
	tenantID := args[0]
	installID := args[1]
	deploymentID := args[2]
	credentialID := args[3]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Build the URL with query parameters
	fullURL, err := buildUpdateDeploymentCredentialURL(endpoint, version, tenantID, installID, deploymentID, credentialID)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	if updateDeploymentCredentialVerbose {
		fmt.Fprintf(os.Stderr, "* Requesting PATCH %s\n", fullURL)
	}

	// Create the HTTP request
	var body io.Reader
	if updateDeploymentCredentialData != "" {
		body = strings.NewReader(updateDeploymentCredentialData)
	}

	req, err := http.NewRequest("PATCH", fullURL, body)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Set content type for JSON data
	if updateDeploymentCredentialData != "" {
		req.Header.Set("Content-Type", "application/vnd.api+json")
	}

	// Handle authentication with same precedence as curl: Authorization header > SNYK_TOKEN > OAuth
	if updateDeploymentCredentialVerbose {
		fmt.Fprintf(os.Stderr, "* Checking authentication options\n")
	}

	authHeader, err := buildAuthHeader([]string{}) // No manual headers for this command
	if err != nil {
		if updateDeploymentCredentialVerbose {
			fmt.Fprintf(os.Stderr, "* Warning: failed to get automatic auth: %v\n", err)
		}
		// Don't fail the request, just proceed without automatic auth
	} else if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
		if updateDeploymentCredentialVerbose {
			fmt.Fprintf(os.Stderr, "* Added automatic authorization header\n")
		}
	} else if updateDeploymentCredentialVerbose {
		fmt.Fprintf(os.Stderr, "* No automatic authorization available\n")
	}

	// Set user agent
	req.Header.Set("User-Agent", updateDeploymentCredentialUserAgent)

	// Make the request
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	if updateDeploymentCredentialVerbose {
		fmt.Fprintf(os.Stderr, "* Making request...\n")
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// Handle response using the same pattern as other commands
	return handleUpdateDeploymentCredentialResponse(resp, updateDeploymentCredentialIncludeResp, updateDeploymentCredentialVerbose, updateDeploymentCredentialSilent)
}

func buildUpdateDeploymentCredentialURL(endpoint, version, tenantID, installID, deploymentID, credentialID string) (string, error) {
	// Build base URL
	baseURL := fmt.Sprintf("https://%s/rest/tenants/%s/brokers/installs/%s/deployments/%s/credentials/%s", endpoint, tenantID, installID, deploymentID, credentialID)

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

func handleUpdateDeploymentCredentialResponse(resp *http.Response, includeResp, verbose, silent bool) error {
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