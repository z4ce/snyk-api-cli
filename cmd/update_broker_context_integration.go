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

// UpdateBrokerContextIntegrationCmd represents the update-broker-context-integration command
var UpdateBrokerContextIntegrationCmd = &cobra.Command{
	Use:   "update-broker-context-integration [tenant_id] [install_id] [context_id]",
	Short: "Updates an integration to be associated with a Broker context",
	Long: `Updates an integration to be associated with a Broker context from the Snyk API.

This command updates an integration association for a specific broker context within a tenant and installation.
The request must include the org_id in the attributes, as well as the integration id and type.

Examples:
  snyk-api-cli update-broker-context-integration 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321 11111111-1111-1111-1111-111111111111 --data '{"data":{"attributes":{"org_id":"22222222-2222-2222-2222-222222222222"},"id":"integration-uuid","type":"broker_integration"}}'
  snyk-api-cli update-broker-context-integration 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321 11111111-1111-1111-1111-111111111111 --data '{"data":{"attributes":{"org_id":"22222222-2222-2222-2222-222222222222"},"id":"integration-uuid","type":"broker_integration"}}' --verbose`,
	Args: cobra.ExactArgs(3),
	RunE: runUpdateBrokerContextIntegration,
}

var (
	updateBrokerContextIntegrationData        string
	updateBrokerContextIntegrationVerbose     bool
	updateBrokerContextIntegrationSilent      bool
	updateBrokerContextIntegrationIncludeResp bool
	updateBrokerContextIntegrationUserAgent   string
)

func init() {
	// Add flags for request data
	UpdateBrokerContextIntegrationCmd.Flags().StringVarP(&updateBrokerContextIntegrationData, "data", "d", "", "JSON data to send in request body")

	// Add standard flags like other commands
	UpdateBrokerContextIntegrationCmd.Flags().BoolVarP(&updateBrokerContextIntegrationVerbose, "verbose", "v", false, "Make the operation more talkative")
	UpdateBrokerContextIntegrationCmd.Flags().BoolVarP(&updateBrokerContextIntegrationSilent, "silent", "s", false, "Silent mode")
	UpdateBrokerContextIntegrationCmd.Flags().BoolVarP(&updateBrokerContextIntegrationIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	UpdateBrokerContextIntegrationCmd.Flags().StringVarP(&updateBrokerContextIntegrationUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")

	// Mark data flag as required
	UpdateBrokerContextIntegrationCmd.MarkFlagRequired("data")
}

func runUpdateBrokerContextIntegration(cmd *cobra.Command, args []string) error {
	tenantID := args[0]
	installID := args[1]
	contextID := args[2]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Build the URL with query parameters
	fullURL, err := buildUpdateBrokerContextIntegrationURL(endpoint, version, tenantID, installID, contextID)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	if updateBrokerContextIntegrationVerbose {
		fmt.Fprintf(os.Stderr, "* Requesting PATCH %s\n", fullURL)
	}

	// Create the HTTP request
	var body io.Reader
	if updateBrokerContextIntegrationData != "" {
		body = strings.NewReader(updateBrokerContextIntegrationData)
	}

	req, err := http.NewRequest("PATCH", fullURL, body)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Set content type for JSON data
	if updateBrokerContextIntegrationData != "" {
		req.Header.Set("Content-Type", "application/vnd.api+json")
	}

	// Handle authentication with same precedence as curl: Authorization header > SNYK_TOKEN > OAuth
	if updateBrokerContextIntegrationVerbose {
		fmt.Fprintf(os.Stderr, "* Checking authentication options\n")
	}

	authHeader, err := buildAuthHeader([]string{}) // No manual headers for this command
	if err != nil {
		if updateBrokerContextIntegrationVerbose {
			fmt.Fprintf(os.Stderr, "* Warning: failed to get automatic auth: %v\n", err)
		}
		// Don't fail the request, just proceed without automatic auth
	} else if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
		if updateBrokerContextIntegrationVerbose {
			fmt.Fprintf(os.Stderr, "* Added automatic authorization header\n")
		}
	} else if updateBrokerContextIntegrationVerbose {
		fmt.Fprintf(os.Stderr, "* No automatic authorization available\n")
	}

	// Set user agent
	req.Header.Set("User-Agent", updateBrokerContextIntegrationUserAgent)

	// Make the request
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	if updateBrokerContextIntegrationVerbose {
		fmt.Fprintf(os.Stderr, "* Making request...\n")
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// Handle response using the same pattern as other commands
	return handleUpdateBrokerContextIntegrationResponse(resp, updateBrokerContextIntegrationIncludeResp, updateBrokerContextIntegrationVerbose, updateBrokerContextIntegrationSilent)
}

func buildUpdateBrokerContextIntegrationURL(endpoint, version, tenantID, installID, contextID string) (string, error) {
	// Build base URL
	baseURL := fmt.Sprintf("https://%s/rest/tenants/%s/brokers/installs/%s/contexts/%s/integration", endpoint, tenantID, installID, contextID)

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

func handleUpdateBrokerContextIntegrationResponse(resp *http.Response, includeResp, verbose, silent bool) error {
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