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

// CreateBrokerConnectionIntegrationCmd represents the create-broker-connection-integration command
var CreateBrokerConnectionIntegrationCmd = &cobra.Command{
	Use:   "create-broker-connection-integration [tenant_id] [connection_id] [org_id]",
	Short: "Creates Broker connection Integration Configuration",
	Long: `Creates Broker connection Integration Configuration from the Snyk API.

This command creates a new integration configuration for a specific broker connection within a tenant and organization.
The integration_id and type must be provided in the request data.

Examples:
  snyk-api-cli create-broker-connection-integration 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321 11111111-1111-1111-1111-111111111111 --data '{"data":{"integration_id":"integration-uuid","type":"broker_integration"}}'
  snyk-api-cli create-broker-connection-integration 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321 11111111-1111-1111-1111-111111111111 --data '{"data":{"integration_id":"integration-uuid","type":"broker_integration"}}' --verbose`,
	Args: cobra.ExactArgs(3),
	RunE: runCreateBrokerConnectionIntegration,
}

var (
	createBrokerConnectionIntegrationData        string
	createBrokerConnectionIntegrationVerbose     bool
	createBrokerConnectionIntegrationSilent      bool
	createBrokerConnectionIntegrationIncludeResp bool
	createBrokerConnectionIntegrationUserAgent   string
)

func init() {
	// Add flags for request data
	CreateBrokerConnectionIntegrationCmd.Flags().StringVarP(&createBrokerConnectionIntegrationData, "data", "d", "", "JSON data to send in request body")

	// Add standard flags like other commands
	CreateBrokerConnectionIntegrationCmd.Flags().BoolVarP(&createBrokerConnectionIntegrationVerbose, "verbose", "v", false, "Make the operation more talkative")
	CreateBrokerConnectionIntegrationCmd.Flags().BoolVarP(&createBrokerConnectionIntegrationSilent, "silent", "s", false, "Silent mode")
	CreateBrokerConnectionIntegrationCmd.Flags().BoolVarP(&createBrokerConnectionIntegrationIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	CreateBrokerConnectionIntegrationCmd.Flags().StringVarP(&createBrokerConnectionIntegrationUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")

	// Mark data flag as required
	CreateBrokerConnectionIntegrationCmd.MarkFlagRequired("data")
}

func runCreateBrokerConnectionIntegration(cmd *cobra.Command, args []string) error {
	tenantID := args[0]
	connectionID := args[1]
	orgID := args[2]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Build the URL with query parameters
	fullURL, err := buildCreateBrokerConnectionIntegrationURL(endpoint, version, tenantID, connectionID, orgID)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	if createBrokerConnectionIntegrationVerbose {
		fmt.Fprintf(os.Stderr, "* Requesting POST %s\n", fullURL)
	}

	// Create the HTTP request
	var body io.Reader
	if createBrokerConnectionIntegrationData != "" {
		body = strings.NewReader(createBrokerConnectionIntegrationData)
	}

	req, err := http.NewRequest("POST", fullURL, body)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Set content type for JSON data
	if createBrokerConnectionIntegrationData != "" {
		req.Header.Set("Content-Type", "application/vnd.api+json")
	}

	// Handle authentication with same precedence as curl: Authorization header > SNYK_TOKEN > OAuth
	if createBrokerConnectionIntegrationVerbose {
		fmt.Fprintf(os.Stderr, "* Checking authentication options\n")
	}

	authHeader, err := buildAuthHeader([]string{}) // No manual headers for this command
	if err != nil {
		if createBrokerConnectionIntegrationVerbose {
			fmt.Fprintf(os.Stderr, "* Warning: failed to get automatic auth: %v\n", err)
		}
		// Don't fail the request, just proceed without automatic auth
	} else if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
		if createBrokerConnectionIntegrationVerbose {
			fmt.Fprintf(os.Stderr, "* Added automatic authorization header\n")
		}
	} else if createBrokerConnectionIntegrationVerbose {
		fmt.Fprintf(os.Stderr, "* No automatic authorization available\n")
	}

	// Set user agent
	req.Header.Set("User-Agent", createBrokerConnectionIntegrationUserAgent)

	// Make the request
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	if createBrokerConnectionIntegrationVerbose {
		fmt.Fprintf(os.Stderr, "* Making request...\n")
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// Handle response using the same pattern as other commands
	return handleCreateBrokerConnectionIntegrationResponse(resp, createBrokerConnectionIntegrationIncludeResp, createBrokerConnectionIntegrationVerbose, createBrokerConnectionIntegrationSilent)
}

func buildCreateBrokerConnectionIntegrationURL(endpoint, version, tenantID, connectionID, orgID string) (string, error) {
	// Build base URL
	baseURL := fmt.Sprintf("https://%s/rest/tenants/%s/brokers/connections/%s/orgs/%s/integration", endpoint, tenantID, connectionID, orgID)

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

func handleCreateBrokerConnectionIntegrationResponse(resp *http.Response, includeResp, verbose, silent bool) error {
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