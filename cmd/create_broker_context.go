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

// CreateBrokerContextCmd represents the create-broker-context command
var CreateBrokerContextCmd = &cobra.Command{
	Use:   "create-broker-context [tenant_id] [install_id] [deployment_id]",
	Short: "Create broker Context",
	Long: `Create broker Context from the Snyk API.

This command creates a new broker context for a specific tenant, install ID, and deployment ID.
The request data should be provided in JSON format with connection_id and context attributes.

Examples:
  snyk-api-cli create-broker-context 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321 11111111-1111-1111-1111-111111111111 --data '{"data":{"type":"broker_context","attributes":{"connection_id":"22222222-2222-2222-2222-222222222222","context":{}}}}'
  snyk-api-cli create-broker-context 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321 11111111-1111-1111-1111-111111111111 --data '{"data":{"type":"broker_context","attributes":{"connection_id":"22222222-2222-2222-2222-222222222222","context":{}}}}' --verbose`,
	Args: cobra.ExactArgs(3),
	RunE: runCreateBrokerContext,
}

var (
	createBrokerContextData        string
	createBrokerContextVerbose     bool
	createBrokerContextSilent      bool
	createBrokerContextIncludeResp bool
	createBrokerContextUserAgent   string
)

func init() {
	// Add flags for request data
	CreateBrokerContextCmd.Flags().StringVarP(&createBrokerContextData, "data", "d", "", "JSON data to send in request body")

	// Add standard flags like other commands
	CreateBrokerContextCmd.Flags().BoolVarP(&createBrokerContextVerbose, "verbose", "v", false, "Make the operation more talkative")
	CreateBrokerContextCmd.Flags().BoolVarP(&createBrokerContextSilent, "silent", "s", false, "Silent mode")
	CreateBrokerContextCmd.Flags().BoolVarP(&createBrokerContextIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	CreateBrokerContextCmd.Flags().StringVarP(&createBrokerContextUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")

	// Mark data flag as required
	CreateBrokerContextCmd.MarkFlagRequired("data")
}

func runCreateBrokerContext(cmd *cobra.Command, args []string) error {
	tenantID := args[0]
	installID := args[1]
	deploymentID := args[2]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Build the URL with query parameters
	fullURL, err := buildCreateBrokerContextURL(endpoint, version, tenantID, installID, deploymentID)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	if createBrokerContextVerbose {
		fmt.Fprintf(os.Stderr, "* Requesting POST %s\n", fullURL)
	}

	// Create the HTTP request
	var body io.Reader
	if createBrokerContextData != "" {
		body = strings.NewReader(createBrokerContextData)
	}

	req, err := http.NewRequest("POST", fullURL, body)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Set content type for JSON data
	if createBrokerContextData != "" {
		req.Header.Set("Content-Type", "application/vnd.api+json")
	}

	// Handle authentication with same precedence as curl: Authorization header > SNYK_TOKEN > OAuth
	if createBrokerContextVerbose {
		fmt.Fprintf(os.Stderr, "* Checking authentication options\n")
	}

	authHeader, err := buildAuthHeader([]string{}) // No manual headers for this command
	if err != nil {
		if createBrokerContextVerbose {
			fmt.Fprintf(os.Stderr, "* Warning: failed to get automatic auth: %v\n", err)
		}
		// Don't fail the request, just proceed without automatic auth
	} else if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
		if createBrokerContextVerbose {
			fmt.Fprintf(os.Stderr, "* Added automatic authorization header\n")
		}
	} else if createBrokerContextVerbose {
		fmt.Fprintf(os.Stderr, "* No automatic authorization available\n")
	}

	// Set user agent
	req.Header.Set("User-Agent", createBrokerContextUserAgent)

	// Make the request
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	if createBrokerContextVerbose {
		fmt.Fprintf(os.Stderr, "* Making request...\n")
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// Handle response using the same pattern as other commands
	return handleCreateBrokerContextResponse(resp, createBrokerContextIncludeResp, createBrokerContextVerbose, createBrokerContextSilent)
}

func buildCreateBrokerContextURL(endpoint, version, tenantID, installID, deploymentID string) (string, error) {
	// Build base URL
	baseURL := fmt.Sprintf("https://%s/rest/tenants/%s/brokers/installs/%s/deployments/%s/contexts", endpoint, tenantID, installID, deploymentID)

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

func handleCreateBrokerContextResponse(resp *http.Response, includeResp, verbose, silent bool) error {
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