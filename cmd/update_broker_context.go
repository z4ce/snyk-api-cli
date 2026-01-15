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

// UpdateBrokerContextCmd represents the update-broker-context command
var UpdateBrokerContextCmd = &cobra.Command{
	Use:   "update-broker-context [tenant_id] [install_id] [context_id]",
	Short: "Updates Broker Context",
	Long: `Updates Broker Context from the Snyk API.

This command updates a broker context configuration for a specific tenant and installation.
The request must include the context data, id, and type in the JSON payload.

Examples:
  snyk-api-cli update-broker-context 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321 11111111-1111-1111-1111-111111111111 --data '{"data":{"attributes":{"context":{}},"id":"11111111-1111-1111-1111-111111111111","type":"broker_context"}}'
  snyk-api-cli update-broker-context 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321 11111111-1111-1111-1111-111111111111 --data '{"data":{"attributes":{"context":{"key":"value"}},"id":"11111111-1111-1111-1111-111111111111","type":"broker_context"}}' --verbose`,
	Args: cobra.ExactArgs(3),
	RunE: runUpdateBrokerContext,
}

var (
	updateBrokerContextData        string
	updateBrokerContextVerbose     bool
	updateBrokerContextSilent      bool
	updateBrokerContextIncludeResp bool
	updateBrokerContextUserAgent   string
)

func init() {
	// Add flags for request data
	UpdateBrokerContextCmd.Flags().StringVarP(&updateBrokerContextData, "data", "d", "", "JSON data to send in request body")

	// Add standard flags like other commands
	UpdateBrokerContextCmd.Flags().BoolVarP(&updateBrokerContextVerbose, "verbose", "v", false, "Make the operation more talkative")
	UpdateBrokerContextCmd.Flags().BoolVarP(&updateBrokerContextSilent, "silent", "s", false, "Silent mode")
	UpdateBrokerContextCmd.Flags().BoolVarP(&updateBrokerContextIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	UpdateBrokerContextCmd.Flags().StringVarP(&updateBrokerContextUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")

	// Mark data flag as required
	UpdateBrokerContextCmd.MarkFlagRequired("data")
}

func runUpdateBrokerContext(cmd *cobra.Command, args []string) error {
	tenantID := args[0]
	installID := args[1]
	contextID := args[2]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Build the URL with query parameters
	fullURL, err := buildUpdateBrokerContextURL(endpoint, version, tenantID, installID, contextID)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	if updateBrokerContextVerbose {
		fmt.Fprintf(os.Stderr, "* Requesting PATCH %s\n", fullURL)
	}

	// Create the HTTP request
	var body io.Reader
	if updateBrokerContextData != "" {
		body = strings.NewReader(updateBrokerContextData)
	}

	req, err := http.NewRequest("PATCH", fullURL, body)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Set content type for JSON data
	if updateBrokerContextData != "" {
		req.Header.Set("Content-Type", "application/vnd.api+json")
	}

	// Handle authentication with same precedence as curl: Authorization header > SNYK_TOKEN > OAuth
	if updateBrokerContextVerbose {
		fmt.Fprintf(os.Stderr, "* Checking authentication options\n")
	}

	authHeader, err := buildAuthHeader([]string{}) // No manual headers for this command
	if err != nil {
		if updateBrokerContextVerbose {
			fmt.Fprintf(os.Stderr, "* Warning: failed to get automatic auth: %v\n", err)
		}
		// Don't fail the request, just proceed without automatic auth
	} else if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
		if updateBrokerContextVerbose {
			fmt.Fprintf(os.Stderr, "* Added automatic authorization header\n")
		}
	} else if updateBrokerContextVerbose {
		fmt.Fprintf(os.Stderr, "* No automatic authorization available\n")
	}

	// Set user agent
	req.Header.Set("User-Agent", updateBrokerContextUserAgent)

	// Make the request
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	if updateBrokerContextVerbose {
		fmt.Fprintf(os.Stderr, "* Making request...\n")
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// Handle response using the same pattern as other commands
	return handleUpdateBrokerContextResponse(resp, updateBrokerContextIncludeResp, updateBrokerContextVerbose, updateBrokerContextSilent)
}

func buildUpdateBrokerContextURL(endpoint, version, tenantID, installID, contextID string) (string, error) {
	// Build base URL
	baseURL := fmt.Sprintf("https://%s/rest/tenants/%s/brokers/installs/%s/contexts/%s", endpoint, tenantID, installID, contextID)

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

func handleUpdateBrokerContextResponse(resp *http.Response, includeResp, verbose, silent bool) error {
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