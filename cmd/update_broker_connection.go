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

// UpdateBrokerConnectionCmd represents the update-broker-connection command
var UpdateBrokerConnectionCmd = &cobra.Command{
	Use:   "update-broker-connection [tenant_id] [install_id] [deployment_id] [connection_id]",
	Short: "Updates Broker connection",
	Long: `Updates Broker connection from the Snyk API.

This command updates an existing broker connection for a specific tenant, install ID, deployment ID, and connection ID.
The request data should be provided in JSON format.

Examples:
  snyk-api-cli update-broker-connection 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321 11111111-1111-1111-1111-111111111111 22222222-2222-2222-2222-222222222222 --data '{"data":{"type":"broker_connection","id":"22222222-2222-2222-2222-222222222222","attributes":{}}}'
  snyk-api-cli update-broker-connection 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321 11111111-1111-1111-1111-111111111111 22222222-2222-2222-2222-222222222222 --data '{"data":{"type":"broker_connection","id":"22222222-2222-2222-2222-222222222222","attributes":{}}}' --verbose`,
	Args: cobra.ExactArgs(4),
	RunE: runUpdateBrokerConnection,
}

var (
	updateBrokerConnectionData        string
	updateBrokerConnectionVerbose     bool
	updateBrokerConnectionSilent      bool
	updateBrokerConnectionIncludeResp bool
	updateBrokerConnectionUserAgent   string
)

func init() {
	// Add flags for request data
	UpdateBrokerConnectionCmd.Flags().StringVarP(&updateBrokerConnectionData, "data", "d", "", "JSON data to send in request body")

	// Add standard flags like other commands
	UpdateBrokerConnectionCmd.Flags().BoolVarP(&updateBrokerConnectionVerbose, "verbose", "v", false, "Make the operation more talkative")
	UpdateBrokerConnectionCmd.Flags().BoolVarP(&updateBrokerConnectionSilent, "silent", "s", false, "Silent mode")
	UpdateBrokerConnectionCmd.Flags().BoolVarP(&updateBrokerConnectionIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	UpdateBrokerConnectionCmd.Flags().StringVarP(&updateBrokerConnectionUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")

	// Mark data flag as required
	UpdateBrokerConnectionCmd.MarkFlagRequired("data")
}

func runUpdateBrokerConnection(cmd *cobra.Command, args []string) error {
	tenantID := args[0]
	installID := args[1]
	deploymentID := args[2]
	connectionID := args[3]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Build the URL with query parameters
	fullURL, err := buildUpdateBrokerConnectionURL(endpoint, version, tenantID, installID, deploymentID, connectionID)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	if updateBrokerConnectionVerbose {
		fmt.Fprintf(os.Stderr, "* Requesting PATCH %s\n", fullURL)
	}

	// Create the HTTP request
	var body io.Reader
	if updateBrokerConnectionData != "" {
		body = strings.NewReader(updateBrokerConnectionData)
	}

	req, err := http.NewRequest("PATCH", fullURL, body)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Set content type for JSON data
	if updateBrokerConnectionData != "" {
		req.Header.Set("Content-Type", "application/vnd.api+json")
	}

	// Handle authentication with same precedence as curl: Authorization header > SNYK_TOKEN > OAuth
	if updateBrokerConnectionVerbose {
		fmt.Fprintf(os.Stderr, "* Checking authentication options\n")
	}

	authHeader, err := buildAuthHeader([]string{}) // No manual headers for this command
	if err != nil {
		if updateBrokerConnectionVerbose {
			fmt.Fprintf(os.Stderr, "* Warning: failed to get automatic auth: %v\n", err)
		}
		// Don't fail the request, just proceed without automatic auth
	} else if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
		if updateBrokerConnectionVerbose {
			fmt.Fprintf(os.Stderr, "* Added automatic authorization header\n")
		}
	} else if updateBrokerConnectionVerbose {
		fmt.Fprintf(os.Stderr, "* No automatic authorization available\n")
	}

	// Set user agent
	req.Header.Set("User-Agent", updateBrokerConnectionUserAgent)

	// Make the request
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	if updateBrokerConnectionVerbose {
		fmt.Fprintf(os.Stderr, "* Making request...\n")
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// Handle response using the same pattern as other commands
	return handleUpdateBrokerConnectionResponse(resp, updateBrokerConnectionIncludeResp, updateBrokerConnectionVerbose, updateBrokerConnectionSilent)
}

func buildUpdateBrokerConnectionURL(endpoint, version, tenantID, installID, deploymentID, connectionID string) (string, error) {
	// Build base URL
	baseURL := fmt.Sprintf("https://%s/rest/tenants/%s/brokers/installs/%s/deployments/%s/connections/%s", endpoint, tenantID, installID, deploymentID, connectionID)

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

func handleUpdateBrokerConnectionResponse(resp *http.Response, includeResp, verbose, silent bool) error {
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