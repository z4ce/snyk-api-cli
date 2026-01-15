package cmd

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// DeleteBrokerConnectionIntegrationCmd represents the delete-broker-connection-integration command
var DeleteBrokerConnectionIntegrationCmd = &cobra.Command{
	Use:   "delete-broker-connection-integration [tenant_id] [connection_id] [org_id] [integration_id]",
	Short: "Deletes an Integration for a Broker connection",
	Long: `Deletes an Integration for a Broker connection from the Snyk API.

This command deletes an integration configuration for a specific broker connection within a tenant and organization.
The integration will be permanently removed from the broker connection.

Examples:
  snyk-api-cli delete-broker-connection-integration 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321 11111111-1111-1111-1111-111111111111 22222222-2222-2222-2222-222222222222
  snyk-api-cli delete-broker-connection-integration 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321 11111111-1111-1111-1111-111111111111 22222222-2222-2222-2222-222222222222 --verbose`,
	Args: cobra.ExactArgs(4),
	RunE: runDeleteBrokerConnectionIntegration,
}

var (
	deleteBrokerConnectionIntegrationVerbose     bool
	deleteBrokerConnectionIntegrationSilent      bool
	deleteBrokerConnectionIntegrationIncludeResp bool
	deleteBrokerConnectionIntegrationUserAgent   string
)

func init() {
	// Add standard flags like other commands
	DeleteBrokerConnectionIntegrationCmd.Flags().BoolVarP(&deleteBrokerConnectionIntegrationVerbose, "verbose", "v", false, "Make the operation more talkative")
	DeleteBrokerConnectionIntegrationCmd.Flags().BoolVarP(&deleteBrokerConnectionIntegrationSilent, "silent", "s", false, "Silent mode")
	DeleteBrokerConnectionIntegrationCmd.Flags().BoolVarP(&deleteBrokerConnectionIntegrationIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	DeleteBrokerConnectionIntegrationCmd.Flags().StringVarP(&deleteBrokerConnectionIntegrationUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")
}

func runDeleteBrokerConnectionIntegration(cmd *cobra.Command, args []string) error {
	tenantID := args[0]
	connectionID := args[1]
	orgID := args[2]
	integrationID := args[3]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Build the URL with query parameters
	fullURL, err := buildDeleteBrokerConnectionIntegrationURL(endpoint, version, tenantID, connectionID, orgID, integrationID)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	if deleteBrokerConnectionIntegrationVerbose {
		fmt.Fprintf(os.Stderr, "* Requesting DELETE %s\n", fullURL)
	}

	// Create the HTTP request
	req, err := http.NewRequest("DELETE", fullURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Handle authentication with same precedence as curl: Authorization header > SNYK_TOKEN > OAuth
	if deleteBrokerConnectionIntegrationVerbose {
		fmt.Fprintf(os.Stderr, "* Checking authentication options\n")
	}

	authHeader, err := buildAuthHeader([]string{}) // No manual headers for this command
	if err != nil {
		if deleteBrokerConnectionIntegrationVerbose {
			fmt.Fprintf(os.Stderr, "* Warning: failed to get automatic auth: %v\n", err)
		}
		// Don't fail the request, just proceed without automatic auth
	} else if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
		if deleteBrokerConnectionIntegrationVerbose {
			fmt.Fprintf(os.Stderr, "* Added automatic authorization header\n")
		}
	} else if deleteBrokerConnectionIntegrationVerbose {
		fmt.Fprintf(os.Stderr, "* No automatic authorization available\n")
	}

	// Set user agent
	req.Header.Set("User-Agent", deleteBrokerConnectionIntegrationUserAgent)

	// Make the request
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	if deleteBrokerConnectionIntegrationVerbose {
		fmt.Fprintf(os.Stderr, "* Making request...\n")
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// Handle response using the same pattern as other commands
	return handleDeleteBrokerConnectionIntegrationResponse(resp, deleteBrokerConnectionIntegrationIncludeResp, deleteBrokerConnectionIntegrationVerbose, deleteBrokerConnectionIntegrationSilent)
}

func buildDeleteBrokerConnectionIntegrationURL(endpoint, version, tenantID, connectionID, orgID, integrationID string) (string, error) {
	// Build base URL
	baseURL := fmt.Sprintf("https://%s/rest/tenants/%s/brokers/connections/%s/orgs/%s/integrations/%s", endpoint, tenantID, connectionID, orgID, integrationID)

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

func handleDeleteBrokerConnectionIntegrationResponse(resp *http.Response, includeResp, verbose, silent bool) error {
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