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

// DeleteBrokerContextIntegrationCmd represents the delete-broker-context-integration command
var DeleteBrokerContextIntegrationCmd = &cobra.Command{
	Use:   "delete-broker-context-integration [tenant_id] [install_id] [context_id] [integration_id]",
	Short: "Deletes the Broker context association with an Integration",
	Long: `Deletes the Broker context association with an Integration from the Snyk API.

This command deletes the association between a broker context and an integration within a tenant and installation.
The integration association will be permanently removed from the broker context.

Examples:
  snyk-api-cli delete-broker-context-integration 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321 11111111-1111-1111-1111-111111111111 22222222-2222-2222-2222-222222222222
  snyk-api-cli delete-broker-context-integration 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321 11111111-1111-1111-1111-111111111111 22222222-2222-2222-2222-222222222222 --verbose`,
	Args: cobra.ExactArgs(4),
	RunE: runDeleteBrokerContextIntegration,
}

var (
	deleteBrokerContextIntegrationVerbose     bool
	deleteBrokerContextIntegrationSilent      bool
	deleteBrokerContextIntegrationIncludeResp bool
	deleteBrokerContextIntegrationUserAgent   string
)

func init() {
	// Add standard flags like other commands
	DeleteBrokerContextIntegrationCmd.Flags().BoolVarP(&deleteBrokerContextIntegrationVerbose, "verbose", "v", false, "Make the operation more talkative")
	DeleteBrokerContextIntegrationCmd.Flags().BoolVarP(&deleteBrokerContextIntegrationSilent, "silent", "s", false, "Silent mode")
	DeleteBrokerContextIntegrationCmd.Flags().BoolVarP(&deleteBrokerContextIntegrationIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	DeleteBrokerContextIntegrationCmd.Flags().StringVarP(&deleteBrokerContextIntegrationUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")
}

func runDeleteBrokerContextIntegration(cmd *cobra.Command, args []string) error {
	tenantID := args[0]
	installID := args[1]
	contextID := args[2]
	integrationID := args[3]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Build the URL with query parameters
	fullURL, err := buildDeleteBrokerContextIntegrationURL(endpoint, version, tenantID, installID, contextID, integrationID)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	if deleteBrokerContextIntegrationVerbose {
		fmt.Fprintf(os.Stderr, "* Requesting DELETE %s\n", fullURL)
	}

	// Create the HTTP request
	req, err := http.NewRequest("DELETE", fullURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Handle authentication with same precedence as curl: Authorization header > SNYK_TOKEN > OAuth
	if deleteBrokerContextIntegrationVerbose {
		fmt.Fprintf(os.Stderr, "* Checking authentication options\n")
	}

	authHeader, err := buildAuthHeader([]string{}) // No manual headers for this command
	if err != nil {
		if deleteBrokerContextIntegrationVerbose {
			fmt.Fprintf(os.Stderr, "* Warning: failed to get automatic auth: %v\n", err)
		}
		// Don't fail the request, just proceed without automatic auth
	} else if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
		if deleteBrokerContextIntegrationVerbose {
			fmt.Fprintf(os.Stderr, "* Added automatic authorization header\n")
		}
	} else if deleteBrokerContextIntegrationVerbose {
		fmt.Fprintf(os.Stderr, "* No automatic authorization available\n")
	}

	// Set user agent
	req.Header.Set("User-Agent", deleteBrokerContextIntegrationUserAgent)

	// Make the request
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	if deleteBrokerContextIntegrationVerbose {
		fmt.Fprintf(os.Stderr, "* Making request...\n")
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// Handle response using the same pattern as other commands
	return handleDeleteBrokerContextIntegrationResponse(resp, deleteBrokerContextIntegrationIncludeResp, deleteBrokerContextIntegrationVerbose, deleteBrokerContextIntegrationSilent)
}

func buildDeleteBrokerContextIntegrationURL(endpoint, version, tenantID, installID, contextID, integrationID string) (string, error) {
	// Build base URL
	baseURL := fmt.Sprintf("https://%s/rest/tenants/%s/brokers/installs/%s/contexts/%s/integrations/%s", endpoint, tenantID, installID, contextID, integrationID)

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

func handleDeleteBrokerContextIntegrationResponse(resp *http.Response, includeResp, verbose, silent bool) error {
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