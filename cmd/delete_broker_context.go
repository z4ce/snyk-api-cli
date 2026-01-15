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

// DeleteBrokerContextCmd represents the delete-broker-context command
var DeleteBrokerContextCmd = &cobra.Command{
	Use:   "delete-broker-context [tenant_id] [install_id] [context_id]",
	Short: "Deletes broker context",
	Long: `Deletes broker context from the Snyk API.

This command deletes a broker context configuration for a specific tenant and installation.
The broker context will be permanently removed.

Examples:
  snyk-api-cli delete-broker-context 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321 11111111-1111-1111-1111-111111111111
  snyk-api-cli delete-broker-context 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321 11111111-1111-1111-1111-111111111111 --verbose`,
	Args: cobra.ExactArgs(3),
	RunE: runDeleteBrokerContext,
}

var (
	deleteBrokerContextVerbose     bool
	deleteBrokerContextSilent      bool
	deleteBrokerContextIncludeResp bool
	deleteBrokerContextUserAgent   string
)

func init() {
	// Add standard flags like other commands
	DeleteBrokerContextCmd.Flags().BoolVarP(&deleteBrokerContextVerbose, "verbose", "v", false, "Make the operation more talkative")
	DeleteBrokerContextCmd.Flags().BoolVarP(&deleteBrokerContextSilent, "silent", "s", false, "Silent mode")
	DeleteBrokerContextCmd.Flags().BoolVarP(&deleteBrokerContextIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	DeleteBrokerContextCmd.Flags().StringVarP(&deleteBrokerContextUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")
}

func runDeleteBrokerContext(cmd *cobra.Command, args []string) error {
	tenantID := args[0]
	installID := args[1]
	contextID := args[2]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Build the URL with query parameters
	fullURL, err := buildDeleteBrokerContextURL(endpoint, version, tenantID, installID, contextID)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	if deleteBrokerContextVerbose {
		fmt.Fprintf(os.Stderr, "* Requesting DELETE %s\n", fullURL)
	}

	// Create the HTTP request
	req, err := http.NewRequest("DELETE", fullURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Handle authentication with same precedence as curl: Authorization header > SNYK_TOKEN > OAuth
	if deleteBrokerContextVerbose {
		fmt.Fprintf(os.Stderr, "* Checking authentication options\n")
	}

	authHeader, err := buildAuthHeader([]string{}) // No manual headers for this command
	if err != nil {
		if deleteBrokerContextVerbose {
			fmt.Fprintf(os.Stderr, "* Warning: failed to get automatic auth: %v\n", err)
		}
		// Don't fail the request, just proceed without automatic auth
	} else if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
		if deleteBrokerContextVerbose {
			fmt.Fprintf(os.Stderr, "* Added automatic authorization header\n")
		}
	} else if deleteBrokerContextVerbose {
		fmt.Fprintf(os.Stderr, "* No automatic authorization available\n")
	}

	// Set user agent
	req.Header.Set("User-Agent", deleteBrokerContextUserAgent)

	// Make the request
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	if deleteBrokerContextVerbose {
		fmt.Fprintf(os.Stderr, "* Making request...\n")
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// Handle response using the same pattern as other commands
	return handleDeleteBrokerContextResponse(resp, deleteBrokerContextIncludeResp, deleteBrokerContextVerbose, deleteBrokerContextSilent)
}

func buildDeleteBrokerContextURL(endpoint, version, tenantID, installID, contextID string) (string, error) {
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

func handleDeleteBrokerContextResponse(resp *http.Response, includeResp, verbose, silent bool) error {
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