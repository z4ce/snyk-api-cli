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

// GetBrokerConnectionIntegrationsCmd represents the get-broker-connection-integrations command
var GetBrokerConnectionIntegrationsCmd = &cobra.Command{
	Use:   "get-broker-connection-integrations [tenant_id] [connection_id]",
	Short: "Get Integrations using the current Broker connection",
	Long: `Get Integrations using the current Broker connection from the Snyk API.

This command retrieves a list of integrations for a specific broker connection within a tenant.
The results can be paginated using various query parameters.

Examples:
  snyk-api-cli get-broker-connection-integrations 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321
  snyk-api-cli get-broker-connection-integrations 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321 --limit 10
  snyk-api-cli get-broker-connection-integrations 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321 --starting-after abc123
  snyk-api-cli get-broker-connection-integrations 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321 --ending-before xyz789
  snyk-api-cli get-broker-connection-integrations 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321 --verbose`,
	Args: cobra.ExactArgs(2),
	RunE: runGetBrokerConnectionIntegrations,
}

var (
	getBrokerConnectionIntegrationsStartingAfter string
	getBrokerConnectionIntegrationsEndingBefore  string
	getBrokerConnectionIntegrationsLimit         int
	getBrokerConnectionIntegrationsVerbose       bool
	getBrokerConnectionIntegrationsSilent        bool
	getBrokerConnectionIntegrationsIncludeResp   bool
	getBrokerConnectionIntegrationsUserAgent     string
)

func init() {
	// Add flags for query parameters
	GetBrokerConnectionIntegrationsCmd.Flags().StringVar(&getBrokerConnectionIntegrationsStartingAfter, "starting-after", "", "Return the page of results immediately after this cursor")
	GetBrokerConnectionIntegrationsCmd.Flags().StringVar(&getBrokerConnectionIntegrationsEndingBefore, "ending-before", "", "Return the page of results immediately before this cursor")
	GetBrokerConnectionIntegrationsCmd.Flags().IntVar(&getBrokerConnectionIntegrationsLimit, "limit", 0, "Number of results to return per page")

	// Add standard flags like other commands
	GetBrokerConnectionIntegrationsCmd.Flags().BoolVarP(&getBrokerConnectionIntegrationsVerbose, "verbose", "v", false, "Make the operation more talkative")
	GetBrokerConnectionIntegrationsCmd.Flags().BoolVarP(&getBrokerConnectionIntegrationsSilent, "silent", "s", false, "Silent mode")
	GetBrokerConnectionIntegrationsCmd.Flags().BoolVarP(&getBrokerConnectionIntegrationsIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	GetBrokerConnectionIntegrationsCmd.Flags().StringVarP(&getBrokerConnectionIntegrationsUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")
}

func runGetBrokerConnectionIntegrations(cmd *cobra.Command, args []string) error {
	tenantID := args[0]
	connectionID := args[1]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Build the URL with query parameters
	fullURL, err := buildGetBrokerConnectionIntegrationsURL(endpoint, version, tenantID, connectionID, cmd)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	if getBrokerConnectionIntegrationsVerbose {
		fmt.Fprintf(os.Stderr, "* Requesting GET %s\n", fullURL)
	}

	// Create the HTTP request
	req, err := http.NewRequest("GET", fullURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Handle authentication with same precedence as curl: Authorization header > SNYK_TOKEN > OAuth
	if getBrokerConnectionIntegrationsVerbose {
		fmt.Fprintf(os.Stderr, "* Checking authentication options\n")
	}

	authHeader, err := buildAuthHeader([]string{}) // No manual headers for this command
	if err != nil {
		if getBrokerConnectionIntegrationsVerbose {
			fmt.Fprintf(os.Stderr, "* Warning: failed to get automatic auth: %v\n", err)
		}
		// Don't fail the request, just proceed without automatic auth
	} else if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
		if getBrokerConnectionIntegrationsVerbose {
			fmt.Fprintf(os.Stderr, "* Added automatic authorization header\n")
		}
	} else if getBrokerConnectionIntegrationsVerbose {
		fmt.Fprintf(os.Stderr, "* No automatic authorization available\n")
	}

	// Set user agent
	req.Header.Set("User-Agent", getBrokerConnectionIntegrationsUserAgent)

	// Make the request
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	if getBrokerConnectionIntegrationsVerbose {
		fmt.Fprintf(os.Stderr, "* Making request...\n")
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// Handle response using the same pattern as other commands
	return handleGetBrokerConnectionIntegrationsResponse(resp, getBrokerConnectionIntegrationsIncludeResp, getBrokerConnectionIntegrationsVerbose, getBrokerConnectionIntegrationsSilent)
}

func buildGetBrokerConnectionIntegrationsURL(endpoint, version, tenantID, connectionID string, cmd *cobra.Command) (string, error) {
	// Build base URL
	baseURL := fmt.Sprintf("https://%s/rest/tenants/%s/brokers/connections/%s/integrations", endpoint, tenantID, connectionID)

	// Parse URL to handle query parameters properly
	u, err := url.Parse(baseURL)
	if err != nil {
		return "", err
	}

	// Add query parameters
	q := u.Query()

	// Version is required
	q.Set("version", version)

	// Add optional parameters if provided
	if getBrokerConnectionIntegrationsStartingAfter != "" {
		q.Set("starting_after", getBrokerConnectionIntegrationsStartingAfter)
	}
	if getBrokerConnectionIntegrationsEndingBefore != "" {
		q.Set("ending_before", getBrokerConnectionIntegrationsEndingBefore)
	}
	if getBrokerConnectionIntegrationsLimit > 0 {
		q.Set("limit", fmt.Sprintf("%d", getBrokerConnectionIntegrationsLimit))
	}

	u.RawQuery = q.Encode()
	return u.String(), nil
}

func handleGetBrokerConnectionIntegrationsResponse(resp *http.Response, includeResp, verbose, silent bool) error {
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