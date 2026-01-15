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

// CreateBrokerOrgsForBulkMigrationCmd represents the create-broker-orgs-for-bulk-migration command
var CreateBrokerOrgsForBulkMigrationCmd = &cobra.Command{
	Use:   "create-broker-orgs-for-bulk-migration [tenant_id] [install_id] [deployment_id] [connection_id]",
	Short: "Performs bulk migration integrations to universal broker",
	Long: `Performs bulk migration integrations to universal broker from the Snyk API.

This command performs bulk migration integrations from legacy to universal broker for a specific tenant, install ID, deployment ID, and connection ID.
The request data should be provided in JSON format.

Examples:
  snyk-api-cli create-broker-orgs-for-bulk-migration 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321 11111111-1111-1111-1111-111111111111 22222222-2222-2222-2222-222222222222 --data '{"data":{"type":"broker_migration"}}'
  snyk-api-cli create-broker-orgs-for-bulk-migration 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321 11111111-1111-1111-1111-111111111111 22222222-2222-2222-2222-222222222222 --data '{"data":{"type":"broker_migration"}}' --verbose`,
	Args: cobra.ExactArgs(4),
	RunE: runCreateBrokerOrgsForBulkMigration,
}

var (
	createBrokerOrgsForBulkMigrationData        string
	createBrokerOrgsForBulkMigrationVerbose     bool
	createBrokerOrgsForBulkMigrationSilent      bool
	createBrokerOrgsForBulkMigrationIncludeResp bool
	createBrokerOrgsForBulkMigrationUserAgent   string
)

func init() {
	// Add flags for request data
	CreateBrokerOrgsForBulkMigrationCmd.Flags().StringVarP(&createBrokerOrgsForBulkMigrationData, "data", "d", "", "JSON data to send in request body")

	// Add standard flags like other commands
	CreateBrokerOrgsForBulkMigrationCmd.Flags().BoolVarP(&createBrokerOrgsForBulkMigrationVerbose, "verbose", "v", false, "Make the operation more talkative")
	CreateBrokerOrgsForBulkMigrationCmd.Flags().BoolVarP(&createBrokerOrgsForBulkMigrationSilent, "silent", "s", false, "Silent mode")
	CreateBrokerOrgsForBulkMigrationCmd.Flags().BoolVarP(&createBrokerOrgsForBulkMigrationIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	CreateBrokerOrgsForBulkMigrationCmd.Flags().StringVarP(&createBrokerOrgsForBulkMigrationUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")

	// Mark data flag as required
	CreateBrokerOrgsForBulkMigrationCmd.MarkFlagRequired("data")
}

func runCreateBrokerOrgsForBulkMigration(cmd *cobra.Command, args []string) error {
	tenantID := args[0]
	installID := args[1]
	deploymentID := args[2]
	connectionID := args[3]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Build the URL with query parameters
	fullURL, err := buildCreateBrokerOrgsForBulkMigrationURL(endpoint, version, tenantID, installID, deploymentID, connectionID)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	if createBrokerOrgsForBulkMigrationVerbose {
		fmt.Fprintf(os.Stderr, "* Requesting POST %s\n", fullURL)
	}

	// Create the HTTP request
	var body io.Reader
	if createBrokerOrgsForBulkMigrationData != "" {
		body = strings.NewReader(createBrokerOrgsForBulkMigrationData)
	}

	req, err := http.NewRequest("POST", fullURL, body)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Set content type for JSON data
	if createBrokerOrgsForBulkMigrationData != "" {
		req.Header.Set("Content-Type", "application/vnd.api+json")
	}

	// Handle authentication with same precedence as curl: Authorization header > SNYK_TOKEN > OAuth
	if createBrokerOrgsForBulkMigrationVerbose {
		fmt.Fprintf(os.Stderr, "* Checking authentication options\n")
	}

	authHeader, err := buildAuthHeader([]string{}) // No manual headers for this command
	if err != nil {
		if createBrokerOrgsForBulkMigrationVerbose {
			fmt.Fprintf(os.Stderr, "* Warning: failed to get automatic auth: %v\n", err)
		}
		// Don't fail the request, just proceed without automatic auth
	} else if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
		if createBrokerOrgsForBulkMigrationVerbose {
			fmt.Fprintf(os.Stderr, "* Added automatic authorization header\n")
		}
	} else if createBrokerOrgsForBulkMigrationVerbose {
		fmt.Fprintf(os.Stderr, "* No automatic authorization available\n")
	}

	// Set user agent
	req.Header.Set("User-Agent", createBrokerOrgsForBulkMigrationUserAgent)

	// Make the request
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	if createBrokerOrgsForBulkMigrationVerbose {
		fmt.Fprintf(os.Stderr, "* Making request...\n")
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// Handle response using the same pattern as other commands
	return handleCreateBrokerOrgsForBulkMigrationResponse(resp, createBrokerOrgsForBulkMigrationIncludeResp, createBrokerOrgsForBulkMigrationVerbose, createBrokerOrgsForBulkMigrationSilent)
}

func buildCreateBrokerOrgsForBulkMigrationURL(endpoint, version, tenantID, installID, deploymentID, connectionID string) (string, error) {
	// Build base URL
	baseURL := fmt.Sprintf("https://%s/rest/tenants/%s/brokers/installs/%s/deployments/%s/connections/%s/bulk_migration", endpoint, tenantID, installID, deploymentID, connectionID)

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

func handleCreateBrokerOrgsForBulkMigrationResponse(resp *http.Response, includeResp, verbose, silent bool) error {
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