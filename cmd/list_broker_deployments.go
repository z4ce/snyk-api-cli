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

// ListBrokerDeploymentsCmd represents the list-broker-deployments command
var ListBrokerDeploymentsCmd = &cobra.Command{
	Use:   "list-broker-deployments [tenant_id] [install_id]",
	Short: "List Broker deployments",
	Long: `List Broker deployments for a specific tenant and install from the Snyk API.

This command retrieves a list of broker deployments for the specified tenant and install ID.
The results can be paginated using various query parameters.

Examples:
  snyk-api-cli list-broker-deployments 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321
  snyk-api-cli list-broker-deployments 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321 --limit 10
  snyk-api-cli list-broker-deployments 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321 --starting-after abc123
  snyk-api-cli list-broker-deployments 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321 --ending-before xyz789
  snyk-api-cli list-broker-deployments 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321 --verbose`,
	Args: cobra.ExactArgs(2),
	RunE: runListBrokerDeployments,
}

var (
	listBrokerDeploymentsStartingAfter string
	listBrokerDeploymentsEndingBefore  string
	listBrokerDeploymentsLimit         int
	listBrokerDeploymentsVerbose       bool
	listBrokerDeploymentsSilent        bool
	listBrokerDeploymentsIncludeResp   bool
	listBrokerDeploymentsUserAgent     string
)

func init() {
	// Add flags for query parameters
	ListBrokerDeploymentsCmd.Flags().StringVar(&listBrokerDeploymentsStartingAfter, "starting-after", "", "Return the page of results immediately after this cursor")
	ListBrokerDeploymentsCmd.Flags().StringVar(&listBrokerDeploymentsEndingBefore, "ending-before", "", "Return the page of results immediately before this cursor")
	ListBrokerDeploymentsCmd.Flags().IntVar(&listBrokerDeploymentsLimit, "limit", 0, "Number of results to return per page")

	// Add standard flags like other commands
	ListBrokerDeploymentsCmd.Flags().BoolVarP(&listBrokerDeploymentsVerbose, "verbose", "v", false, "Make the operation more talkative")
	ListBrokerDeploymentsCmd.Flags().BoolVarP(&listBrokerDeploymentsSilent, "silent", "s", false, "Silent mode")
	ListBrokerDeploymentsCmd.Flags().BoolVarP(&listBrokerDeploymentsIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	ListBrokerDeploymentsCmd.Flags().StringVarP(&listBrokerDeploymentsUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")
}

func runListBrokerDeployments(cmd *cobra.Command, args []string) error {
	tenantID := args[0]
	installID := args[1]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Build the URL with query parameters
	fullURL, err := buildListBrokerDeploymentsURL(endpoint, version, tenantID, installID, cmd)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	if listBrokerDeploymentsVerbose {
		fmt.Fprintf(os.Stderr, "* Requesting GET %s\n", fullURL)
	}

	// Create the HTTP request
	req, err := http.NewRequest("GET", fullURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Handle authentication with same precedence as curl: Authorization header > SNYK_TOKEN > OAuth
	if listBrokerDeploymentsVerbose {
		fmt.Fprintf(os.Stderr, "* Checking authentication options\n")
	}

	authHeader, err := buildAuthHeader([]string{}) // No manual headers for this command
	if err != nil {
		if listBrokerDeploymentsVerbose {
			fmt.Fprintf(os.Stderr, "* Warning: failed to get automatic auth: %v\n", err)
		}
		// Don't fail the request, just proceed without automatic auth
	} else if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
		if listBrokerDeploymentsVerbose {
			fmt.Fprintf(os.Stderr, "* Added automatic authorization header\n")
		}
	} else if listBrokerDeploymentsVerbose {
		fmt.Fprintf(os.Stderr, "* No automatic authorization available\n")
	}

	// Set user agent
	req.Header.Set("User-Agent", listBrokerDeploymentsUserAgent)

	// Make the request
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	if listBrokerDeploymentsVerbose {
		fmt.Fprintf(os.Stderr, "* Making request...\n")
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// Handle response using the same pattern as other commands
	return handleListBrokerDeploymentsResponse(resp, listBrokerDeploymentsIncludeResp, listBrokerDeploymentsVerbose, listBrokerDeploymentsSilent)
}

func buildListBrokerDeploymentsURL(endpoint, version, tenantID, installID string, cmd *cobra.Command) (string, error) {
	// Build base URL
	baseURL := fmt.Sprintf("https://%s/rest/tenants/%s/brokers/installs/%s/deployments", endpoint, tenantID, installID)

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
	if listBrokerDeploymentsStartingAfter != "" {
		q.Set("starting_after", listBrokerDeploymentsStartingAfter)
	}
	if listBrokerDeploymentsEndingBefore != "" {
		q.Set("ending_before", listBrokerDeploymentsEndingBefore)
	}
	if listBrokerDeploymentsLimit > 0 {
		q.Set("limit", fmt.Sprintf("%d", listBrokerDeploymentsLimit))
	}

	u.RawQuery = q.Encode()
	return u.String(), nil
}

func handleListBrokerDeploymentsResponse(resp *http.Response, includeResp, verbose, silent bool) error {
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