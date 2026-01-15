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

// ListDeploymentCredentialsCmd represents the list-deployment-credentials command
var ListDeploymentCredentialsCmd = &cobra.Command{
	Use:   "list-deployment-credentials [tenant_id] [install_id] [deployment_id]",
	Short: "List Deployment credentials",
	Long: `List Deployment credentials from the Snyk API.

This command retrieves a list of deployment credentials for a specific tenant, install ID, and deployment ID.
The results can be paginated using various query parameters.

Examples:
  snyk-api-cli list-deployment-credentials 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321 11111111-1111-1111-1111-111111111111
  snyk-api-cli list-deployment-credentials 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321 11111111-1111-1111-1111-111111111111 --limit 10
  snyk-api-cli list-deployment-credentials 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321 11111111-1111-1111-1111-111111111111 --starting-after abc123
  snyk-api-cli list-deployment-credentials 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321 11111111-1111-1111-1111-111111111111 --verbose`,
	Args: cobra.ExactArgs(3),
	RunE: runListDeploymentCredentials,
}

var (
	listDeploymentCredentialsStartingAfter string
	listDeploymentCredentialsEndingBefore  string
	listDeploymentCredentialsLimit         int
	listDeploymentCredentialsVerbose       bool
	listDeploymentCredentialsSilent        bool
	listDeploymentCredentialsIncludeResp   bool
	listDeploymentCredentialsUserAgent     string
)

func init() {
	// Add flags for query parameters
	ListDeploymentCredentialsCmd.Flags().StringVar(&listDeploymentCredentialsStartingAfter, "starting-after", "", "Return the page of results immediately after this cursor")
	ListDeploymentCredentialsCmd.Flags().StringVar(&listDeploymentCredentialsEndingBefore, "ending-before", "", "Return the page of results immediately before this cursor")
	ListDeploymentCredentialsCmd.Flags().IntVar(&listDeploymentCredentialsLimit, "limit", 0, "Number of results to return per page")

	// Add standard flags like other commands
	ListDeploymentCredentialsCmd.Flags().BoolVarP(&listDeploymentCredentialsVerbose, "verbose", "v", false, "Make the operation more talkative")
	ListDeploymentCredentialsCmd.Flags().BoolVarP(&listDeploymentCredentialsSilent, "silent", "s", false, "Silent mode")
	ListDeploymentCredentialsCmd.Flags().BoolVarP(&listDeploymentCredentialsIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	ListDeploymentCredentialsCmd.Flags().StringVarP(&listDeploymentCredentialsUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")
}

func runListDeploymentCredentials(cmd *cobra.Command, args []string) error {
	tenantID := args[0]
	installID := args[1]
	deploymentID := args[2]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Build the URL with query parameters
	fullURL, err := buildListDeploymentCredentialsURL(endpoint, version, tenantID, installID, deploymentID, cmd)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	if listDeploymentCredentialsVerbose {
		fmt.Fprintf(os.Stderr, "* Requesting GET %s\n", fullURL)
	}

	// Create the HTTP request
	req, err := http.NewRequest("GET", fullURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Handle authentication with same precedence as curl: Authorization header > SNYK_TOKEN > OAuth
	if listDeploymentCredentialsVerbose {
		fmt.Fprintf(os.Stderr, "* Checking authentication options\n")
	}

	authHeader, err := buildAuthHeader([]string{}) // No manual headers for this command
	if err != nil {
		if listDeploymentCredentialsVerbose {
			fmt.Fprintf(os.Stderr, "* Warning: failed to get automatic auth: %v\n", err)
		}
		// Don't fail the request, just proceed without automatic auth
	} else if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
		if listDeploymentCredentialsVerbose {
			fmt.Fprintf(os.Stderr, "* Added automatic authorization header\n")
		}
	} else if listDeploymentCredentialsVerbose {
		fmt.Fprintf(os.Stderr, "* No automatic authorization available\n")
	}

	// Set user agent
	req.Header.Set("User-Agent", listDeploymentCredentialsUserAgent)

	// Make the request
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	if listDeploymentCredentialsVerbose {
		fmt.Fprintf(os.Stderr, "* Making request...\n")
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// Handle response using the same pattern as other commands
	return handleListDeploymentCredentialsResponse(resp, listDeploymentCredentialsIncludeResp, listDeploymentCredentialsVerbose, listDeploymentCredentialsSilent)
}

func buildListDeploymentCredentialsURL(endpoint, version, tenantID, installID, deploymentID string, cmd *cobra.Command) (string, error) {
	// Build base URL
	baseURL := fmt.Sprintf("https://%s/rest/tenants/%s/brokers/installs/%s/deployments/%s/credentials", endpoint, tenantID, installID, deploymentID)

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
	if listDeploymentCredentialsStartingAfter != "" {
		q.Set("starting_after", listDeploymentCredentialsStartingAfter)
	}
	if listDeploymentCredentialsEndingBefore != "" {
		q.Set("ending_before", listDeploymentCredentialsEndingBefore)
	}
	if listDeploymentCredentialsLimit > 0 {
		q.Set("limit", fmt.Sprintf("%d", listDeploymentCredentialsLimit))
	}

	u.RawQuery = q.Encode()
	return u.String(), nil
}

func handleListDeploymentCredentialsResponse(resp *http.Response, includeResp, verbose, silent bool) error {
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