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

// ListConnectionContextsCmd represents the list-connection-contexts command
var ListConnectionContextsCmd = &cobra.Command{
	Use:   "list-connection-contexts [tenant_id] [install_id] [connection_id]",
	Short: "List Connection contexts",
	Long: `List Connection contexts from the Snyk API.

This command retrieves a list of broker contexts for a specific connection within a tenant and installation.
The results can be paginated using various query parameters.

Examples:
  snyk-api-cli list-connection-contexts 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321 11111111-1111-1111-1111-111111111111
  snyk-api-cli list-connection-contexts 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321 11111111-1111-1111-1111-111111111111 --limit 10
  snyk-api-cli list-connection-contexts 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321 11111111-1111-1111-1111-111111111111 --starting-after abc123
  snyk-api-cli list-connection-contexts 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321 11111111-1111-1111-1111-111111111111 --ending-before xyz789
  snyk-api-cli list-connection-contexts 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321 11111111-1111-1111-1111-111111111111 --verbose`,
	Args: cobra.ExactArgs(3),
	RunE: runListConnectionContexts,
}

var (
	listConnectionContextsStartingAfter string
	listConnectionContextsEndingBefore  string
	listConnectionContextsLimit         int
	listConnectionContextsVerbose       bool
	listConnectionContextsSilent        bool
	listConnectionContextsIncludeResp   bool
	listConnectionContextsUserAgent     string
)

func init() {
	// Add flags for query parameters
	ListConnectionContextsCmd.Flags().StringVar(&listConnectionContextsStartingAfter, "starting-after", "", "Return the page of results immediately after this cursor")
	ListConnectionContextsCmd.Flags().StringVar(&listConnectionContextsEndingBefore, "ending-before", "", "Return the page of results immediately before this cursor")
	ListConnectionContextsCmd.Flags().IntVar(&listConnectionContextsLimit, "limit", 0, "Number of results to return per page")

	// Add standard flags like other commands
	ListConnectionContextsCmd.Flags().BoolVarP(&listConnectionContextsVerbose, "verbose", "v", false, "Make the operation more talkative")
	ListConnectionContextsCmd.Flags().BoolVarP(&listConnectionContextsSilent, "silent", "s", false, "Silent mode")
	ListConnectionContextsCmd.Flags().BoolVarP(&listConnectionContextsIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	ListConnectionContextsCmd.Flags().StringVarP(&listConnectionContextsUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")
}

func runListConnectionContexts(cmd *cobra.Command, args []string) error {
	tenantID := args[0]
	installID := args[1]
	connectionID := args[2]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Build the URL with query parameters
	fullURL, err := buildListConnectionContextsURL(endpoint, version, tenantID, installID, connectionID, cmd)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	if listConnectionContextsVerbose {
		fmt.Fprintf(os.Stderr, "* Requesting GET %s\n", fullURL)
	}

	// Create the HTTP request
	req, err := http.NewRequest("GET", fullURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Handle authentication with same precedence as curl: Authorization header > SNYK_TOKEN > OAuth
	if listConnectionContextsVerbose {
		fmt.Fprintf(os.Stderr, "* Checking authentication options\n")
	}

	authHeader, err := buildAuthHeader([]string{}) // No manual headers for this command
	if err != nil {
		if listConnectionContextsVerbose {
			fmt.Fprintf(os.Stderr, "* Warning: failed to get automatic auth: %v\n", err)
		}
		// Don't fail the request, just proceed without automatic auth
	} else if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
		if listConnectionContextsVerbose {
			fmt.Fprintf(os.Stderr, "* Added automatic authorization header\n")
		}
	} else if listConnectionContextsVerbose {
		fmt.Fprintf(os.Stderr, "* No automatic authorization available\n")
	}

	// Set user agent
	req.Header.Set("User-Agent", listConnectionContextsUserAgent)

	// Make the request
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	if listConnectionContextsVerbose {
		fmt.Fprintf(os.Stderr, "* Making request...\n")
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// Handle response using the same pattern as other commands
	return handleListConnectionContextsResponse(resp, listConnectionContextsIncludeResp, listConnectionContextsVerbose, listConnectionContextsSilent)
}

func buildListConnectionContextsURL(endpoint, version, tenantID, installID, connectionID string, cmd *cobra.Command) (string, error) {
	// Build base URL
	baseURL := fmt.Sprintf("https://%s/rest/tenants/%s/brokers/installs/%s/connections/%s/contexts", endpoint, tenantID, installID, connectionID)

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
	if listConnectionContextsStartingAfter != "" {
		q.Set("starting_after", listConnectionContextsStartingAfter)
	}
	if listConnectionContextsEndingBefore != "" {
		q.Set("ending_before", listConnectionContextsEndingBefore)
	}
	if listConnectionContextsLimit > 0 {
		q.Set("limit", fmt.Sprintf("%d", listConnectionContextsLimit))
	}

	u.RawQuery = q.Encode()
	return u.String(), nil
}

func handleListConnectionContextsResponse(resp *http.Response, includeResp, verbose, silent bool) error {
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