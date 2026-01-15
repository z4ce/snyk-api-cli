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

// ListAPIVersionsCmd represents the list-api-versions command
var ListAPIVersionsCmd = &cobra.Command{
	Use:   "list-api-versions",
	Short: "List available versions of OpenAPI specification",
	Long: `List available versions of OpenAPI specification from the Snyk API.

This command retrieves a list of available API versions that can be used
with the Snyk REST API endpoints. The versions are returned as an array
of strings.

Examples:
  snyk-api-cli list-api-versions
  snyk-api-cli list-api-versions --verbose
  snyk-api-cli list-api-versions --include`,
	RunE: runListAPIVersions,
}

var (
	listAPIVersionsVerbose     bool
	listAPIVersionsSilent      bool
	listAPIVersionsIncludeResp bool
	listAPIVersionsUserAgent   string
)

func init() {
	// Add standard flags like other commands
	ListAPIVersionsCmd.Flags().BoolVarP(&listAPIVersionsVerbose, "verbose", "v", false, "Make the operation more talkative")
	ListAPIVersionsCmd.Flags().BoolVarP(&listAPIVersionsSilent, "silent", "s", false, "Silent mode")
	ListAPIVersionsCmd.Flags().BoolVarP(&listAPIVersionsIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	ListAPIVersionsCmd.Flags().StringVarP(&listAPIVersionsUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")
}

func runListAPIVersions(cmd *cobra.Command, args []string) error {
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Build the URL
	fullURL, err := buildListAPIVersionsURL(endpoint, version)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	if listAPIVersionsVerbose {
		fmt.Fprintf(os.Stderr, "* Requesting GET %s\n", fullURL)
	}

	// Create the HTTP request
	req, err := http.NewRequest("GET", fullURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Handle authentication with same precedence as curl: Authorization header > SNYK_TOKEN > OAuth
	if listAPIVersionsVerbose {
		fmt.Fprintf(os.Stderr, "* Checking authentication options\n")
	}

	authHeader, err := buildAuthHeader([]string{}) // No manual headers for this command
	if err != nil {
		if listAPIVersionsVerbose {
			fmt.Fprintf(os.Stderr, "* Warning: failed to get automatic auth: %v\n", err)
		}
		// Don't fail the request, just proceed without automatic auth
	} else if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
		if listAPIVersionsVerbose {
			fmt.Fprintf(os.Stderr, "* Added automatic authorization header\n")
		}
	} else if listAPIVersionsVerbose {
		fmt.Fprintf(os.Stderr, "* No automatic authorization available\n")
	}

	// Set user agent
	req.Header.Set("User-Agent", listAPIVersionsUserAgent)

	// Make the request
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	if listAPIVersionsVerbose {
		fmt.Fprintf(os.Stderr, "* Making request...\n")
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// Handle response using the same pattern as other commands
	return handleListAPIVersionsResponse(resp, listAPIVersionsIncludeResp, listAPIVersionsVerbose, listAPIVersionsSilent)
}

func buildListAPIVersionsURL(endpoint, version string) (string, error) {
	// Build base URL for the /openapi endpoint
	baseURL := fmt.Sprintf("https://%s/openapi", endpoint)

	// Parse URL to handle query parameters properly
	u, err := url.Parse(baseURL)
	if err != nil {
		return "", err
	}

	// Add query parameters
	q := u.Query()

	// Version is required for REST endpoints
	q.Set("version", version)

	u.RawQuery = q.Encode()
	return u.String(), nil
}

func handleListAPIVersionsResponse(resp *http.Response, includeResp, verbose, silent bool) error {
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