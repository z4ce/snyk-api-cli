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

// GetAPIVersionCmd represents the get-api-version command
var GetAPIVersionCmd = &cobra.Command{
	Use:   "get-api-version [version]",
	Short: "Get OpenAPI specification effective at version",
	Long: `Get OpenAPI specification effective at version from the Snyk API.

This command retrieves the OpenAPI specification for a specific version
of the Snyk API. The version parameter is required and specifies which
version of the API specification to retrieve.

Examples:
  snyk-api-cli get-api-version 2024-10-15
  snyk-api-cli get-api-version 2024-10-15 --verbose
  snyk-api-cli get-api-version 2024-10-15 --include`,
	Args: cobra.ExactArgs(1),
	RunE: runGetAPIVersion,
}

var (
	getAPIVersionVerbose     bool
	getAPIVersionSilent      bool
	getAPIVersionIncludeResp bool
	getAPIVersionUserAgent   string
)

func init() {
	// Add standard flags like other commands
	GetAPIVersionCmd.Flags().BoolVarP(&getAPIVersionVerbose, "verbose", "v", false, "Make the operation more talkative")
	GetAPIVersionCmd.Flags().BoolVarP(&getAPIVersionSilent, "silent", "s", false, "Silent mode")
	GetAPIVersionCmd.Flags().BoolVarP(&getAPIVersionIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	GetAPIVersionCmd.Flags().StringVarP(&getAPIVersionUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")
}

func runGetAPIVersion(cmd *cobra.Command, args []string) error {
	version := args[0]
	endpoint := viper.GetString("endpoint")
	defaultVersion := viper.GetString("version")

	// Build the URL
	fullURL, err := buildGetAPIVersionURL(endpoint, version, defaultVersion)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	if getAPIVersionVerbose {
		fmt.Fprintf(os.Stderr, "* Requesting GET %s\n", fullURL)
	}

	// Create the HTTP request
	req, err := http.NewRequest("GET", fullURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Handle authentication with same precedence as curl: Authorization header > SNYK_TOKEN > OAuth
	if getAPIVersionVerbose {
		fmt.Fprintf(os.Stderr, "* Checking authentication options\n")
	}

	authHeader, err := buildAuthHeader([]string{}) // No manual headers for this command
	if err != nil {
		if getAPIVersionVerbose {
			fmt.Fprintf(os.Stderr, "* Warning: failed to get automatic auth: %v\n", err)
		}
		// Don't fail the request, just proceed without automatic auth
	} else if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
		if getAPIVersionVerbose {
			fmt.Fprintf(os.Stderr, "* Added automatic authorization header\n")
		}
	} else if getAPIVersionVerbose {
		fmt.Fprintf(os.Stderr, "* No automatic authorization available\n")
	}

	// Set user agent
	req.Header.Set("User-Agent", getAPIVersionUserAgent)

	// Make the request
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	if getAPIVersionVerbose {
		fmt.Fprintf(os.Stderr, "* Making request...\n")
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// Handle response using the same pattern as other commands
	return handleGetAPIVersionResponse(resp, getAPIVersionIncludeResp, getAPIVersionVerbose, getAPIVersionSilent)
}

func buildGetAPIVersionURL(endpoint, version, defaultVersion string) (string, error) {
	// Build base URL for the /openapi/{version} endpoint
	baseURL := fmt.Sprintf("https://%s/openapi/%s", endpoint, version)

	// Parse URL to handle query parameters properly
	u, err := url.Parse(baseURL)
	if err != nil {
		return "", err
	}

	// Add query parameters
	q := u.Query()

	// Version is required for REST endpoints
	q.Set("version", defaultVersion)

	u.RawQuery = q.Encode()
	return u.String(), nil
}

func handleGetAPIVersionResponse(resp *http.Response, includeResp, verbose, silent bool) error {
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