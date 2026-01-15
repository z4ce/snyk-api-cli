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

// GetOrgCmd represents the get-org command
var GetOrgCmd = &cobra.Command{
	Use:   "get-org [org_id]",
	Short: "Get details of a specific organization from Snyk",
	Long: `Get details of a specific organization from the Snyk API.

This command retrieves detailed information about a specific organization by its ID.
The organization ID must be provided as a required argument.

Examples:
  snyk-api-cli get-org 12345678-1234-1234-1234-123456789012
  snyk-api-cli get-org 12345678-1234-1234-1234-123456789012 --verbose
  snyk-api-cli get-org 12345678-1234-1234-1234-123456789012 --expand tenant
  snyk-api-cli get-org 12345678-1234-1234-1234-123456789012 --include`,
	Args: cobra.ExactArgs(1),
	RunE: runGetOrg,
}

var (
	getOrgVerbose     bool
	getOrgSilent      bool
	getOrgIncludeResp bool
	getOrgUserAgent   string
	getOrgExpand      []string
)

func init() {
	// Add standard flags like other commands
	GetOrgCmd.Flags().BoolVarP(&getOrgVerbose, "verbose", "v", false, "Make the operation more talkative")
	GetOrgCmd.Flags().BoolVarP(&getOrgSilent, "silent", "s", false, "Silent mode")
	GetOrgCmd.Flags().BoolVarP(&getOrgIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	GetOrgCmd.Flags().StringVarP(&getOrgUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")
	
	// Add expand flag based on API spec
	GetOrgCmd.Flags().StringSliceVar(&getOrgExpand, "expand", []string{}, "Expand the specified related resources in the response (allowed values: tenant)")
}

func runGetOrg(cmd *cobra.Command, args []string) error {
	orgID := args[0]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Build the URL
	fullURL, err := buildGetOrgURL(endpoint, version, orgID, getOrgExpand)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	if getOrgVerbose {
		fmt.Fprintf(os.Stderr, "* Requesting GET %s\n", fullURL)
	}

	// Create the HTTP request
	req, err := http.NewRequest("GET", fullURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Handle authentication with same precedence as curl: Authorization header > SNYK_TOKEN > OAuth
	if getOrgVerbose {
		fmt.Fprintf(os.Stderr, "* Checking authentication options\n")
	}

	authHeader, err := buildAuthHeader([]string{}) // No manual headers for this command
	if err != nil {
		if getOrgVerbose {
			fmt.Fprintf(os.Stderr, "* Warning: failed to get automatic auth: %v\n", err)
		}
		// Don't fail the request, just proceed without automatic auth
	} else if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
		if getOrgVerbose {
			fmt.Fprintf(os.Stderr, "* Added automatic authorization header\n")
		}
	} else if getOrgVerbose {
		fmt.Fprintf(os.Stderr, "* No automatic authorization available\n")
	}

	// Set user agent
	req.Header.Set("User-Agent", getOrgUserAgent)

	// Make the request
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	if getOrgVerbose {
		fmt.Fprintf(os.Stderr, "* Making request...\n")
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// Handle response using the same pattern as other commands
	return handleGetOrgResponse(resp, getOrgIncludeResp, getOrgVerbose, getOrgSilent)
}

func buildGetOrgURL(endpoint, version, orgID string, expand []string) (string, error) {
	// Build base URL with org ID path parameter
	baseURL := fmt.Sprintf("https://%s/rest/orgs/%s", endpoint, orgID)

	// Parse URL to handle query parameters properly
	u, err := url.Parse(baseURL)
	if err != nil {
		return "", err
	}

	// Add query parameters
	q := u.Query()

	// Version is required
	q.Set("version", version)

	// Add expand parameter if specified
	if len(expand) > 0 {
		// Validate expand values
		for _, value := range expand {
			if value != "tenant" {
				return "", fmt.Errorf("invalid expand value: %s (allowed values: tenant)", value)
			}
		}
		q.Set("expand", strings.Join(expand, ","))
	}

	u.RawQuery = q.Encode()
	return u.String(), nil
}

func handleGetOrgResponse(resp *http.Response, includeResp, verbose, silent bool) error {
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