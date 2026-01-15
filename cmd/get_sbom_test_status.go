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

// GetSbomTestStatusCmd represents the get-sbom-test-status command
var GetSbomTestStatusCmd = &cobra.Command{
	Use:   "get-sbom-test-status [org_id] [job_id]",
	Short: "Get an SBOM test run status from Snyk",
	Long: `Get an SBOM test run status from the Snyk API.

This command retrieves the status of an SBOM test run by its job ID within an organization.
Both the organization ID and job ID must be provided as required arguments.

Required permissions: Test Projects (org.project.test)

Possible status values:
- processing: The test is currently running
- error: The test encountered an error
- finished: The test completed successfully

Examples:
  snyk-api-cli get-sbom-test-status 12345678-1234-1234-1234-123456789012 87654321-4321-8765-2109-876543210987
  snyk-api-cli get-sbom-test-status 12345678-1234-1234-1234-123456789012 87654321-4321-8765-2109-876543210987 --verbose
  snyk-api-cli get-sbom-test-status 12345678-1234-1234-1234-123456789012 87654321-4321-8765-2109-876543210987 --include`,
	Args: cobra.ExactArgs(2),
	RunE: runGetSbomTestStatus,
}

var (
	getSbomTestStatusVerbose     bool
	getSbomTestStatusSilent      bool
	getSbomTestStatusIncludeResp bool
	getSbomTestStatusUserAgent   string
)

func init() {
	// Add standard flags like other commands
	GetSbomTestStatusCmd.Flags().BoolVarP(&getSbomTestStatusVerbose, "verbose", "v", false, "Make the operation more talkative")
	GetSbomTestStatusCmd.Flags().BoolVarP(&getSbomTestStatusSilent, "silent", "s", false, "Silent mode")
	GetSbomTestStatusCmd.Flags().BoolVarP(&getSbomTestStatusIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	GetSbomTestStatusCmd.Flags().StringVarP(&getSbomTestStatusUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")
}

func runGetSbomTestStatus(cmd *cobra.Command, args []string) error {
	orgID := args[0]
	jobID := args[1]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Build the URL
	fullURL, err := buildGetSbomTestStatusURL(endpoint, version, orgID, jobID)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	if getSbomTestStatusVerbose {
		fmt.Fprintf(os.Stderr, "* Requesting GET %s\n", fullURL)
	}

	// Create the HTTP request
	req, err := http.NewRequest("GET", fullURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Handle authentication with same precedence as curl: Authorization header > SNYK_TOKEN > OAuth
	if getSbomTestStatusVerbose {
		fmt.Fprintf(os.Stderr, "* Checking authentication options\n")
	}

	authHeader, err := buildAuthHeader([]string{}) // No manual headers for this command
	if err != nil {
		if getSbomTestStatusVerbose {
			fmt.Fprintf(os.Stderr, "* Warning: failed to get automatic auth: %v\n", err)
		}
		// Don't fail the request, just proceed without automatic auth
	} else if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
		if getSbomTestStatusVerbose {
			fmt.Fprintf(os.Stderr, "* Added automatic authorization header\n")
		}
	} else if getSbomTestStatusVerbose {
		fmt.Fprintf(os.Stderr, "* No automatic authorization available\n")
	}

	// Set user agent
	req.Header.Set("User-Agent", getSbomTestStatusUserAgent)

	// Make the request
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	if getSbomTestStatusVerbose {
		fmt.Fprintf(os.Stderr, "* Making request...\n")
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// Handle response using the same pattern as other commands
	return handleGetSbomTestStatusResponse(resp, getSbomTestStatusIncludeResp, getSbomTestStatusVerbose, getSbomTestStatusSilent)
}

func buildGetSbomTestStatusURL(endpoint, version, orgID, jobID string) (string, error) {
	// Validate the required parameters
	if strings.TrimSpace(orgID) == "" {
		return "", fmt.Errorf("org_id cannot be empty")
	}
	if strings.TrimSpace(jobID) == "" {
		return "", fmt.Errorf("job_id cannot be empty")
	}

	// Build base URL with organization ID and job ID path parameters
	baseURL := fmt.Sprintf("https://%s/rest/orgs/%s/sbom_tests/%s", endpoint, orgID, jobID)

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

func handleGetSbomTestStatusResponse(resp *http.Response, includeResp, verbose, silent bool) error {
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