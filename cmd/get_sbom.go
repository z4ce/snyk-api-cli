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

// GetSbomCmd represents the get-sbom command
var GetSbomCmd = &cobra.Command{
	Use:   "get-sbom [org_id] [project_id]",
	Short: "Get a project's SBOM document from Snyk",
	Long: `Get a project's SBOM document from the Snyk API.

This command retrieves the Software Bill of Materials (SBOM) document for a specific project
within an organization. Both the organization ID and project ID must be provided as required arguments.

Required permissions: View Project history (org.project.snapshot.read)

Examples:
  snyk-api-cli get-sbom 12345678-1234-1234-1234-123456789012 87654321-4321-8765-2109-876543210987
  snyk-api-cli get-sbom 12345678-1234-1234-1234-123456789012 87654321-4321-8765-2109-876543210987 --format "cyclonedx1.6+json"
  snyk-api-cli get-sbom 12345678-1234-1234-1234-123456789012 87654321-4321-8765-2109-876543210987 --format "spdx2.3+json"
  snyk-api-cli get-sbom 12345678-1234-1234-1234-123456789012 87654321-4321-8765-2109-876543210987 --format "cyclonedx1.5+xml"
  snyk-api-cli get-sbom 12345678-1234-1234-1234-123456789012 87654321-4321-8765-2109-876543210987 --exclude "licenses"
  snyk-api-cli get-sbom 12345678-1234-1234-1234-123456789012 87654321-4321-8765-2109-876543210987 --format "cyclonedx1.6+json" --exclude "licenses" --verbose`,
	Args: cobra.ExactArgs(2),
	RunE: runGetSbom,
}

var (
	getSbomFormat      string
	getSbomExclude     []string
	getSbomVerbose     bool
	getSbomSilent      bool
	getSbomIncludeResp bool
	getSbomUserAgent   string
)

func init() {
	// Add flags for query parameters
	GetSbomCmd.Flags().StringVar(&getSbomFormat, "format", "", "SBOM format (cyclonedx1.6+json, cyclonedx1.6+xml, cyclonedx1.5+json, cyclonedx1.5+xml, cyclonedx1.4+json, cyclonedx1.4+xml, spdx2.3+json)")
	GetSbomCmd.Flags().StringSliceVar(&getSbomExclude, "exclude", []string{}, "Features to exclude from SBOM (e.g., 'licenses')")

	// Add standard flags like other commands
	GetSbomCmd.Flags().BoolVarP(&getSbomVerbose, "verbose", "v", false, "Make the operation more talkative")
	GetSbomCmd.Flags().BoolVarP(&getSbomSilent, "silent", "s", false, "Silent mode")
	GetSbomCmd.Flags().BoolVarP(&getSbomIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	GetSbomCmd.Flags().StringVarP(&getSbomUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")
}

func runGetSbom(cmd *cobra.Command, args []string) error {
	orgID := args[0]
	projectID := args[1]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Build the URL
	fullURL, err := buildGetSbomURL(endpoint, version, orgID, projectID)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	if getSbomVerbose {
		fmt.Fprintf(os.Stderr, "* Requesting GET %s\n", fullURL)
	}

	// Create the HTTP request
	req, err := http.NewRequest("GET", fullURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Handle authentication with same precedence as curl: Authorization header > SNYK_TOKEN > OAuth
	if getSbomVerbose {
		fmt.Fprintf(os.Stderr, "* Checking authentication options\n")
	}

	authHeader, err := buildAuthHeader([]string{}) // No manual headers for this command
	if err != nil {
		if getSbomVerbose {
			fmt.Fprintf(os.Stderr, "* Warning: failed to get automatic auth: %v\n", err)
		}
		// Don't fail the request, just proceed without automatic auth
	} else if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
		if getSbomVerbose {
			fmt.Fprintf(os.Stderr, "* Added automatic authorization header\n")
		}
	} else if getSbomVerbose {
		fmt.Fprintf(os.Stderr, "* No automatic authorization available\n")
	}

	// Set user agent
	req.Header.Set("User-Agent", getSbomUserAgent)

	// Make the request
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	if getSbomVerbose {
		fmt.Fprintf(os.Stderr, "* Making request...\n")
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// Handle response using the same pattern as other commands
	return handleGetSbomResponse(resp, getSbomIncludeResp, getSbomVerbose, getSbomSilent)
}

func buildGetSbomURL(endpoint, version, orgID, projectID string) (string, error) {
	// Validate the required parameters
	if strings.TrimSpace(orgID) == "" {
		return "", fmt.Errorf("org_id cannot be empty")
	}
	if strings.TrimSpace(projectID) == "" {
		return "", fmt.Errorf("project_id cannot be empty")
	}

	// Build base URL with organization ID and project ID path parameters
	baseURL := fmt.Sprintf("https://%s/rest/orgs/%s/projects/%s/sbom", endpoint, orgID, projectID)

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
	if getSbomFormat != "" {
		q.Set("format", getSbomFormat)
	}
	if len(getSbomExclude) > 0 {
		for _, exclude := range getSbomExclude {
			q.Add("exclude", exclude)
		}
	}

	u.RawQuery = q.Encode()
	return u.String(), nil
}

func handleGetSbomResponse(resp *http.Response, includeResp, verbose, silent bool) error {
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