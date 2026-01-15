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

// GetIacSettingsForOrgCmd represents the get-iac-settings-for-org command
var GetIacSettingsForOrgCmd = &cobra.Command{
	Use:   "get-iac-settings-for-org [org_id]",
	Short: "Get Infrastructure as Code settings for an organization",
	Long: `Get Infrastructure as Code settings for an organization from the Snyk API.

This command retrieves the Infrastructure as Code settings for a specific organization by its ID.
The organization ID must be provided as a required argument.

Required permissions: View Organization (org.read)

Examples:
  snyk-api-cli get-iac-settings-for-org 12345678-1234-1234-1234-123456789012
  snyk-api-cli get-iac-settings-for-org 12345678-1234-1234-1234-123456789012 --verbose
  snyk-api-cli get-iac-settings-for-org 12345678-1234-1234-1234-123456789012 --include`,
	Args: cobra.ExactArgs(1),
	RunE: runGetIacSettingsForOrg,
}

var (
	getIacSettingsForOrgVerbose     bool
	getIacSettingsForOrgSilent      bool
	getIacSettingsForOrgIncludeResp bool
	getIacSettingsForOrgUserAgent   string
)

func init() {
	// Add standard flags like other commands
	GetIacSettingsForOrgCmd.Flags().BoolVarP(&getIacSettingsForOrgVerbose, "verbose", "v", false, "Make the operation more talkative")
	GetIacSettingsForOrgCmd.Flags().BoolVarP(&getIacSettingsForOrgSilent, "silent", "s", false, "Silent mode")
	GetIacSettingsForOrgCmd.Flags().BoolVarP(&getIacSettingsForOrgIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	GetIacSettingsForOrgCmd.Flags().StringVarP(&getIacSettingsForOrgUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")
}

func runGetIacSettingsForOrg(cmd *cobra.Command, args []string) error {
	orgID := args[0]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Build the URL
	fullURL, err := buildGetIacSettingsForOrgURL(endpoint, version, orgID)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	if getIacSettingsForOrgVerbose {
		fmt.Fprintf(os.Stderr, "* Requesting GET %s\n", fullURL)
	}

	// Create the HTTP request
	req, err := http.NewRequest("GET", fullURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Handle authentication with same precedence as curl: Authorization header > SNYK_TOKEN > OAuth
	if getIacSettingsForOrgVerbose {
		fmt.Fprintf(os.Stderr, "* Checking authentication options\n")
	}

	authHeader, err := buildAuthHeader([]string{}) // No manual headers for this command
	if err != nil {
		if getIacSettingsForOrgVerbose {
			fmt.Fprintf(os.Stderr, "* Warning: failed to get automatic auth: %v\n", err)
		}
		// Don't fail the request, just proceed without automatic auth
	} else if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
		if getIacSettingsForOrgVerbose {
			fmt.Fprintf(os.Stderr, "* Added automatic authorization header\n")
		}
	} else if getIacSettingsForOrgVerbose {
		fmt.Fprintf(os.Stderr, "* No automatic authorization available\n")
	}

	// Set user agent
	req.Header.Set("User-Agent", getIacSettingsForOrgUserAgent)

	// Make the request
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	if getIacSettingsForOrgVerbose {
		fmt.Fprintf(os.Stderr, "* Making request...\n")
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// Handle response using the same pattern as other commands
	return handleGetIacSettingsForOrgResponse(resp, getIacSettingsForOrgIncludeResp, getIacSettingsForOrgVerbose, getIacSettingsForOrgSilent)
}

func buildGetIacSettingsForOrgURL(endpoint, version, orgID string) (string, error) {
	// Validate the required parameters
	if strings.TrimSpace(orgID) == "" {
		return "", fmt.Errorf("org_id cannot be empty")
	}

	// Build base URL with organization ID path parameter
	baseURL := fmt.Sprintf("https://%s/rest/orgs/%s/settings/iac", endpoint, orgID)

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

func handleGetIacSettingsForOrgResponse(resp *http.Response, includeResp, verbose, silent bool) error {
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