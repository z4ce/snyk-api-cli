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

// GetAssetInOrgCmd represents the get-asset-in-org command
var GetAssetInOrgCmd = &cobra.Command{
	Use:   "get-asset-in-org [org_id] [asset_id]",
	Short: "Get details of a specific asset in an organization from Snyk",
	Long: `Get details of a specific asset in an organization from the Snyk API.

This command retrieves detailed information about a specific asset by its ID within an organization.
Both the organization ID and asset ID must be provided as required arguments.

Required permissions: View Organization (org.read)

Examples:
  snyk-api-cli get-asset-in-org 12345678-1234-1234-1234-123456789012 87654321-8765-4321-8765-210987654321
  snyk-api-cli get-asset-in-org 12345678-1234-1234-1234-123456789012 87654321-8765-4321-8765-210987654321 --verbose
  snyk-api-cli get-asset-in-org 12345678-1234-1234-1234-123456789012 87654321-8765-4321-8765-210987654321 --include`,
	Args: cobra.ExactArgs(2),
	RunE: runGetAssetInOrg,
}

var (
	getAssetInOrgVerbose     bool
	getAssetInOrgSilent      bool
	getAssetInOrgIncludeResp bool
	getAssetInOrgUserAgent   string
)

func init() {
	// Add standard flags like other commands
	GetAssetInOrgCmd.Flags().BoolVarP(&getAssetInOrgVerbose, "verbose", "v", false, "Make the operation more talkative")
	GetAssetInOrgCmd.Flags().BoolVarP(&getAssetInOrgSilent, "silent", "s", false, "Silent mode")
	GetAssetInOrgCmd.Flags().BoolVarP(&getAssetInOrgIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	GetAssetInOrgCmd.Flags().StringVarP(&getAssetInOrgUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")
}

func runGetAssetInOrg(cmd *cobra.Command, args []string) error {
	orgID := args[0]
	assetID := args[1]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Build the URL
	fullURL, err := buildGetAssetInOrgURL(endpoint, version, orgID, assetID)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	if getAssetInOrgVerbose {
		fmt.Fprintf(os.Stderr, "* Requesting GET %s\n", fullURL)
	}

	// Create the HTTP request
	req, err := http.NewRequest("GET", fullURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Handle authentication with same precedence as curl: Authorization header > SNYK_TOKEN > OAuth
	if getAssetInOrgVerbose {
		fmt.Fprintf(os.Stderr, "* Checking authentication options\n")
	}

	authHeader, err := buildAuthHeader([]string{}) // No manual headers for this command
	if err != nil {
		if getAssetInOrgVerbose {
			fmt.Fprintf(os.Stderr, "* Warning: failed to get automatic auth: %v\n", err)
		}
		// Don't fail the request, just proceed without automatic auth
	} else if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
		if getAssetInOrgVerbose {
			fmt.Fprintf(os.Stderr, "* Added automatic authorization header\n")
		}
	} else if getAssetInOrgVerbose {
		fmt.Fprintf(os.Stderr, "* No automatic authorization available\n")
	}

	// Set user agent
	req.Header.Set("User-Agent", getAssetInOrgUserAgent)

	// Make the request
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	if getAssetInOrgVerbose {
		fmt.Fprintf(os.Stderr, "* Making request...\n")
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// Handle response using the same pattern as other commands
	return handleGetAssetInOrgResponse(resp, getAssetInOrgIncludeResp, getAssetInOrgVerbose, getAssetInOrgSilent)
}

func buildGetAssetInOrgURL(endpoint, version, orgID, assetID string) (string, error) {
	// Build base URL with organization ID and asset ID path parameters
	baseURL := fmt.Sprintf("https://%s/rest/orgs/%s/assets/%s", endpoint, orgID, assetID)

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

func handleGetAssetInOrgResponse(resp *http.Response, includeResp, verbose, silent bool) error {
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