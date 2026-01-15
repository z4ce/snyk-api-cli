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

// RevokeUserInstalledAppCmd represents the revoke-user-installed-app command
var RevokeUserInstalledAppCmd = &cobra.Command{
	Use:   "revoke-user-installed-app [app_id]",
	Short: "Revoke a Snyk App by app ID",
	Long: `Revoke a Snyk App by app ID from the Snyk API.

This command revokes access to a specific Snyk App using its unique app identifier.
The app_id parameter is required and must be a valid UUID.

Examples:
  snyk-api-cli revoke-user-installed-app 12345678-1234-5678-9012-123456789012
  snyk-api-cli revoke-user-installed-app --verbose 12345678-1234-5678-9012-123456789012
  snyk-api-cli revoke-user-installed-app --include 12345678-1234-5678-9012-123456789012`,
	Args: cobra.ExactArgs(1),
	RunE: runRevokeUserInstalledApp,
}

var (
	revokeUserInstalledAppVerbose     bool
	revokeUserInstalledAppSilent      bool
	revokeUserInstalledAppIncludeResp bool
	revokeUserInstalledAppUserAgent   string
)

func init() {
	// Add standard flags like curl command
	RevokeUserInstalledAppCmd.Flags().BoolVarP(&revokeUserInstalledAppVerbose, "verbose", "v", false, "Make the operation more talkative")
	RevokeUserInstalledAppCmd.Flags().BoolVarP(&revokeUserInstalledAppSilent, "silent", "s", false, "Silent mode")
	RevokeUserInstalledAppCmd.Flags().BoolVarP(&revokeUserInstalledAppIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	RevokeUserInstalledAppCmd.Flags().StringVarP(&revokeUserInstalledAppUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")
}

func runRevokeUserInstalledApp(cmd *cobra.Command, args []string) error {
	appID := args[0]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Build the URL with the app_id path parameter
	fullURL, err := buildRevokeUserInstalledAppURL(endpoint, appID, version)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	if revokeUserInstalledAppVerbose {
		fmt.Fprintf(os.Stderr, "* Requesting DELETE %s\n", fullURL)
	}

	// Create the HTTP request
	req, err := http.NewRequest("DELETE", fullURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Handle authentication with same precedence as curl: Authorization header > SNYK_TOKEN > OAuth
	if revokeUserInstalledAppVerbose {
		fmt.Fprintf(os.Stderr, "* Checking authentication options\n")
	}

	authHeader, err := buildAuthHeader([]string{}) // No manual headers for this command
	if err != nil {
		if revokeUserInstalledAppVerbose {
			fmt.Fprintf(os.Stderr, "* Warning: failed to get automatic auth: %v\n", err)
		}
		// Don't fail the request, just proceed without automatic auth
	} else if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
		if revokeUserInstalledAppVerbose {
			fmt.Fprintf(os.Stderr, "* Added automatic authorization header\n")
		}
	} else if revokeUserInstalledAppVerbose {
		fmt.Fprintf(os.Stderr, "* No automatic authorization available\n")
	}

	// Set user agent
	req.Header.Set("User-Agent", revokeUserInstalledAppUserAgent)

	// Make the request
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	if revokeUserInstalledAppVerbose {
		fmt.Fprintf(os.Stderr, "* Making request...\n")
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// Handle response using the same pattern as curl
	return handleRevokeUserInstalledAppResponse(resp, revokeUserInstalledAppIncludeResp, revokeUserInstalledAppVerbose, revokeUserInstalledAppSilent)
}

func buildRevokeUserInstalledAppURL(endpoint, appID, version string) (string, error) {
	// Validate the app_id parameter
	if strings.TrimSpace(appID) == "" {
		return "", fmt.Errorf("app_id cannot be empty")
	}

	// Build base URL with the path parameter
	baseURL := fmt.Sprintf("https://%s/rest/self/apps/%s", endpoint, appID)

	// Parse URL to handle query parameters properly
	u, err := url.Parse(baseURL)
	if err != nil {
		return "", err
	}

	// Add required version query parameter
	q := u.Query()
	q.Set("version", version)
	u.RawQuery = q.Encode()

	return u.String(), nil
}

func handleRevokeUserInstalledAppResponse(resp *http.Response, includeResp, verbose, silent bool) error {
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