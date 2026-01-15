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

// RevokeUserAppSessionCmd represents the revoke-user-app-session command
var RevokeUserAppSessionCmd = &cobra.Command{
	Use:   "revoke-user-app-session [app_id] [session_id]",
	Short: "Revoke the Snyk App session of an active user",
	Long: `Revoke the Snyk App session of an active user from the Snyk API.

This command revokes a specific active OAuth session for a Snyk App using both
the app identifier and session identifier. Both app_id and session_id parameters
are required and must be valid UUIDs.

Examples:
  snyk-api-cli revoke-user-app-session 12345678-1234-5678-9012-123456789012 87654321-4321-8765-2109-876543210987
  snyk-api-cli revoke-user-app-session --verbose 12345678-1234-5678-9012-123456789012 87654321-4321-8765-2109-876543210987
  snyk-api-cli revoke-user-app-session --include 12345678-1234-5678-9012-123456789012 87654321-4321-8765-2109-876543210987`,
	Args: cobra.ExactArgs(2),
	RunE: runRevokeUserAppSession,
}

var (
	revokeUserAppSessionVerbose     bool
	revokeUserAppSessionSilent      bool
	revokeUserAppSessionIncludeResp bool
	revokeUserAppSessionUserAgent   string
)

func init() {
	// Add standard flags like curl command
	RevokeUserAppSessionCmd.Flags().BoolVarP(&revokeUserAppSessionVerbose, "verbose", "v", false, "Make the operation more talkative")
	RevokeUserAppSessionCmd.Flags().BoolVarP(&revokeUserAppSessionSilent, "silent", "s", false, "Silent mode")
	RevokeUserAppSessionCmd.Flags().BoolVarP(&revokeUserAppSessionIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	RevokeUserAppSessionCmd.Flags().StringVarP(&revokeUserAppSessionUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")
}

func runRevokeUserAppSession(cmd *cobra.Command, args []string) error {
	appID := args[0]
	sessionID := args[1]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Build the URL with the app_id and session_id path parameters
	fullURL, err := buildRevokeUserAppSessionURL(endpoint, appID, sessionID, version)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	if revokeUserAppSessionVerbose {
		fmt.Fprintf(os.Stderr, "* Requesting DELETE %s\n", fullURL)
	}

	// Create the HTTP request
	req, err := http.NewRequest("DELETE", fullURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Handle authentication with same precedence as curl: Authorization header > SNYK_TOKEN > OAuth
	if revokeUserAppSessionVerbose {
		fmt.Fprintf(os.Stderr, "* Checking authentication options\n")
	}

	authHeader, err := buildAuthHeader([]string{}) // No manual headers for this command
	if err != nil {
		if revokeUserAppSessionVerbose {
			fmt.Fprintf(os.Stderr, "* Warning: failed to get automatic auth: %v\n", err)
		}
		// Don't fail the request, just proceed without automatic auth
	} else if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
		if revokeUserAppSessionVerbose {
			fmt.Fprintf(os.Stderr, "* Added automatic authorization header\n")
		}
	} else if revokeUserAppSessionVerbose {
		fmt.Fprintf(os.Stderr, "* No automatic authorization available\n")
	}

	// Set user agent
	req.Header.Set("User-Agent", revokeUserAppSessionUserAgent)

	// Make the request
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	if revokeUserAppSessionVerbose {
		fmt.Fprintf(os.Stderr, "* Making request...\n")
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// Handle response using the same pattern as curl
	return handleRevokeUserAppSessionResponse(resp, revokeUserAppSessionIncludeResp, revokeUserAppSessionVerbose, revokeUserAppSessionSilent)
}

func buildRevokeUserAppSessionURL(endpoint, appID, sessionID, version string) (string, error) {
	// Validate the app_id parameter
	if strings.TrimSpace(appID) == "" {
		return "", fmt.Errorf("app_id cannot be empty")
	}

	// Validate the session_id parameter
	if strings.TrimSpace(sessionID) == "" {
		return "", fmt.Errorf("session_id cannot be empty")
	}

	// Build base URL with the path parameters
	baseURL := fmt.Sprintf("https://%s/rest/self/apps/%s/sessions/%s", endpoint, appID, sessionID)

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

func handleRevokeUserAppSessionResponse(resp *http.Response, includeResp, verbose, silent bool) error {
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