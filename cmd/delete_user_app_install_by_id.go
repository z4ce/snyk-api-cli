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

// DeleteUserAppInstallByIdCmd represents the delete-user-app-install-by-id command
var DeleteUserAppInstallByIdCmd = &cobra.Command{
	Use:   "delete-user-app-install-by-id [install_id]",
	Short: "Revoke a Snyk App by install ID",
	Long: `Revoke a Snyk App by install ID from the Snyk API.

This command revokes a specific Snyk App installation using its unique install identifier.
The install_id parameter is required and must be a valid UUID.

Examples:
  snyk-api-cli delete-user-app-install-by-id 12345678-1234-5678-9012-123456789012
  snyk-api-cli delete-user-app-install-by-id --verbose 12345678-1234-5678-9012-123456789012
  snyk-api-cli delete-user-app-install-by-id --include 12345678-1234-5678-9012-123456789012`,
	Args: cobra.ExactArgs(1),
	RunE: runDeleteUserAppInstallById,
}

var (
	deleteUserAppInstallByIdVerbose     bool
	deleteUserAppInstallByIdSilent      bool
	deleteUserAppInstallByIdIncludeResp bool
	deleteUserAppInstallByIdUserAgent   string
)

func init() {
	// Add standard flags like curl command
	DeleteUserAppInstallByIdCmd.Flags().BoolVarP(&deleteUserAppInstallByIdVerbose, "verbose", "v", false, "Make the operation more talkative")
	DeleteUserAppInstallByIdCmd.Flags().BoolVarP(&deleteUserAppInstallByIdSilent, "silent", "s", false, "Silent mode")
	DeleteUserAppInstallByIdCmd.Flags().BoolVarP(&deleteUserAppInstallByIdIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	DeleteUserAppInstallByIdCmd.Flags().StringVarP(&deleteUserAppInstallByIdUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")
}

func runDeleteUserAppInstallById(cmd *cobra.Command, args []string) error {
	installID := args[0]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Build the URL with the install_id path parameter
	fullURL, err := buildDeleteUserAppInstallByIdURL(endpoint, installID, version)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	if deleteUserAppInstallByIdVerbose {
		fmt.Fprintf(os.Stderr, "* Requesting DELETE %s\n", fullURL)
	}

	// Create the HTTP request
	req, err := http.NewRequest("DELETE", fullURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Handle authentication with same precedence as curl: Authorization header > SNYK_TOKEN > OAuth
	if deleteUserAppInstallByIdVerbose {
		fmt.Fprintf(os.Stderr, "* Checking authentication options\n")
	}

	authHeader, err := buildAuthHeader([]string{}) // No manual headers for this command
	if err != nil {
		if deleteUserAppInstallByIdVerbose {
			fmt.Fprintf(os.Stderr, "* Warning: failed to get automatic auth: %v\n", err)
		}
		// Don't fail the request, just proceed without automatic auth
	} else if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
		if deleteUserAppInstallByIdVerbose {
			fmt.Fprintf(os.Stderr, "* Added automatic authorization header\n")
		}
	} else if deleteUserAppInstallByIdVerbose {
		fmt.Fprintf(os.Stderr, "* No automatic authorization available\n")
	}

	// Set user agent
	req.Header.Set("User-Agent", deleteUserAppInstallByIdUserAgent)

	// Make the request
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	if deleteUserAppInstallByIdVerbose {
		fmt.Fprintf(os.Stderr, "* Making request...\n")
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// Handle response using the same pattern as curl
	return handleDeleteUserAppInstallByIdResponse(resp, deleteUserAppInstallByIdIncludeResp, deleteUserAppInstallByIdVerbose, deleteUserAppInstallByIdSilent)
}

func buildDeleteUserAppInstallByIdURL(endpoint, installID, version string) (string, error) {
	// Validate the install_id parameter
	if strings.TrimSpace(installID) == "" {
		return "", fmt.Errorf("install_id cannot be empty")
	}

	// Build base URL with the path parameter
	baseURL := fmt.Sprintf("https://%s/rest/self/apps/installs/%s", endpoint, installID)

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

func handleDeleteUserAppInstallByIdResponse(resp *http.Response, includeResp, verbose, silent bool) error {
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