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

// DeleteGroupAppInstallByIdCmd represents the delete-group-app-install-by-id command
var DeleteGroupAppInstallByIdCmd = &cobra.Command{
	Use:   "delete-group-app-install-by-id [group_id] [install_id]",
	Short: "Revoke app authorization for a Snyk group with install ID",
	Long: `Revoke app authorization for a Snyk group with install ID.

This command deletes a specific app install using the group ID and install ID parameters.
Both group_id and install_id parameters are required and must be valid UUIDs.

Examples:
  snyk-api-cli delete-group-app-install-by-id 12345678-1234-5678-9012-123456789012 87654321-4321-8765-2109-876543210987
  snyk-api-cli delete-group-app-install-by-id --verbose 12345678-1234-5678-9012-123456789012 87654321-4321-8765-2109-876543210987
  snyk-api-cli delete-group-app-install-by-id --include 12345678-1234-5678-9012-123456789012 87654321-4321-8765-2109-876543210987`,
	Args: cobra.ExactArgs(2),
	RunE: runDeleteGroupAppInstallById,
}

var (
	deleteGroupAppInstallByIdVerbose     bool
	deleteGroupAppInstallByIdSilent      bool
	deleteGroupAppInstallByIdIncludeResp bool
	deleteGroupAppInstallByIdUserAgent   string
)

func init() {
	// Add standard flags like curl command
	DeleteGroupAppInstallByIdCmd.Flags().BoolVarP(&deleteGroupAppInstallByIdVerbose, "verbose", "v", false, "Make the operation more talkative")
	DeleteGroupAppInstallByIdCmd.Flags().BoolVarP(&deleteGroupAppInstallByIdSilent, "silent", "s", false, "Silent mode")
	DeleteGroupAppInstallByIdCmd.Flags().BoolVarP(&deleteGroupAppInstallByIdIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	DeleteGroupAppInstallByIdCmd.Flags().StringVarP(&deleteGroupAppInstallByIdUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")
}

func runDeleteGroupAppInstallById(cmd *cobra.Command, args []string) error {
	groupID := args[0]
	installID := args[1]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Build the URL with the group_id and install_id path parameters
	fullURL, err := buildDeleteGroupAppInstallByIdURL(endpoint, groupID, installID, version)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	if deleteGroupAppInstallByIdVerbose {
		fmt.Fprintf(os.Stderr, "* Requesting DELETE %s\n", fullURL)
	}

	// Create the HTTP request
	req, err := http.NewRequest("DELETE", fullURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Handle authentication with same precedence as curl: Authorization header > SNYK_TOKEN > OAuth
	if deleteGroupAppInstallByIdVerbose {
		fmt.Fprintf(os.Stderr, "* Checking authentication options\n")
	}

	authHeader, err := buildAuthHeader([]string{}) // No manual headers for this command
	if err != nil {
		if deleteGroupAppInstallByIdVerbose {
			fmt.Fprintf(os.Stderr, "* Warning: failed to get automatic auth: %v\n", err)
		}
		// Don't fail the request, just proceed without automatic auth
	} else if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
		if deleteGroupAppInstallByIdVerbose {
			fmt.Fprintf(os.Stderr, "* Added automatic authorization header\n")
		}
	} else if deleteGroupAppInstallByIdVerbose {
		fmt.Fprintf(os.Stderr, "* No automatic authorization available\n")
	}

	// Set user agent
	req.Header.Set("User-Agent", deleteGroupAppInstallByIdUserAgent)

	// Make the request
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	if deleteGroupAppInstallByIdVerbose {
		fmt.Fprintf(os.Stderr, "* Making request...\n")
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// Handle response using the same pattern as curl
	return handleDeleteGroupAppInstallByIdResponse(resp, deleteGroupAppInstallByIdIncludeResp, deleteGroupAppInstallByIdVerbose, deleteGroupAppInstallByIdSilent)
}

func buildDeleteGroupAppInstallByIdURL(endpoint, groupID, installID, version string) (string, error) {
	// Validate the group_id parameter
	if strings.TrimSpace(groupID) == "" {
		return "", fmt.Errorf("group_id cannot be empty")
	}

	// Validate the install_id parameter
	if strings.TrimSpace(installID) == "" {
		return "", fmt.Errorf("install_id cannot be empty")
	}

	// Build base URL with the path parameters
	baseURL := fmt.Sprintf("https://%s/rest/groups/%s/apps/installs/%s", endpoint, groupID, installID)

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

func handleDeleteGroupAppInstallByIdResponse(resp *http.Response, includeResp, verbose, silent bool) error {
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