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

// DeleteOneGroupServiceAccountCmd represents the delete-one-group-service-account command
var DeleteOneGroupServiceAccountCmd = &cobra.Command{
	Use:   "delete-one-group-service-account [group_id] [serviceaccount_id]",
	Short: "Delete a group service account from Snyk",
	Long: `Delete a group service account from the Snyk API.

This command permanently deletes a specific group-level service account using the group ID and service account ID.
Both group_id and serviceaccount_id parameters are required and must be valid UUIDs.

Examples:
  snyk-api-cli delete-one-group-service-account 12345678-1234-5678-9012-123456789012 87654321-4321-8765-2109-876543210987
  snyk-api-cli delete-one-group-service-account --verbose 12345678-1234-5678-9012-123456789012 87654321-4321-8765-2109-876543210987
  snyk-api-cli delete-one-group-service-account --include 12345678-1234-5678-9012-123456789012 87654321-4321-8765-2109-876543210987`,
	Args: cobra.ExactArgs(2),
	RunE: runDeleteOneGroupServiceAccount,
}

var (
	deleteOneGroupServiceAccountVerbose     bool
	deleteOneGroupServiceAccountSilent      bool
	deleteOneGroupServiceAccountIncludeResp bool
	deleteOneGroupServiceAccountUserAgent   string
)

func init() {
	// Add standard flags like curl command
	DeleteOneGroupServiceAccountCmd.Flags().BoolVarP(&deleteOneGroupServiceAccountVerbose, "verbose", "v", false, "Make the operation more talkative")
	DeleteOneGroupServiceAccountCmd.Flags().BoolVarP(&deleteOneGroupServiceAccountSilent, "silent", "s", false, "Silent mode")
	DeleteOneGroupServiceAccountCmd.Flags().BoolVarP(&deleteOneGroupServiceAccountIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	DeleteOneGroupServiceAccountCmd.Flags().StringVarP(&deleteOneGroupServiceAccountUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")
}

func runDeleteOneGroupServiceAccount(cmd *cobra.Command, args []string) error {
	groupID := args[0]
	serviceAccountID := args[1]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Build the URL with the group_id and serviceaccount_id path parameters
	fullURL, err := buildDeleteOneGroupServiceAccountURL(endpoint, groupID, serviceAccountID, version)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	if deleteOneGroupServiceAccountVerbose {
		fmt.Fprintf(os.Stderr, "* Requesting DELETE %s\n", fullURL)
	}

	// Create the HTTP request
	req, err := http.NewRequest("DELETE", fullURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Handle authentication with same precedence as curl: Authorization header > SNYK_TOKEN > OAuth
	if deleteOneGroupServiceAccountVerbose {
		fmt.Fprintf(os.Stderr, "* Checking authentication options\n")
	}

	authHeader, err := buildAuthHeader([]string{}) // No manual headers for this command
	if err != nil {
		if deleteOneGroupServiceAccountVerbose {
			fmt.Fprintf(os.Stderr, "* Warning: failed to get automatic auth: %v\n", err)
		}
		// Don't fail the request, just proceed without automatic auth
	} else if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
		if deleteOneGroupServiceAccountVerbose {
			fmt.Fprintf(os.Stderr, "* Added automatic authorization header\n")
		}
	} else if deleteOneGroupServiceAccountVerbose {
		fmt.Fprintf(os.Stderr, "* No automatic authorization available\n")
	}

	// Set user agent
	req.Header.Set("User-Agent", deleteOneGroupServiceAccountUserAgent)

	// Make the request
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	if deleteOneGroupServiceAccountVerbose {
		fmt.Fprintf(os.Stderr, "* Making request...\n")
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// Handle response using the same pattern as curl
	return handleDeleteOneGroupServiceAccountResponse(resp, deleteOneGroupServiceAccountIncludeResp, deleteOneGroupServiceAccountVerbose, deleteOneGroupServiceAccountSilent)
}

func buildDeleteOneGroupServiceAccountURL(endpoint, groupID, serviceAccountID, version string) (string, error) {
	// Validate the group_id parameter
	if strings.TrimSpace(groupID) == "" {
		return "", fmt.Errorf("group_id cannot be empty")
	}

	// Validate the serviceaccount_id parameter
	if strings.TrimSpace(serviceAccountID) == "" {
		return "", fmt.Errorf("serviceaccount_id cannot be empty")
	}

	// Build base URL with the path parameters
	baseURL := fmt.Sprintf("https://%s/rest/groups/%s/service_accounts/%s", endpoint, groupID, serviceAccountID)

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

func handleDeleteOneGroupServiceAccountResponse(resp *http.Response, includeResp, verbose, silent bool) error {
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