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

// GetOneGroupServiceAccountCmd represents the get-one-group-service-account command
var GetOneGroupServiceAccountCmd = &cobra.Command{
	Use:   "get-one-group-service-account <group_id> <serviceaccount_id>",
	Short: "Get details of a specific group service account",
	Long: `Get details of a specific group service account from the Snyk API.

This command retrieves detailed information about a service account within a specific group,
including its name, auth_type, role_id, and creation date.

Examples:
  snyk-api-cli get-one-group-service-account 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321
  snyk-api-cli get-one-group-service-account 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321 --verbose
  snyk-api-cli get-one-group-service-account 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321 --include`,
	Args: cobra.ExactArgs(2),
	RunE: runGetOneGroupServiceAccount,
}

var (
	getOneGroupServiceAccountVerbose     bool
	getOneGroupServiceAccountSilent      bool
	getOneGroupServiceAccountIncludeResp bool
	getOneGroupServiceAccountUserAgent   string
)

func init() {
	// Add standard flags like curl command
	GetOneGroupServiceAccountCmd.Flags().BoolVarP(&getOneGroupServiceAccountVerbose, "verbose", "v", false, "Make the operation more talkative")
	GetOneGroupServiceAccountCmd.Flags().BoolVarP(&getOneGroupServiceAccountSilent, "silent", "s", false, "Silent mode")
	GetOneGroupServiceAccountCmd.Flags().BoolVarP(&getOneGroupServiceAccountIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	GetOneGroupServiceAccountCmd.Flags().StringVarP(&getOneGroupServiceAccountUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")
}

func runGetOneGroupServiceAccount(cmd *cobra.Command, args []string) error {
	groupID := args[0]
	serviceAccountID := args[1]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Build the URL with path parameters
	fullURL, err := buildGetOneGroupServiceAccountURL(endpoint, version, groupID, serviceAccountID)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	if getOneGroupServiceAccountVerbose {
		fmt.Fprintf(os.Stderr, "* Requesting GET %s\n", fullURL)
	}

	// Create the HTTP request
	req, err := http.NewRequest("GET", fullURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Handle authentication with same precedence as curl: Authorization header > SNYK_TOKEN > OAuth
	if getOneGroupServiceAccountVerbose {
		fmt.Fprintf(os.Stderr, "* Checking authentication options\n")
	}

	authHeader, err := buildAuthHeader([]string{}) // No manual headers for this command
	if err != nil {
		if getOneGroupServiceAccountVerbose {
			fmt.Fprintf(os.Stderr, "* Warning: failed to get automatic auth: %v\n", err)
		}
		// Don't fail the request, just proceed without automatic auth
	} else if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
		if getOneGroupServiceAccountVerbose {
			fmt.Fprintf(os.Stderr, "* Added automatic authorization header\n")
		}
	} else if getOneGroupServiceAccountVerbose {
		fmt.Fprintf(os.Stderr, "* No automatic authorization available\n")
	}

	// Set user agent
	req.Header.Set("User-Agent", getOneGroupServiceAccountUserAgent)

	// Make the request
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	if getOneGroupServiceAccountVerbose {
		fmt.Fprintf(os.Stderr, "* Making request...\n")
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// Handle response using the same pattern as other commands
	return handleGetOneGroupServiceAccountResponse(resp, getOneGroupServiceAccountIncludeResp, getOneGroupServiceAccountVerbose, getOneGroupServiceAccountSilent)
}

func buildGetOneGroupServiceAccountURL(endpoint, version, groupID, serviceAccountID string) (string, error) {
	// Build base URL with path parameters
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

func handleGetOneGroupServiceAccountResponse(resp *http.Response, includeResp, verbose, silent bool) error {
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