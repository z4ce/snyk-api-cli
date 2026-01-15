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

// DeleteOrgsTargetCmd represents the delete-orgs-target command
var DeleteOrgsTargetCmd = &cobra.Command{
	Use:   "delete-orgs-target [org_id] [target_id]",
	Short: "Delete target by target ID from Snyk",
	Long: `Delete target by target ID from the Snyk API.

This command deletes a specific target using its unique identifier within an organization.
Both org_id and target_id parameters are required and must be valid UUIDs.

Required permissions: Remove Projects (org.project.delete)

Examples:
  snyk-api-cli delete-orgs-target 12345678-1234-1234-1234-123456789012 87654321-4321-8765-2109-876543210987
  snyk-api-cli delete-orgs-target 12345678-1234-1234-1234-123456789012 87654321-4321-8765-2109-876543210987 --verbose
  snyk-api-cli delete-orgs-target 12345678-1234-1234-1234-123456789012 87654321-4321-8765-2109-876543210987 --include`,
	Args: cobra.ExactArgs(2),
	RunE: runDeleteOrgsTarget,
}

var (
	deleteOrgsTargetVerbose     bool
	deleteOrgsTargetSilent      bool
	deleteOrgsTargetIncludeResp bool
	deleteOrgsTargetUserAgent   string
)

func init() {
	// Add standard flags like curl command
	DeleteOrgsTargetCmd.Flags().BoolVarP(&deleteOrgsTargetVerbose, "verbose", "v", false, "Make the operation more talkative")
	DeleteOrgsTargetCmd.Flags().BoolVarP(&deleteOrgsTargetSilent, "silent", "s", false, "Silent mode")
	DeleteOrgsTargetCmd.Flags().BoolVarP(&deleteOrgsTargetIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	DeleteOrgsTargetCmd.Flags().StringVarP(&deleteOrgsTargetUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")
}

func runDeleteOrgsTarget(cmd *cobra.Command, args []string) error {
	orgID := args[0]
	targetID := args[1]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Build the URL with the org_id and target_id path parameters
	fullURL, err := buildDeleteOrgsTargetURL(endpoint, orgID, targetID, version)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	if deleteOrgsTargetVerbose {
		fmt.Fprintf(os.Stderr, "* Requesting DELETE %s\n", fullURL)
	}

	// Create the HTTP request
	req, err := http.NewRequest("DELETE", fullURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Handle authentication with same precedence as curl: Authorization header > SNYK_TOKEN > OAuth
	if deleteOrgsTargetVerbose {
		fmt.Fprintf(os.Stderr, "* Checking authentication options\n")
	}

	authHeader, err := buildAuthHeader([]string{}) // No manual headers for this command
	if err != nil {
		if deleteOrgsTargetVerbose {
			fmt.Fprintf(os.Stderr, "* Warning: failed to get automatic auth: %v\n", err)
		}
		// Don't fail the request, just proceed without automatic auth
	} else if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
		if deleteOrgsTargetVerbose {
			fmt.Fprintf(os.Stderr, "* Added automatic authorization header\n")
		}
	} else if deleteOrgsTargetVerbose {
		fmt.Fprintf(os.Stderr, "* No automatic authorization available\n")
	}

	// Set user agent
	req.Header.Set("User-Agent", deleteOrgsTargetUserAgent)

	// Make the request
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	if deleteOrgsTargetVerbose {
		fmt.Fprintf(os.Stderr, "* Making request...\n")
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// Handle response using the same pattern as curl
	return handleDeleteOrgsTargetResponse(resp, deleteOrgsTargetIncludeResp, deleteOrgsTargetVerbose, deleteOrgsTargetSilent)
}

func buildDeleteOrgsTargetURL(endpoint, orgID, targetID, version string) (string, error) {
	// Validate the org_id parameter
	if strings.TrimSpace(orgID) == "" {
		return "", fmt.Errorf("org_id cannot be empty")
	}

	// Validate the target_id parameter
	if strings.TrimSpace(targetID) == "" {
		return "", fmt.Errorf("target_id cannot be empty")
	}

	// Build base URL with the path parameters
	baseURL := fmt.Sprintf("https://%s/rest/orgs/%s/targets/%s", endpoint, orgID, targetID)

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

func handleDeleteOrgsTargetResponse(resp *http.Response, includeResp, verbose, silent bool) error {
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