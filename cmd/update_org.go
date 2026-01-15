package cmd

import (
	"encoding/json"
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

// UpdateOrgCmd represents the update-org command
var UpdateOrgCmd = &cobra.Command{
	Use:   "update-org [org_id]",
	Short: "Update an organization",
	Long: `Update an organization in the Snyk API.

This command updates an organization's details by providing the organization ID
as a required argument. The organization name can be updated via the --name flag.

The org-id flag specifies the organization's ID (defaults to the org_id argument).
The type flag specifies the content type (defaults to "org").

Examples:
  snyk-api-cli update-org 12345678-1234-1234-1234-123456789012 --name "My Updated Organization"
  snyk-api-cli update-org 12345678-1234-1234-1234-123456789012 --name "New Org Name" --verbose --include`,
	Args: cobra.ExactArgs(1),
	RunE: runUpdateOrg,
}

var (
	updateOrgName        string
	updateOrgOrgID       string
	updateOrgType        string
	updateOrgVerbose     bool
	updateOrgSilent      bool
	updateOrgIncludeResp bool
	updateOrgUserAgent   string
)

func init() {
	// Add flags for request body attributes
	UpdateOrgCmd.Flags().StringVar(&updateOrgName, "name", "", "Organization name (required)")
	UpdateOrgCmd.Flags().StringVar(&updateOrgOrgID, "org-id", "", "Organization's ID (optional, defaults to org_id argument)")
	UpdateOrgCmd.Flags().StringVar(&updateOrgType, "type", "org", "Content type for the organization (defaults to 'org')")

	// Add standard flags like other commands
	UpdateOrgCmd.Flags().BoolVarP(&updateOrgVerbose, "verbose", "v", false, "Make the operation more talkative")
	UpdateOrgCmd.Flags().BoolVarP(&updateOrgSilent, "silent", "s", false, "Silent mode")
	UpdateOrgCmd.Flags().BoolVarP(&updateOrgIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	UpdateOrgCmd.Flags().StringVarP(&updateOrgUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")

	// Mark required flags
	UpdateOrgCmd.MarkFlagRequired("name")
}

func runUpdateOrg(cmd *cobra.Command, args []string) error {
	orgID := args[0]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Use org ID from argument if not provided via flag
	if updateOrgOrgID == "" {
		updateOrgOrgID = orgID
	}

	// Build the URL
	fullURL, err := buildUpdateOrgURL(endpoint, version, orgID)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	if updateOrgVerbose {
		fmt.Fprintf(os.Stderr, "* Requesting PATCH %s\n", fullURL)
	}

	// Build request body
	requestBody, err := buildUpdateOrgRequestBody()
	if err != nil {
		return fmt.Errorf("failed to build request body: %w", err)
	}

	if updateOrgVerbose {
		fmt.Fprintf(os.Stderr, "* Request body: %s\n", requestBody)
	}

	// Create the HTTP request
	req, err := http.NewRequest("PATCH", fullURL, strings.NewReader(requestBody))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Set content type for JSON:API
	req.Header.Set("Content-Type", "application/vnd.api+json")

	// Handle authentication with same precedence as curl: Authorization header > SNYK_TOKEN > OAuth
	if updateOrgVerbose {
		fmt.Fprintf(os.Stderr, "* Checking authentication options\n")
	}

	authHeader, err := buildAuthHeader([]string{}) // No manual headers for this command
	if err != nil {
		if updateOrgVerbose {
			fmt.Fprintf(os.Stderr, "* Warning: failed to get automatic auth: %v\n", err)
		}
		// Don't fail the request, just proceed without automatic auth
	} else if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
		if updateOrgVerbose {
			fmt.Fprintf(os.Stderr, "* Added automatic authorization header\n")
		}
	} else if updateOrgVerbose {
		fmt.Fprintf(os.Stderr, "* No automatic authorization available\n")
	}

	// Set user agent
	req.Header.Set("User-Agent", updateOrgUserAgent)

	// Make the request
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	if updateOrgVerbose {
		fmt.Fprintf(os.Stderr, "* Making request...\n")
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// Handle response using the same pattern as other commands
	return handleUpdateOrgResponse(resp, updateOrgIncludeResp, updateOrgVerbose, updateOrgSilent)
}

func buildUpdateOrgURL(endpoint, version, orgID string) (string, error) {
	// Build base URL with org ID path parameter
	baseURL := fmt.Sprintf("https://%s/rest/orgs/%s", endpoint, orgID)

	// Parse URL to handle query parameters properly
	u, err := url.Parse(baseURL)
	if err != nil {
		return "", err
	}

	// Add version parameter
	q := u.Query()
	q.Set("version", version)
	u.RawQuery = q.Encode()

	return u.String(), nil
}

func buildUpdateOrgRequestBody() (string, error) {
	// Build JSON:API format request body according to the specification
	requestData := map[string]interface{}{
		"data": map[string]interface{}{
			"type": updateOrgType,
			"id":   updateOrgOrgID,
			"attributes": map[string]interface{}{
				"name": updateOrgName,
			},
		},
	}

	// Convert to JSON
	jsonData, err := json.Marshal(requestData)
	if err != nil {
		return "", fmt.Errorf("failed to marshal request body: %w", err)
	}

	return string(jsonData), nil
}

func handleUpdateOrgResponse(resp *http.Response, includeResp, verbose, silent bool) error {
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
