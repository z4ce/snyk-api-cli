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

// CreateOrgMembershipCmd represents the create-org-membership command
var CreateOrgMembershipCmd = &cobra.Command{
	Use:   "create-org-membership [org_id]",
	Short: "Create an organization membership for a user with role in Snyk",
	Long: `Create an organization membership for a user with role in the Snyk API.

This command creates a membership for a specific user in an organization with a specified role.
The organization ID must be provided as a required argument, and the user ID and role ID 
must be provided as flags.

Examples:
  snyk-api-cli create-org-membership 12345678-1234-1234-1234-123456789012 --user-id 87654321-4321-4321-4321-876543210987 --role-id 11111111-2222-3333-4444-555555555555
  snyk-api-cli create-org-membership 12345678-1234-1234-1234-123456789012 --user-id 87654321-4321-4321-4321-876543210987 --role-id 11111111-2222-3333-4444-555555555555 --verbose`,
	Args: cobra.ExactArgs(1),
	RunE: runCreateOrgMembership,
}

var (
	createOrgMembershipUserID     string
	createOrgMembershipRoleID     string
	createOrgMembershipVerbose    bool
	createOrgMembershipSilent     bool
	createOrgMembershipIncludeResp bool
	createOrgMembershipUserAgent  string
)

func init() {
	// Add flags for request body attributes
	CreateOrgMembershipCmd.Flags().StringVar(&createOrgMembershipUserID, "user-id", "", "User ID to add to the organization (required)")
	CreateOrgMembershipCmd.Flags().StringVar(&createOrgMembershipRoleID, "role-id", "", "Role ID to assign to the user (required)")

	// Add standard flags like other commands
	CreateOrgMembershipCmd.Flags().BoolVarP(&createOrgMembershipVerbose, "verbose", "v", false, "Make the operation more talkative")
	CreateOrgMembershipCmd.Flags().BoolVarP(&createOrgMembershipSilent, "silent", "s", false, "Silent mode")
	CreateOrgMembershipCmd.Flags().BoolVarP(&createOrgMembershipIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	CreateOrgMembershipCmd.Flags().StringVarP(&createOrgMembershipUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")

	// Mark required flags
	CreateOrgMembershipCmd.MarkFlagRequired("user-id")
	CreateOrgMembershipCmd.MarkFlagRequired("role-id")
}

func runCreateOrgMembership(cmd *cobra.Command, args []string) error {
	orgID := args[0]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Build the URL
	fullURL, err := buildCreateOrgMembershipURL(endpoint, version, orgID)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	if createOrgMembershipVerbose {
		fmt.Fprintf(os.Stderr, "* Requesting POST %s\n", fullURL)
	}

	// Build request body
	requestBody, err := buildCreateOrgMembershipRequestBody(orgID)
	if err != nil {
		return fmt.Errorf("failed to build request body: %w", err)
	}

	if createOrgMembershipVerbose {
		fmt.Fprintf(os.Stderr, "* Request body: %s\n", requestBody)
	}

	// Create the HTTP request
	req, err := http.NewRequest("POST", fullURL, strings.NewReader(requestBody))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Set content type for JSON:API
	req.Header.Set("Content-Type", "application/vnd.api+json")

	// Handle authentication with same precedence as curl: Authorization header > SNYK_TOKEN > OAuth
	if createOrgMembershipVerbose {
		fmt.Fprintf(os.Stderr, "* Checking authentication options\n")
	}

	authHeader, err := buildAuthHeader([]string{}) // No manual headers for this command
	if err != nil {
		if createOrgMembershipVerbose {
			fmt.Fprintf(os.Stderr, "* Warning: failed to get automatic auth: %v\n", err)
		}
		// Don't fail the request, just proceed without automatic auth
	} else if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
		if createOrgMembershipVerbose {
			fmt.Fprintf(os.Stderr, "* Added automatic authorization header\n")
		}
	} else if createOrgMembershipVerbose {
		fmt.Fprintf(os.Stderr, "* No automatic authorization available\n")
	}

	// Set user agent
	req.Header.Set("User-Agent", createOrgMembershipUserAgent)

	// Make the request
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	if createOrgMembershipVerbose {
		fmt.Fprintf(os.Stderr, "* Making request...\n")
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// Handle response using the same pattern as other commands
	return handleCreateOrgMembershipResponse(resp, createOrgMembershipIncludeResp, createOrgMembershipVerbose, createOrgMembershipSilent)
}

func buildCreateOrgMembershipURL(endpoint, version, orgID string) (string, error) {
	// Build base URL with organization ID path parameter
	baseURL := fmt.Sprintf("https://%s/rest/orgs/%s/memberships", endpoint, orgID)

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

func buildCreateOrgMembershipRequestBody(orgID string) (string, error) {
	// Build request body according to the JSON:API specification
	requestData := map[string]interface{}{
		"data": map[string]interface{}{
			"type": "org_membership",
			"relationships": map[string]interface{}{
				"org": map[string]interface{}{
					"data": map[string]interface{}{
						"id":   orgID,
						"type": "org",
					},
				},
				"role": map[string]interface{}{
					"data": map[string]interface{}{
						"id":   createOrgMembershipRoleID,
						"type": "org_role",
					},
				},
				"user": map[string]interface{}{
					"data": map[string]interface{}{
						"id":   createOrgMembershipUserID,
						"type": "user",
					},
				},
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

func handleCreateOrgMembershipResponse(resp *http.Response, includeResp, verbose, silent bool) error {
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