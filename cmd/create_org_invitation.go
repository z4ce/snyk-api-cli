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

// CreateOrgInvitationCmd represents the create-org-invitation command
var CreateOrgInvitationCmd = &cobra.Command{
	Use:   "create-org-invitation [org_id]",
	Short: "Invite a user to an organization",
	Long: `Invite a user to an organization in the Snyk API.

This command creates an invitation for a user to join a specific organization.
The organization ID must be provided as a required argument, and the user's
email address and role must be provided as flags.

Examples:
  snyk-api-cli create-org-invitation 12345678-1234-1234-1234-123456789012 --email "user@example.com" --role "87654321-4321-4321-4321-876543210987"
  snyk-api-cli create-org-invitation 12345678-1234-1234-1234-123456789012 --email "user@example.com" --role "87654321-4321-4321-4321-876543210987" --verbose`,
	Args: cobra.ExactArgs(1),
	RunE: runCreateOrgInvitation,
}

var (
	createOrgInvitationEmail       string
	createOrgInvitationRole        string
	createOrgInvitationVerbose     bool
	createOrgInvitationSilent      bool
	createOrgInvitationIncludeResp bool
	createOrgInvitationUserAgent   string
)

func init() {
	// Add flags for request body attributes
	CreateOrgInvitationCmd.Flags().StringVar(&createOrgInvitationEmail, "email", "", "Email address of the user to invite (required)")
	CreateOrgInvitationCmd.Flags().StringVar(&createOrgInvitationRole, "role", "", "Role UUID for the user in the organization (required)")

	// Add standard flags like other commands
	CreateOrgInvitationCmd.Flags().BoolVarP(&createOrgInvitationVerbose, "verbose", "v", false, "Make the operation more talkative")
	CreateOrgInvitationCmd.Flags().BoolVarP(&createOrgInvitationSilent, "silent", "s", false, "Silent mode")
	CreateOrgInvitationCmd.Flags().BoolVarP(&createOrgInvitationIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	CreateOrgInvitationCmd.Flags().StringVarP(&createOrgInvitationUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")

	// Mark required flags
	CreateOrgInvitationCmd.MarkFlagRequired("email")
	CreateOrgInvitationCmd.MarkFlagRequired("role")
}

func runCreateOrgInvitation(cmd *cobra.Command, args []string) error {
	orgID := args[0]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Build the URL
	fullURL, err := buildCreateOrgInvitationURL(endpoint, version, orgID)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	if createOrgInvitationVerbose {
		fmt.Fprintf(os.Stderr, "* Requesting POST %s\n", fullURL)
	}

	// Build request body
	requestBody, err := buildCreateOrgInvitationRequestBody()
	if err != nil {
		return fmt.Errorf("failed to build request body: %w", err)
	}

	if createOrgInvitationVerbose {
		fmt.Fprintf(os.Stderr, "* Request body: %s\n", requestBody)
	}

	// Create the HTTP request
	req, err := http.NewRequest("POST", fullURL, strings.NewReader(requestBody))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Set content type for JSON API
	req.Header.Set("Content-Type", "application/vnd.api+json")

	// Handle authentication with same precedence as curl: Authorization header > SNYK_TOKEN > OAuth
	if createOrgInvitationVerbose {
		fmt.Fprintf(os.Stderr, "* Checking authentication options\n")
	}

	authHeader, err := buildAuthHeader([]string{}) // No manual headers for this command
	if err != nil {
		if createOrgInvitationVerbose {
			fmt.Fprintf(os.Stderr, "* Warning: failed to get automatic auth: %v\n", err)
		}
		// Don't fail the request, just proceed without automatic auth
	} else if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
		if createOrgInvitationVerbose {
			fmt.Fprintf(os.Stderr, "* Added automatic authorization header\n")
		}
	} else if createOrgInvitationVerbose {
		fmt.Fprintf(os.Stderr, "* No automatic authorization available\n")
	}

	// Set user agent
	req.Header.Set("User-Agent", createOrgInvitationUserAgent)

	// Make the request
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	if createOrgInvitationVerbose {
		fmt.Fprintf(os.Stderr, "* Making request...\n")
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// Handle response using the same pattern as other commands
	return handleCreateOrgInvitationResponse(resp, createOrgInvitationIncludeResp, createOrgInvitationVerbose, createOrgInvitationSilent)
}

func buildCreateOrgInvitationURL(endpoint, version, orgID string) (string, error) {
	// Build base URL with organization ID path parameter
	baseURL := fmt.Sprintf("https://%s/rest/orgs/%s/invites", endpoint, orgID)

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

func buildCreateOrgInvitationRequestBody() (string, error) {
	// Build request body according to the JSON:API specification
	requestData := map[string]interface{}{
		"data": map[string]interface{}{
			"type": "org_invitation",
			"attributes": map[string]interface{}{
				"email": createOrgInvitationEmail,
				"role":  createOrgInvitationRole,
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

func handleCreateOrgInvitationResponse(resp *http.Response, includeResp, verbose, silent bool) error {
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