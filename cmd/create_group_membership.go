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

// CreateGroupMembershipCmd represents the create-group-membership command
var CreateGroupMembershipCmd = &cobra.Command{
	Use:   "create-group-membership [group_id]",
	Short: "Create a group membership for a specific user in Snyk",
	Long: `Create a group membership for a specific user in the Snyk API.

This command creates a group membership by associating a user with a group
and assigning them a specific role. The group ID must be provided as a 
required argument, and the user ID and role ID must be provided as flags.

Examples:
  snyk-api-cli create-group-membership 12345678-1234-1234-1234-123456789012 --user-id 87654321-4321-4321-4321-210987654321 --role-id 11111111-1111-1111-1111-111111111111
  snyk-api-cli create-group-membership 12345678-1234-1234-1234-123456789012 --user-id 87654321-4321-4321-4321-210987654321 --role-id 11111111-1111-1111-1111-111111111111 --verbose --include`,
	Args: cobra.ExactArgs(1),
	RunE: runCreateGroupMembership,
}

var (
	createGroupMembershipUserID       string
	createGroupMembershipRoleID       string
	createGroupMembershipVerbose      bool
	createGroupMembershipSilent       bool
	createGroupMembershipIncludeResp  bool
	createGroupMembershipUserAgent    string
)

func init() {
	// Add flags for request body attributes
	CreateGroupMembershipCmd.Flags().StringVar(&createGroupMembershipUserID, "user-id", "", "User ID to add to the group (required)")
	CreateGroupMembershipCmd.Flags().StringVar(&createGroupMembershipRoleID, "role-id", "", "Role ID to assign to the user (required)")
	
	// Add standard flags like other commands
	CreateGroupMembershipCmd.Flags().BoolVarP(&createGroupMembershipVerbose, "verbose", "v", false, "Make the operation more talkative")
	CreateGroupMembershipCmd.Flags().BoolVarP(&createGroupMembershipSilent, "silent", "s", false, "Silent mode")
	CreateGroupMembershipCmd.Flags().BoolVarP(&createGroupMembershipIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	CreateGroupMembershipCmd.Flags().StringVarP(&createGroupMembershipUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")

	// Mark required flags
	CreateGroupMembershipCmd.MarkFlagRequired("user-id")
	CreateGroupMembershipCmd.MarkFlagRequired("role-id")
}

func runCreateGroupMembership(cmd *cobra.Command, args []string) error {
	groupID := args[0]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Build the URL
	fullURL, err := buildCreateGroupMembershipURL(endpoint, version, groupID)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	if createGroupMembershipVerbose {
		fmt.Fprintf(os.Stderr, "* Requesting POST %s\n", fullURL)
	}

	// Build request body
	requestBody, err := buildCreateGroupMembershipRequestBody(groupID)
	if err != nil {
		return fmt.Errorf("failed to build request body: %w", err)
	}

	if createGroupMembershipVerbose {
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
	if createGroupMembershipVerbose {
		fmt.Fprintf(os.Stderr, "* Checking authentication options\n")
	}

	authHeader, err := buildAuthHeader([]string{}) // No manual headers for this command
	if err != nil {
		if createGroupMembershipVerbose {
			fmt.Fprintf(os.Stderr, "* Warning: failed to get automatic auth: %v\n", err)
		}
		// Don't fail the request, just proceed without automatic auth
	} else if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
		if createGroupMembershipVerbose {
			fmt.Fprintf(os.Stderr, "* Added automatic authorization header\n")
		}
	} else if createGroupMembershipVerbose {
		fmt.Fprintf(os.Stderr, "* No automatic authorization available\n")
	}

	// Set user agent
	req.Header.Set("User-Agent", createGroupMembershipUserAgent)

	// Make the request
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	if createGroupMembershipVerbose {
		fmt.Fprintf(os.Stderr, "* Making request...\n")
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// Handle response using the same pattern as other commands
	return handleCreateGroupMembershipResponse(resp, createGroupMembershipIncludeResp, createGroupMembershipVerbose, createGroupMembershipSilent)
}

func buildCreateGroupMembershipURL(endpoint, version, groupID string) (string, error) {
	// Build base URL with group ID path parameter
	baseURL := fmt.Sprintf("https://%s/rest/groups/%s/memberships", endpoint, groupID)

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

func buildCreateGroupMembershipRequestBody(groupID string) (string, error) {
	// Build JSON:API format request body according to the specification
	requestData := map[string]interface{}{
		"data": map[string]interface{}{
			"type": "group_membership",
			"relationships": map[string]interface{}{
				"group": map[string]interface{}{
					"data": map[string]interface{}{
						"id":   groupID,
						"type": "group",
					},
				},
				"role": map[string]interface{}{
					"data": map[string]interface{}{
						"id":   createGroupMembershipRoleID,
						"type": "group_role",
					},
				},
				"user": map[string]interface{}{
					"data": map[string]interface{}{
						"id":   createGroupMembershipUserID,
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

func handleCreateGroupMembershipResponse(resp *http.Response, includeResp, verbose, silent bool) error {
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