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

// UpdateGroupUserMembershipCmd represents the update-group-user-membership command
var UpdateGroupUserMembershipCmd = &cobra.Command{
	Use:   "update-group-user-membership [group_id] [membership_id]",
	Short: "Update a user's membership in a group",
	Long: `Update a user's membership in a group in the Snyk API.

This command updates a user's membership by changing their role within a group.
Both the group ID and membership ID must be provided as required arguments.

The role-id flag specifies the new role to assign to the user's membership.

Examples:
  snyk-api-cli update-group-user-membership 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321 --role-id 11111111-1111-1111-1111-111111111111
  snyk-api-cli update-group-user-membership 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321 --role-id 11111111-1111-1111-1111-111111111111 --verbose --include`,
	Args: cobra.ExactArgs(2),
	RunE: runUpdateGroupUserMembership,
}

var (
	updateGroupUserMembershipRoleID        string
	updateGroupUserMembershipID            string
	updateGroupUserMembershipType          string
	updateGroupUserMembershipVerbose       bool
	updateGroupUserMembershipSilent        bool
	updateGroupUserMembershipIncludeResp   bool
	updateGroupUserMembershipUserAgent     string
)

func init() {
	// Add flags for request body attributes
	UpdateGroupUserMembershipCmd.Flags().StringVar(&updateGroupUserMembershipRoleID, "role-id", "", "Role ID to assign to the user (required)")
	UpdateGroupUserMembershipCmd.Flags().StringVar(&updateGroupUserMembershipID, "id", "", "Membership ID (optional, defaults to membership_id argument)")
	UpdateGroupUserMembershipCmd.Flags().StringVar(&updateGroupUserMembershipType, "type", "", "Type field for the membership (optional)")
	
	// Add standard flags like other commands
	UpdateGroupUserMembershipCmd.Flags().BoolVarP(&updateGroupUserMembershipVerbose, "verbose", "v", false, "Make the operation more talkative")
	UpdateGroupUserMembershipCmd.Flags().BoolVarP(&updateGroupUserMembershipSilent, "silent", "s", false, "Silent mode")
	UpdateGroupUserMembershipCmd.Flags().BoolVarP(&updateGroupUserMembershipIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	UpdateGroupUserMembershipCmd.Flags().StringVarP(&updateGroupUserMembershipUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")

	// Mark required flags
	UpdateGroupUserMembershipCmd.MarkFlagRequired("role-id")
}

func runUpdateGroupUserMembership(cmd *cobra.Command, args []string) error {
	groupID := args[0]
	membershipID := args[1]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Use membership ID from argument if not provided via flag
	if updateGroupUserMembershipID == "" {
		updateGroupUserMembershipID = membershipID
	}

	// Build the URL
	fullURL, err := buildUpdateGroupUserMembershipURL(endpoint, version, groupID, membershipID)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	if updateGroupUserMembershipVerbose {
		fmt.Fprintf(os.Stderr, "* Requesting PATCH %s\n", fullURL)
	}

	// Build request body
	requestBody, err := buildUpdateGroupUserMembershipRequestBody()
	if err != nil {
		return fmt.Errorf("failed to build request body: %w", err)
	}

	if updateGroupUserMembershipVerbose {
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
	if updateGroupUserMembershipVerbose {
		fmt.Fprintf(os.Stderr, "* Checking authentication options\n")
	}

	authHeader, err := buildAuthHeader([]string{}) // No manual headers for this command
	if err != nil {
		if updateGroupUserMembershipVerbose {
			fmt.Fprintf(os.Stderr, "* Warning: failed to get automatic auth: %v\n", err)
		}
		// Don't fail the request, just proceed without automatic auth
	} else if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
		if updateGroupUserMembershipVerbose {
			fmt.Fprintf(os.Stderr, "* Added automatic authorization header\n")
		}
	} else if updateGroupUserMembershipVerbose {
		fmt.Fprintf(os.Stderr, "* No automatic authorization available\n")
	}

	// Set user agent
	req.Header.Set("User-Agent", updateGroupUserMembershipUserAgent)

	// Make the request
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	if updateGroupUserMembershipVerbose {
		fmt.Fprintf(os.Stderr, "* Making request...\n")
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// Handle response using the same pattern as other commands
	return handleUpdateGroupUserMembershipResponse(resp, updateGroupUserMembershipIncludeResp, updateGroupUserMembershipVerbose, updateGroupUserMembershipSilent)
}

func buildUpdateGroupUserMembershipURL(endpoint, version, groupID, membershipID string) (string, error) {
	// Build base URL with group ID and membership ID path parameters
	baseURL := fmt.Sprintf("https://%s/rest/groups/%s/memberships/%s", endpoint, groupID, membershipID)

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

func buildUpdateGroupUserMembershipRequestBody() (string, error) {
	// Build JSON:API format request body according to the specification
	requestData := map[string]interface{}{
		"data": map[string]interface{}{
			"id": updateGroupUserMembershipID,
			"relationships": map[string]interface{}{
				"role": map[string]interface{}{
					"data": map[string]interface{}{
						"id":   updateGroupUserMembershipRoleID,
						"type": "group_role",
					},
				},
			},
		},
	}

	// Add optional attributes if provided
	dataMap := requestData["data"].(map[string]interface{})
	if updateGroupUserMembershipType != "" {
		dataMap["type"] = updateGroupUserMembershipType
	}

	// Convert to JSON
	jsonData, err := json.Marshal(requestData)
	if err != nil {
		return "", fmt.Errorf("failed to marshal request body: %w", err)
	}

	return string(jsonData), nil
}

func handleUpdateGroupUserMembershipResponse(resp *http.Response, includeResp, verbose, silent bool) error {
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