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

// UpdateUserCmd represents the update-user command
var UpdateUserCmd = &cobra.Command{
	Use:   "update-user [group_id] [id]",
	Short: "Update a user in a group",
	Long: `Update a user in a group in the Snyk API.

This command updates a user's membership by changing their role within a group.
Both the group ID and user ID must be provided as required arguments.

The role flag specifies the new role to assign to the user's membership.
The user-id flag specifies the user's Snyk ID (defaults to the id argument).
The type flag specifies the content type (required).

Examples:
  snyk-api-cli update-user 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321 --role admin --type user
  snyk-api-cli update-user 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321 --role viewer --type user --verbose --include`,
	Args: cobra.ExactArgs(2),
	RunE: runUpdateUser,
}

var (
	updateUserRole         string
	updateUserUserID       string
	updateUserType         string
	updateUserVerbose      bool
	updateUserSilent       bool
	updateUserIncludeResp  bool
	updateUserUserAgent    string
)

func init() {
	// Add flags for request body attributes
	UpdateUserCmd.Flags().StringVar(&updateUserRole, "role", "", "Role name to assign to the user's membership (required)")
	UpdateUserCmd.Flags().StringVar(&updateUserUserID, "user-id", "", "User's Snyk ID (optional, defaults to id argument)")
	UpdateUserCmd.Flags().StringVar(&updateUserType, "type", "", "Content type for the user (required)")
	
	// Add standard flags like other commands
	UpdateUserCmd.Flags().BoolVarP(&updateUserVerbose, "verbose", "v", false, "Make the operation more talkative")
	UpdateUserCmd.Flags().BoolVarP(&updateUserSilent, "silent", "s", false, "Silent mode")
	UpdateUserCmd.Flags().BoolVarP(&updateUserIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	UpdateUserCmd.Flags().StringVarP(&updateUserUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")

	// Mark required flags
	UpdateUserCmd.MarkFlagRequired("role")
	UpdateUserCmd.MarkFlagRequired("type")
}

func runUpdateUser(cmd *cobra.Command, args []string) error {
	groupID := args[0]
	userID := args[1]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Use user ID from argument if not provided via flag
	if updateUserUserID == "" {
		updateUserUserID = userID
	}

	// Build the URL
	fullURL, err := buildUpdateUserURL(endpoint, version, groupID, userID)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	if updateUserVerbose {
		fmt.Fprintf(os.Stderr, "* Requesting PATCH %s\n", fullURL)
	}

	// Build request body
	requestBody, err := buildUpdateUserRequestBody()
	if err != nil {
		return fmt.Errorf("failed to build request body: %w", err)
	}

	if updateUserVerbose {
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
	if updateUserVerbose {
		fmt.Fprintf(os.Stderr, "* Checking authentication options\n")
	}

	authHeader, err := buildAuthHeader([]string{}) // No manual headers for this command
	if err != nil {
		if updateUserVerbose {
			fmt.Fprintf(os.Stderr, "* Warning: failed to get automatic auth: %v\n", err)
		}
		// Don't fail the request, just proceed without automatic auth
	} else if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
		if updateUserVerbose {
			fmt.Fprintf(os.Stderr, "* Added automatic authorization header\n")
		}
	} else if updateUserVerbose {
		fmt.Fprintf(os.Stderr, "* No automatic authorization available\n")
	}

	// Set user agent
	req.Header.Set("User-Agent", updateUserUserAgent)

	// Make the request
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	if updateUserVerbose {
		fmt.Fprintf(os.Stderr, "* Making request...\n")
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// Handle response using the same pattern as other commands
	return handleUpdateUserResponse(resp, updateUserIncludeResp, updateUserVerbose, updateUserSilent)
}

func buildUpdateUserURL(endpoint, version, groupID, userID string) (string, error) {
	// Build base URL with group ID and user ID path parameters
	baseURL := fmt.Sprintf("https://%s/rest/groups/%s/users/%s", endpoint, groupID, userID)

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

func buildUpdateUserRequestBody() (string, error) {
	// Build JSON:API format request body according to the specification
	requestData := map[string]interface{}{
		"data": map[string]interface{}{
			"type": updateUserType,
			"id":   updateUserUserID,
			"attributes": map[string]interface{}{
				"membership": map[string]interface{}{
					"role": updateUserRole,
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

func handleUpdateUserResponse(resp *http.Response, includeResp, verbose, silent bool) error {
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