package cmd

import (
	"encoding/json"
	"fmt"
	"net/url"

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
	updateUserRole        string
	updateUserUserID      string
	updateUserType        string
	updateUserVerbose     bool
	updateUserSilent      bool
	updateUserIncludeResp bool
	updateUserUserAgent   string
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

	// Build request body
	requestBody, err := buildUpdateUserRequestBody()
	if err != nil {
		return fmt.Errorf("failed to build request body: %w", err)
	}

	return ExecuteAPIRequest(RequestOptions{
		Method:      "PATCH",
		URL:         fullURL,
		Body:        requestBody,
		Verbose:     updateUserVerbose,
		Silent:      updateUserSilent,
		IncludeResp: updateUserIncludeResp,
		UserAgent:   updateUserUserAgent,
	})
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
