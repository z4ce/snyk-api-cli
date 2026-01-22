package cmd

import (
	"encoding/json"
	"fmt"
	"net/url"

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

	// Build request body
	requestBody, err := buildCreateOrgInvitationRequestBody()
	if err != nil {
		return fmt.Errorf("failed to build request body: %w", err)
	}

	return ExecuteAPIRequest(RequestOptions{
		Method:      "POST",
		URL:         fullURL,
		Body:        requestBody,
		ContentType: "application/vnd.api+json",
		Verbose:     createOrgInvitationVerbose,
		Silent:      createOrgInvitationSilent,
		IncludeResp: createOrgInvitationIncludeResp,
		UserAgent:   createOrgInvitationUserAgent,
	})
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
