package cmd

import (
	"encoding/json"
	"net/url"
	"testing"
)

func TestBuildCreateOrgInvitationURL(t *testing.T) {
	tests := []struct {
		name        string
		endpoint    string
		version     string
		orgID       string
		expectedURL string
	}{
		{
			name:        "Basic URL with version",
			endpoint:    "api.snyk.io",
			version:     "2024-10-15",
			orgID:       "12345678-1234-1234-1234-123456789012",
			expectedURL: "https://api.snyk.io/rest/orgs/12345678-1234-1234-1234-123456789012/invites?version=2024-10-15",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := buildCreateOrgInvitationURL(tt.endpoint, tt.version, tt.orgID)

			if err != nil {
				t.Errorf("buildCreateOrgInvitationURL() error = %v", err)
				return
			}

			if result != tt.expectedURL {
				t.Errorf("Expected URL %q, got %q", tt.expectedURL, result)
			}

			// Parse the result URL to verify its structure
			parsedURL, err := url.Parse(result)
			if err != nil {
				t.Errorf("Failed to parse result URL: %v", err)
				return
			}

			// Verify the base path is correct
			expectedPath := "/rest/orgs/" + tt.orgID + "/invites"
			if parsedURL.Path != expectedPath {
				t.Errorf("Expected path %q, got %q", expectedPath, parsedURL.Path)
			}

			// Verify version parameter is present
			if parsedURL.Query().Get("version") != tt.version {
				t.Errorf("Expected version %q, got %q", tt.version, parsedURL.Query().Get("version"))
			}
		})
	}
}

func TestBuildCreateOrgInvitationRequestBody(t *testing.T) {
	tests := []struct {
		name          string
		email         string
		role          string
		expectedEmail string
		expectedRole  string
	}{
		{
			name:          "Valid email and role",
			email:         "user@example.com",
			role:          "87654321-4321-4321-4321-876543210987",
			expectedEmail: "user@example.com",
			expectedRole:  "87654321-4321-4321-4321-876543210987",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set up global variables
			createOrgInvitationEmail = tt.email
			createOrgInvitationRole = tt.role

			result, err := buildCreateOrgInvitationRequestBody()

			if err != nil {
				t.Errorf("buildCreateOrgInvitationRequestBody() error = %v", err)
				return
			}

			// Parse the JSON to verify its structure
			var requestData map[string]interface{}
			if err := json.Unmarshal([]byte(result), &requestData); err != nil {
				t.Errorf("Failed to parse JSON: %v", err)
				return
			}

			// Check data structure
			data, ok := requestData["data"].(map[string]interface{})
			if !ok {
				t.Error("Expected 'data' field to be an object")
				return
			}

			// Check type
			if data["type"] != "org_invitation" {
				t.Errorf("Expected type 'org_invitation', got %v", data["type"])
			}

			// Check attributes
			attributes, ok := data["attributes"].(map[string]interface{})
			if !ok {
				t.Error("Expected 'attributes' field to be an object")
				return
			}

			// Check email
			if attributes["email"] != tt.expectedEmail {
				t.Errorf("Expected email %q, got %v", tt.expectedEmail, attributes["email"])
			}

			// Check role
			if attributes["role"] != tt.expectedRole {
				t.Errorf("Expected role %q, got %v", tt.expectedRole, attributes["role"])
			}

			// Reset global variables
			createOrgInvitationEmail = ""
			createOrgInvitationRole = ""
		})
	}
}

func TestCreateOrgInvitationCommand(t *testing.T) {
	// Test command structure
	if CreateOrgInvitationCmd == nil {
		t.Fatal("CreateOrgInvitationCmd should not be nil")
	}

	if CreateOrgInvitationCmd.Use != "create-org-invitation [org_id]" {
		t.Errorf("Expected Use 'create-org-invitation [org_id]', got %q", CreateOrgInvitationCmd.Use)
	}

	if CreateOrgInvitationCmd.Short == "" {
		t.Error("Short description should not be empty")
	}

	if CreateOrgInvitationCmd.Long == "" {
		t.Error("Long description should not be empty")
	}

	if CreateOrgInvitationCmd.RunE == nil {
		t.Error("RunE should not be nil")
	}
}

func TestCreateOrgInvitationFlags(t *testing.T) {
	// Test that required flags are defined
	flags := CreateOrgInvitationCmd.Flags()

	// Check for email flag
	emailFlag := flags.Lookup("email")
	if emailFlag == nil {
		t.Error("Expected --email flag to be defined")
	}

	// Check for role flag
	roleFlag := flags.Lookup("role")
	if roleFlag == nil {
		t.Error("Expected --role flag to be defined")
	}

	// Check for standard flags
	verboseFlag := flags.Lookup("verbose")
	if verboseFlag == nil {
		t.Error("Expected --verbose flag to be defined")
	}

	silentFlag := flags.Lookup("silent")
	if silentFlag == nil {
		t.Error("Expected --silent flag to be defined")
	}

	includeFlag := flags.Lookup("include")
	if includeFlag == nil {
		t.Error("Expected --include flag to be defined")
	}

	userAgentFlag := flags.Lookup("user-agent")
	if userAgentFlag == nil {
		t.Error("Expected --user-agent flag to be defined")
	}
}