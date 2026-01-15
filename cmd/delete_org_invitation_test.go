package cmd

import (
	"net/url"
	"testing"
)

func TestBuildDeleteOrgInvitationURL(t *testing.T) {
	tests := []struct {
		name        string
		endpoint    string
		orgID       string
		inviteID    string
		version     string
		expectedURL string
		shouldError bool
	}{
		{
			name:        "Basic URL with version",
			endpoint:    "api.snyk.io",
			orgID:       "12345678-1234-1234-1234-123456789012",
			inviteID:    "87654321-4321-4321-4321-876543210987",
			version:     "2024-10-15",
			expectedURL: "https://api.snyk.io/rest/orgs/12345678-1234-1234-1234-123456789012/invites/87654321-4321-4321-4321-876543210987?version=2024-10-15",
			shouldError: false,
		},
		{
			name:        "Empty org_id should error",
			endpoint:    "api.snyk.io",
			orgID:       "",
			inviteID:    "87654321-4321-4321-4321-876543210987",
			version:     "2024-10-15",
			expectedURL: "",
			shouldError: true,
		},
		{
			name:        "Empty invite_id should error",
			endpoint:    "api.snyk.io",
			orgID:       "12345678-1234-1234-1234-123456789012",
			inviteID:    "",
			version:     "2024-10-15",
			expectedURL: "",
			shouldError: true,
		},
		{
			name:        "Whitespace org_id should error",
			endpoint:    "api.snyk.io",
			orgID:       "   ",
			inviteID:    "87654321-4321-4321-4321-876543210987",
			version:     "2024-10-15",
			expectedURL: "",
			shouldError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := buildDeleteOrgInvitationURL(tt.endpoint, tt.orgID, tt.inviteID, tt.version)

			if tt.shouldError {
				if err == nil {
					t.Error("Expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("buildDeleteOrgInvitationURL() error = %v", err)
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
			expectedPath := "/rest/orgs/" + tt.orgID + "/invites/" + tt.inviteID
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

func TestDeleteOrgInvitationCommand(t *testing.T) {
	// Test command structure
	if DeleteOrgInvitationCmd == nil {
		t.Fatal("DeleteOrgInvitationCmd should not be nil")
	}

	if DeleteOrgInvitationCmd.Use != "delete-org-invitation [org_id] [invite_id]" {
		t.Errorf("Expected Use 'delete-org-invitation [org_id] [invite_id]', got %q", DeleteOrgInvitationCmd.Use)
	}

	if DeleteOrgInvitationCmd.Short == "" {
		t.Error("Short description should not be empty")
	}

	if DeleteOrgInvitationCmd.Long == "" {
		t.Error("Long description should not be empty")
	}

	if DeleteOrgInvitationCmd.RunE == nil {
		t.Error("RunE should not be nil")
	}
}

func TestDeleteOrgInvitationFlags(t *testing.T) {
	// Test that required flags are defined
	flags := DeleteOrgInvitationCmd.Flags()

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