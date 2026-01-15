package cmd

import (
	"net/url"
	"strings"
	"testing"
)

func TestBuildListOrgInvitationURL(t *testing.T) {
	tests := []struct {
		name             string
		endpoint         string
		version          string
		orgID            string
		limit            int
		startingAfter    string
		endingBefore     string
		expectedURL      string
		expectedContains []string
	}{
		{
			name:             "Basic URL with version",
			endpoint:         "api.snyk.io",
			version:          "2024-10-15",
			orgID:            "12345678-1234-1234-1234-123456789012",
			limit:            0,
			startingAfter:    "",
			endingBefore:     "",
			expectedURL:      "https://api.snyk.io/rest/orgs/12345678-1234-1234-1234-123456789012/invites?version=2024-10-15",
			expectedContains: []string{"version=2024-10-15"},
		},
		{
			name:             "URL with limit parameter",
			endpoint:         "api.snyk.io",
			version:          "2024-10-15",
			orgID:            "12345678-1234-1234-1234-123456789012",
			limit:            10,
			startingAfter:    "",
			endingBefore:     "",
			expectedURL:      "https://api.snyk.io/rest/orgs/12345678-1234-1234-1234-123456789012/invites?limit=10&version=2024-10-15",
			expectedContains: []string{"version=2024-10-15", "limit=10"},
		},
		{
			name:             "URL with pagination parameters",
			endpoint:         "api.snyk.io",
			version:          "2024-10-15",
			orgID:            "12345678-1234-1234-1234-123456789012",
			limit:            5,
			startingAfter:    "v1.eyJpZCI6IjEwMDAifQo=",
			endingBefore:     "v1.eyJpZCI6IjExMDAifQo=",
			expectedURL:      "https://api.snyk.io/rest/orgs/12345678-1234-1234-1234-123456789012/invites?ending_before=v1.eyJpZCI6IjExMDAifQo%3D&limit=5&starting_after=v1.eyJpZCI6IjEwMDAifQo%3D&version=2024-10-15",
			expectedContains: []string{"version=2024-10-15", "limit=5", "starting_after=", "ending_before="},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set up global variables
			listOrgInvitationLimit = tt.limit
			listOrgInvitationStartingAfter = tt.startingAfter
			listOrgInvitationEndingBefore = tt.endingBefore

			// Call the function
			result, err := buildListOrgInvitationURL(tt.endpoint, tt.version, tt.orgID)

			// Check for errors
			if err != nil {
				t.Errorf("buildListOrgInvitationURL() error = %v", err)
				return
			}

			// Parse the result URL to verify its structure
			parsedURL, err := url.Parse(result)
			if err != nil {
				t.Errorf("Failed to parse result URL: %v", err)
				return
			}

			// Check that required components are present
			for _, expected := range tt.expectedContains {
				if !strings.Contains(result, expected) {
					t.Errorf("Expected %q in URL %q", expected, result)
				}
			}

			// Verify the base path is correct
			expectedPath := "/rest/orgs/" + tt.orgID + "/invites"
			if parsedURL.Path != expectedPath {
				t.Errorf("Expected path %q, got %q", expectedPath, parsedURL.Path)
			}

			// Verify version parameter is always present
			if parsedURL.Query().Get("version") != tt.version {
				t.Errorf("Expected version %q, got %q", tt.version, parsedURL.Query().Get("version"))
			}

			// Reset global variables
			listOrgInvitationLimit = 0
			listOrgInvitationStartingAfter = ""
			listOrgInvitationEndingBefore = ""
		})
	}
}

func TestListOrgInvitationCommand(t *testing.T) {
	// Test command structure
	if ListOrgInvitationCmd == nil {
		t.Fatal("ListOrgInvitationCmd should not be nil")
	}

	if ListOrgInvitationCmd.Use != "list-org-invitation [org_id]" {
		t.Errorf("Expected Use 'list-org-invitation [org_id]', got %q", ListOrgInvitationCmd.Use)
	}

	if ListOrgInvitationCmd.Short == "" {
		t.Error("Short description should not be empty")
	}

	if ListOrgInvitationCmd.Long == "" {
		t.Error("Long description should not be empty")
	}

	if ListOrgInvitationCmd.RunE == nil {
		t.Error("RunE should not be nil")
	}

	// Test that command accepts exactly one argument
	if ListOrgInvitationCmd.Args == nil {
		t.Error("Args should not be nil")
	}
}

func TestListOrgInvitationFlags(t *testing.T) {
	// Test that required flags are defined
	flags := ListOrgInvitationCmd.Flags()

	// Check for limit flag
	limitFlag := flags.Lookup("limit")
	if limitFlag == nil {
		t.Error("Expected --limit flag to be defined")
	}

	// Check for starting-after flag
	startingAfterFlag := flags.Lookup("starting-after")
	if startingAfterFlag == nil {
		t.Error("Expected --starting-after flag to be defined")
	}

	// Check for ending-before flag
	endingBeforeFlag := flags.Lookup("ending-before")
	if endingBeforeFlag == nil {
		t.Error("Expected --ending-before flag to be defined")
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

