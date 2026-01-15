package cmd

import (
	"strings"
	"testing"
)

func TestBuildListAssetProjectsURL(t *testing.T) {
	tests := []struct {
		name              string
		endpoint          string
		version           string
		groupID           string
		assetID           string
		limit             int
		startingAfter     string
		endingBefore      string
		expectedURL       string
		expectedContains  []string
	}{
		{
			name:     "basic URL with version only",
			endpoint: "api.snyk.io",
			version:  "2024-10-15",
			groupID:  "test-group-id",
			assetID:  "test-asset-id",
			expectedURL: "https://api.snyk.io/rest/groups/test-group-id/assets/test-asset-id/relationships/projects?version=2024-10-15",
		},
		{
			name:        "URL with limit parameter",
			endpoint:    "api.snyk.io",
			version:     "2024-10-15",
			groupID:     "test-group-id",
			assetID:     "test-asset-id",
			limit:       10,
			expectedContains: []string{"version=2024-10-15", "limit=10"},
		},
		{
			name:          "URL with starting_after parameter",
			endpoint:      "api.snyk.io",
			version:       "2024-10-15",
			groupID:       "test-group-id",
			assetID:       "test-asset-id",
			startingAfter: "cursor123",
			expectedContains: []string{"version=2024-10-15", "starting_after=cursor123"},
		},
		{
			name:         "URL with ending_before parameter",
			endpoint:     "api.snyk.io",
			version:      "2024-10-15",
			groupID:      "test-group-id",
			assetID:      "test-asset-id",
			endingBefore: "cursor456",
			expectedContains: []string{"version=2024-10-15", "ending_before=cursor456"},
		},
		{
			name:          "URL with all parameters",
			endpoint:      "api.snyk.io",
			version:       "2024-10-15",
			groupID:       "test-group-id",
			assetID:       "test-asset-id",
			limit:         20,
			startingAfter: "cursor123",
			endingBefore:  "cursor456",
			expectedContains: []string{
				"version=2024-10-15",
				"limit=20",
				"starting_after=cursor123",
				"ending_before=cursor456",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set global variables
			listAssetProjectsLimit = tt.limit
			listAssetProjectsStartingAfter = tt.startingAfter
			listAssetProjectsEndingBefore = tt.endingBefore

			// Build URL
			url, err := buildListAssetProjectsURL(tt.endpoint, tt.version, tt.groupID, tt.assetID)
			if err != nil {
				t.Fatalf("buildListAssetProjectsURL() error = %v", err)
			}

			// Check exact URL if provided
			if tt.expectedURL != "" {
				if url != tt.expectedURL {
					t.Errorf("buildListAssetProjectsURL() = %v, want %v", url, tt.expectedURL)
				}
			}

			// Check that URL contains expected parameters
			for _, expected := range tt.expectedContains {
				if !strings.Contains(url, expected) {
					t.Errorf("URL %v does not contain expected parameter %v", url, expected)
				}
			}

			// Basic validation
			if !strings.HasPrefix(url, "https://") {
				t.Errorf("URL should start with https://")
			}
			if !strings.Contains(url, "/rest/groups/") {
				t.Errorf("URL should contain /rest/groups/")
			}
			if !strings.Contains(url, "/assets/") {
				t.Errorf("URL should contain /assets/")
			}
			if !strings.Contains(url, "/relationships/projects") {
				t.Errorf("URL should contain /relationships/projects")
			}
			if !strings.Contains(url, "version=") {
				t.Errorf("URL should always contain version parameter")
			}
			if !strings.Contains(url, tt.groupID) {
				t.Errorf("URL should contain group ID %v", tt.groupID)
			}
			if !strings.Contains(url, tt.assetID) {
				t.Errorf("URL should contain asset ID %v", tt.assetID)
			}
		})
	}
}

func TestBuildListAssetProjectsURLWithZeroLimit(t *testing.T) {
	// Test that zero limit is not included in URL
	listAssetProjectsLimit = 0
	listAssetProjectsStartingAfter = ""
	listAssetProjectsEndingBefore = ""
	
	url, err := buildListAssetProjectsURL("api.snyk.io", "2024-10-15", "test-group", "test-asset")
	if err != nil {
		t.Fatalf("buildListAssetProjectsURL() error = %v", err)
	}
	
	if strings.Contains(url, "limit=0") {
		t.Errorf("URL should not contain limit=0 when limit is zero")
	}
	
	if strings.Contains(url, "limit=") {
		t.Errorf("URL should not contain limit parameter when limit is zero")
	}
}

func TestBuildListAssetProjectsURLWithEmptyStrings(t *testing.T) {
	// Test that empty string parameters are not included in URL
	listAssetProjectsLimit = 0
	listAssetProjectsStartingAfter = ""
	listAssetProjectsEndingBefore = ""
	
	url, err := buildListAssetProjectsURL("api.snyk.io", "2024-10-15", "test-group", "test-asset")
	if err != nil {
		t.Fatalf("buildListAssetProjectsURL() error = %v", err)
	}
	
	if strings.Contains(url, "starting_after=") {
		t.Errorf("URL should not contain starting_after parameter when empty")
	}
	
	if strings.Contains(url, "ending_before=") {
		t.Errorf("URL should not contain ending_before parameter when empty")
	}
}