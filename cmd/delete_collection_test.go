package cmd

import (
	"testing"
)

func TestBuildDeleteCollectionURL(t *testing.T) {
	tests := []struct {
		name         string
		endpoint     string
		orgID        string
		collectionID string
		version      string
		expected     string
		expectError  bool
	}{
		{
			name:         "valid parameters",
			endpoint:     "api.snyk.io",
			orgID:        "12345678-1234-5678-9012-123456789012",
			collectionID: "87654321-4321-8765-2109-876543210987",
			version:      "2024-10-15",
			expected:     "https://api.snyk.io/rest/orgs/12345678-1234-5678-9012-123456789012/collections/87654321-4321-8765-2109-876543210987?version=2024-10-15",
			expectError:  false,
		},
		{
			name:         "empty org_id",
			endpoint:     "api.snyk.io",
			orgID:        "",
			collectionID: "87654321-4321-8765-2109-876543210987",
			version:      "2024-10-15",
			expected:     "",
			expectError:  true,
		},
		{
			name:         "empty collection_id",
			endpoint:     "api.snyk.io",
			orgID:        "12345678-1234-5678-9012-123456789012",
			collectionID: "",
			version:      "2024-10-15",
			expected:     "",
			expectError:  true,
		},
		{
			name:         "whitespace org_id",
			endpoint:     "api.snyk.io",
			orgID:        "   ",
			collectionID: "87654321-4321-8765-2109-876543210987",
			version:      "2024-10-15",
			expected:     "",
			expectError:  true,
		},
		{
			name:         "whitespace collection_id",
			endpoint:     "api.snyk.io",
			orgID:        "12345678-1234-5678-9012-123456789012",
			collectionID: "   ",
			version:      "2024-10-15",
			expected:     "",
			expectError:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := buildDeleteCollectionURL(tt.endpoint, tt.orgID, tt.collectionID, tt.version)

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}

			if result != tt.expected {
				t.Errorf("Expected URL: %s, got: %s", tt.expected, result)
			}
		})
	}
}