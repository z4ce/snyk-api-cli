# Organization Settings Endpoints Implementation

This document summarizes the implementation of 4 organization settings endpoints for the Snyk API CLI.

## Implemented Endpoints

### 1. Get IAC Settings for Organization
**File:** `/Users/ianzink/git/snyk-api-cli/cmd/get_iac_settings_for_org.go`
- **Command:** `get-iac-settings-for-org`
- **Method:** GET
- **Path:** `/orgs/{org_id}/settings/iac`
- **Description:** Get the Infrastructure as Code Settings for an organization
- **Usage:** `snyk-api-cli get-iac-settings-for-org [org_id]`
- **Required Permissions:** View Organization (org.read)

### 2. Update IAC Settings for Organization
**File:** `/Users/ianzink/git/snyk-api-cli/cmd/update_iac_settings_for_org.go`
- **Command:** `update-iac-settings-for-org`
- **Method:** PATCH
- **Path:** `/orgs/{org_id}/settings/iac`
- **Description:** Update the Infrastructure as Code Settings for an organization
- **Usage:** `snyk-api-cli update-iac-settings-for-org [org_id] [flags]`
- **Required Permissions:** Edit Organization (org.edit)
- **Flags:**
  - `--type`: The type field for the data object (default: "org_settings")
  - `--custom-rules-enabled`: Enable or disable custom rules
  - `--custom-rules-oci-registry-url`: OCI registry URL for custom rules
  - `--custom-rules-oci-registry-tag`: OCI registry tag for custom rules
  - `--custom-rules-inherit-from-parent`: Inherit custom rules from parent

### 3. Get SAST Settings for Organization
**File:** `/Users/ianzink/git/snyk-api-cli/cmd/get_sast_settings.go`
- **Command:** `get-sast-settings`
- **Method:** GET
- **Path:** `/orgs/{org_id}/settings/sast`
- **Description:** Retrieves the SAST settings for an organization
- **Usage:** `snyk-api-cli get-sast-settings [org_id]`
- **Required Permissions:** View Organization (org.read)

### 4. Update Organization SAST Settings
**File:** `/Users/ianzink/git/snyk-api-cli/cmd/update_org_sast_settings.go`
- **Command:** `update-org-sast-settings`
- **Method:** PATCH
- **Path:** `/orgs/{org_id}/settings/sast`
- **Description:** Enable/Disable the Snyk Code settings for an organization
- **Usage:** `snyk-api-cli update-org-sast-settings [org_id] [flags]`
- **Required Permissions:** View Organization (org.read), Edit Organization (org.edit)
- **Flags:**
  - `--type`: The type field for the data object (default: "sast_settings")
  - `--id`: The ID field for the data object (UUID)
  - `--sast-enabled`: Enable or disable SAST

## Implementation Details

### Following Established Patterns
All commands follow the exact patterns established in the existing codebase:

- **GET Commands:** Follow the pattern from `get_container_image.go`
- **PATCH Commands:** Follow the pattern from `update_collection.go`
- **Authentication:** Use the same `buildAuthHeader` function for consistent auth handling
- **Error Handling:** Same error handling patterns
- **Response Handling:** Consistent response processing
- **Flags:** Standard verbose, silent, include, and user-agent flags

### Key Features
- **Authentication:** Support for Authorization header, SNYK_TOKEN, and OAuth precedence
- **Content Types:** Appropriate content types (application/vnd.api+json)
- **URL Building:** Proper URL construction with query parameters
- **Request Bodies:** JSON:API compliant request body formatting
- **Error Handling:** Comprehensive error handling for network and API errors
- **Verbose Output:** Optional verbose output for debugging

## Registration Required

To make these commands available, the following lines need to be added to `main.go` in the `init()` function:

```go
// Organization settings
rootCmd.AddCommand(cmd.GetIacSettingsForOrgCmd)
rootCmd.AddCommand(cmd.UpdateIacSettingsForOrgCmd)
rootCmd.AddCommand(cmd.GetSastSettingsCmd)
rootCmd.AddCommand(cmd.UpdateOrgSastSettingsCmd)
```

## API Documentation References

The implementation is based on the official Snyk API documentation:
- [getIacSettingsForOrg](https://oapis.org/summary/https%3A%2F%2Fapi.snyk.io%2Frest%2Fopenapi%2F2024-10-15/getIacSettingsForOrg)
- [updateIacSettingsForOrg](https://oapis.org/summary/https%3A%2F%2Fapi.snyk.io%2Frest%2Fopenapi%2F2024-10-15/updateIacSettingsForOrg)
- [getSastSettings](https://oapis.org/summary/https%3A%2F%2Fapi.snyk.io%2Frest%2Fopenapi%2F2024-10-15/getSastSettings)
- [updateOrgSastSettings](https://oapis.org/summary/https%3A%2F%2Fapi.snyk.io%2Frest%2Fopenapi%2F2024-10-15/updateOrgSastSettings)

## Testing

The commands can be tested once registered in main.go. Example usage:

```bash
# Get IAC settings
snyk-api-cli get-iac-settings-for-org 12345678-1234-1234-1234-123456789012

# Update IAC settings
snyk-api-cli update-iac-settings-for-org 12345678-1234-1234-1234-123456789012 --custom-rules-enabled=true

# Get SAST settings
snyk-api-cli get-sast-settings 12345678-1234-1234-1234-123456789012

# Update SAST settings
snyk-api-cli update-org-sast-settings 12345678-1234-1234-1234-123456789012 --sast-enabled=true
```

All commands support the standard flags (--verbose, --silent, --include, --user-agent) for debugging and customization.