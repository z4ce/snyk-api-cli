# Snyk API CLI

A comprehensive command-line interface for the Snyk API with **196 dedicated subcommands** covering all REST API endpoints, plus curl-like functionality for custom requests.

## Features

### 🚀 **Complete API Coverage**
- **196 dedicated subcommands** for all Snyk REST API endpoints (2024-10-15)
- **Organized by category**: Custom base images, Groups, Organizations, Self/User, Tenants, and more
- **Consistent command structure** with intuitive naming and comprehensive help
- **Full parameter support** for all query parameters, path parameters, and request bodies

### 🔧 **Dual Interface**
- **Dedicated subcommands** for streamlined API operations
- **Curl-like HTTP requests** with familiar flags (`-X`, `-H`, `-d`, `-v`, etc.) for custom requests
- **Automatic version parameter** addition for REST endpoints
- **Configurable endpoints** and API versions

### 🔐 **Smart Authentication**
- **Multiple authentication methods** with smart precedence handling:
  - Manual Authorization headers (highest precedence)
  - OAuth2 client credentials (`--client-id` and `--client-secret`)
  - `SNYK_TOKEN` environment variable
  - OAuth tokens from Snyk CLI (lowest precedence)
- **OAuth2 client credentials grant** for service account authentication
- **Automatic token refresh** for OAuth tokens
- **Token caching** to minimize API calls
- **Consistent authentication** across all commands

### 📋 **Enhanced User Experience**
- **Comprehensive help** with examples for every command
- **Consistent flags** across all commands (`--verbose`, `--silent`, `--include`, `--user-agent`)
- **Robust error handling** and verbose output
- **Pagination support** for list operations
- **JSON:API compliant** request formatting

## Installation

### Download Pre-built Binaries

Download the latest release for your platform from the [releases page](https://github.com/z4ce/snyk-api-cli/releases).

#### macOS / Linux
```bash
# Download and extract (replace VERSION, OS, and ARCH with your values)
curl -LO https://github.com/z4ce/snyk-api-cli/releases/download/VERSION/snyk-api-cli_VERSION_OS_ARCH.tar.gz
tar -xzf snyk-api-cli_VERSION_OS_ARCH.tar.gz
sudo mv snyk-api-cli /usr/local/bin/

# Verify installation
snyk-api-cli version
```

#### Windows
Download the `.zip` file from the releases page and extract `snyk-api-cli.exe` to a directory in your PATH.

### Using Go Install

```bash
go install github.com/z4ce/snyk-api-cli@latest
```

### Build from Source

```bash
git clone https://github.com/z4ce/snyk-api-cli
cd snyk-api-cli
go build -o snyk-api-cli
```

### Prerequisites

- Go 1.24 or later (for building from source)
- (Optional) Snyk CLI for OAuth authentication

## Configuration

The CLI supports configuration via command-line flags or environment variables:

### Global Options

```bash
# Set API endpoint (default: api.snyk.io)
snyk-api-cli --endpoint api.snyk.io curl /rest/orgs

# Set API version (default: 2024-10-15)
snyk-api-cli --version 2023-05-01 curl /rest/orgs

# Get help
snyk-api-cli --help
```

## Authentication

The CLI supports multiple authentication methods with the following precedence order:

### 1. Manual Authorization Headers (Highest Precedence)

```bash
snyk-api-cli curl -H "Authorization: Bearer your_token_here" /rest/orgs
```

### 2. OAuth2 Client Credentials (Service Accounts)

Use OAuth2 client credentials grant flow for service account authentication. This is ideal for CI/CD pipelines and automated scripts:

```bash
# Using command-line flags
snyk-api-cli --client-id "your-client-id" --client-secret "your-client-secret" curl /rest/orgs

# With any subcommand
snyk-api-cli --client-id "your-client-id" --client-secret "your-client-secret" list-orgs
```

The CLI automatically:
- Obtains an access token using the OAuth2 client credentials grant
- Caches the token and reuses it until it expires
- Refreshes the token automatically when needed (with 5-minute buffer)
- Uses the correct token endpoint based on your `--endpoint` setting

**Note**: Both `--client-id` and `--client-secret` must be provided together for OAuth2 client credentials authentication.

### 3. SNYK_TOKEN Environment Variable

```bash
export SNYK_TOKEN="your_snyk_token_here"
snyk-api-cli curl /rest/orgs
```

### 4. OAuth via Snyk CLI (Lowest Precedence)

If you have the Snyk CLI installed and authenticated, the tool will automatically use your OAuth tokens:

```bash
# First, authenticate with Snyk CLI
snyk auth

# Then use the API CLI without additional authentication
snyk-api-cli curl /rest/orgs
```

The CLI automatically:
- Checks if OAuth tokens are expired (with 5-minute buffer)
- Attempts to refresh expired tokens
- Falls back gracefully if Snyk CLI is unavailable

## Usage

### 🎯 **Dedicated Subcommands** (Recommended)

The CLI provides 196 dedicated subcommands organized by category for streamlined API operations:

#### **Organizations**
```bash
# List organizations
snyk-api-cli list-orgs

# Get organization details
snyk-api-cli get-org 12345678-1234-1234-1234-123456789012

# List organization projects
snyk-api-cli list-org-projects 12345678-1234-1234-1234-123456789012

# Get organization issues
snyk-api-cli list-org-issues 12345678-1234-1234-1234-123456789012 --created-after 2024-01-01

# Create a collection
snyk-api-cli create-collection 12345678-1234-1234-1234-123456789012 --name "My Collection"

# Manage organization memberships
snyk-api-cli create-org-membership 12345678-1234-1234-1234-123456789012 --user-id user-id --role-id role-id
```

#### **Groups**
```bash
# List groups
snyk-api-cli list-groups

# Get group details
snyk-api-cli get-group 12345678-1234-1234-1234-123456789012

# List group assets
snyk-api-cli list-assets 12345678-1234-1234-1234-123456789012 --limit 10

# Create group export
snyk-api-cli create-group-export 12345678-1234-1234-1234-123456789012 --dataset issues --format csv
```

#### **Self/User Operations**
```bash
# Get your user details
snyk-api-cli get-self

# List your installed apps
snyk-api-cli get-user-installed-apps

# Get access requests
snyk-api-cli get-access-requests --limit 5
```

#### **Tenants**
```bash
# List tenants
snyk-api-cli list-tenants

# Get tenant details
snyk-api-cli get-tenant 12345678-1234-1234-1234-123456789012

# List tenant roles
snyk-api-cli list-tenant-roles 12345678-1234-1234-1234-123456789012

# Create custom tenant role
snyk-api-cli create-tenant-role 12345678-1234-1234-1234-123456789012 --data '{"data":{"type":"tenant_role","attributes":{"name":"Custom Role","permissions":["tenant.read"]}}}'
```

#### **Custom Base Images**
```bash
# List custom base images
snyk-api-cli get-custom-base-images --org-id 12345678-1234-1234-1234-123456789012

# Create custom base image
snyk-api-cli create-custom-base-image --project-id project-id --tag latest
```

#### **Getting Help**
```bash
# List all available commands
snyk-api-cli --help

# Get help for a specific command
snyk-api-cli list-orgs --help

# All commands support standard flags
snyk-api-cli get-org 12345678-1234-1234-1234-123456789012 --verbose --include
```

### 🔧 **Curl-like Interface** (For Custom Requests)

For advanced users or custom API calls, the original curl interface is still available:

#### GET Request to REST Endpoint

```bash
# Automatic version parameter added for /rest/* paths
snyk-api-cli curl /rest/orgs
# → GET https://api.snyk.io/rest/orgs?version=2024-10-15
```

#### POST Request with Data

```bash
snyk-api-cli curl -X POST -d '{"name":"test-project"}' /rest/orgs/your-org-id/projects
```

#### Custom Headers

```bash
snyk-api-cli curl -H "Content-Type: application/json" -H "Accept: application/json" /rest/orgs
```

#### Non-REST Endpoints

```bash
# No version parameter added for non-REST paths
snyk-api-cli curl /v1/user
# → GET https://api.snyk.io/v1/user
```

## 📚 **Command Categories**

### **Custom Base Images (5 commands)**
- `get-custom-base-images` - List custom base images
- `create-custom-base-image` - Create custom base image
- `get-custom-base-image` - Get custom base image details
- `update-custom-base-image` - Update custom base image
- `delete-custom-base-image` - Delete custom base image

### **Groups (45+ commands)**
- **Core**: `list-groups`, `get-group`
- **Assets**: `list-assets`, `get-asset`, `list-related-assets`, `list-asset-projects`
- **Audit**: `list-group-audit-logs`
- **Exports**: `create-group-export`, `get-group-export`, `delete-group-export`
- **Issues**: `list-group-issues`, `get-group-issue-by-issue-id`
- **Memberships**: `list-group-memberships`, `create-group-membership`, `update-group-user-membership`, `delete-group-membership`
- **Organizations**: `list-orgs-in-group`, `get-org`, `update-org`
- **Service Accounts**: `get-many-group-service-account`, `create-group-service-account`, `update-group-service-account`, `delete-one-group-service-account`
- **Settings**: `get-iac-settings-for-group`, `update-iac-settings-for-group`
- **SSO**: `list-group-sso-connections`, `list-group-sso-connection-users`
- **Apps**: `get-app-installs-for-group`, `create-group-app-install`, `update-group-app-install-secret`

### **Organizations (80+ commands)**
- **Core**: `list-orgs`, `get-org`, `update-org`
- **Apps**: `get-apps`, `create-app`, `get-app-by-id`, `update-app`, `delete-app`, `manage-secrets`
- **Assets**: `list-assets-in-org`, `create-asset`, `get-asset-in-org`
- **Audit**: `list-org-audit-logs`
- **Cloud**: `list-environments`, `create-environment`, `update-environment`, `delete-environment`, `get-permissions`, `list-resources`, `list-scan`, `create-scan`, `get-scan`
- **Collections**: `get-collections`, `create-collection`, `get-collection`, `update-collection`, `delete-collection`, `get-projects-of-collection`, `update-collection-with-projects`, `delete-projects-collection`
- **Container Images**: `list-container-image`, `get-container-image`, `list-image-target-refs`
- **Exports**: `create-export`, `get-export`, `get-export-job-status`
- **Invitations**: `list-org-invitation`, `create-org-invitation`, `delete-org-invitation`
- **Issues**: `list-org-issues`, `get-org-issue`
- **Learn**: `list-org-assignments`, `create-org-assignments`, `update-org-assignments`, `delete-org-assignments`
- **Memberships**: `list-org-memberships`, `create-org-membership`, `update-org-membership`, `delete-org-membership`
- **Packages**: `list-issues-for-many-purls`, `fetch-issues-per-purl`
- **Policies**: `get-org-policies`, `create-org-policy`, `get-org-policy`, `update-org-policy`, `delete-org-policy`, `get-org-policy-events`
- **Projects**: `list-org-projects`, `get-org-project`, `update-org-project`, `delete-org-project`
- **SBOM**: `get-sbom`, `create-sbom-test-run`, `get-sbom-test-status`, `get-sbom-test-result`
- **Service Accounts**: `get-many-org-service-accounts`, `create-org-service-account`, `get-one-org-service-account`, `update-org-service-account`, `delete-service-account`, `update-org-service-account-secret`
- **Settings**: `get-iac-settings-for-org`, `update-iac-settings-for-org`, `get-sast-settings`, `update-org-sast-settings`
- **Slack**: `get-slack-default-notification-settings`, `create-slack-default-notification-settings`, `delete-slack-default-notification-settings`, `get-slack-project-notification-settings-collection`, `create-slack-project-notification-settings`, `update-slack-project-notification-settings`, `delete-slack-project-notification-settings`, `list-channels`, `get-channel-name-by-id`
- **Targets**: `get-orgs-targets`, `get-orgs-target`, `delete-orgs-target`
- **Users**: `get-user`

### **Self/User (8 commands)**
- `get-self` - Get your user details
- `get-access-requests` - Get access requests
- `get-user-installed-apps` - Get installed apps
- `get-app-installs-for-user` - Get app installations
- `delete-user-app-install-by-id` - Revoke app by install ID
- `revoke-user-installed-app` - Revoke app by app ID
- `get-user-app-sessions` - Get active OAuth sessions
- `revoke-user-app-session` - Revoke OAuth session

### **Tenants (41 commands)**
- **Core**: `list-tenants`, `get-tenant`, `update-tenant`
- **Learning**: `list-tenant-learning-programs`
- **Memberships**: `get-tenant-memberships`, `update-tenant-membership`, `delete-tenant-membership`
- **Roles**: `list-tenant-roles`, `create-tenant-role`, `get-tenant-role`, `update-tenant-role`, `delete-tenant-role`
- **Broker Operations**: 29 commands for comprehensive broker deployment and connection management

### **OpenAPI (2 commands)**
- `list-api-versions` - List available API versions
- `get-api-version` - Get specific API version details

### **Learn (1 command)**
- `list-learn-catalog` - List Snyk Learn resources

### **Curl Interface Flags**

#### HTTP Method
```bash
-X, --request string    HTTP method to use (default "GET")
```

#### Headers
```bash
-H, --header strings    HTTP headers to send (can be used multiple times)
```

#### Request Body
```bash
-d, --data string       Data to send in request body
```

#### Output Options
```bash
-v, --verbose          Make the operation more talkative
-s, --silent           Silent mode (no output)
-i, --include          Include HTTP response headers in output
```

#### User Agent
```bash
-A, --user-agent string    User agent string to send (default "snyk-api-cli/1.0")
```

### Legacy Curl Examples

#### List Organizations

```bash
snyk-api-cli curl /rest/orgs
```

#### Get Organization Details

```bash
snyk-api-cli curl /rest/orgs/your-org-id
```

#### List Projects with Verbose Output

```bash
snyk-api-cli curl -v /rest/orgs/your-org-id/projects
```

#### Create a Project

```bash
snyk-api-cli curl -X POST \
  -H "Content-Type: application/json" \
  -d '{"name":"my-project","origin":"cli"}' \
  /rest/orgs/your-org-id/projects
```

#### Get User Information (v1 API)

```bash
snyk-api-cli curl /v1/user
```

#### Custom API Version

```bash
snyk-api-cli --version 2023-05-01 curl /rest/orgs
```

#### Custom Endpoint

```bash
snyk-api-cli --endpoint api.eu.snyk.io curl /rest/orgs
```

### Authentication Examples

#### Using Manual Token

```bash
snyk-api-cli curl -H "Authorization: Bearer snyk_token_12345" /rest/orgs
```

#### Using Environment Variable

```bash
export SNYK_TOKEN="snyk_token_12345"
snyk-api-cli curl /rest/orgs
```

#### Mixing Authentication (Manual Takes Precedence)

```bash
export SNYK_TOKEN="env_token"
# Manual header overrides environment variable
snyk-api-cli curl -H "Authorization: Bearer manual_token" /rest/orgs
```

### Verbose Output

Use `-v` flag to see detailed request information:

```bash
snyk-api-cli curl -v /rest/orgs
```

Output includes:
- Request URL and method
- Authentication method being used
- Response status
- Timing information

### Error Handling

The CLI provides helpful error messages:

```bash
# Invalid header format
snyk-api-cli curl -H "InvalidHeader" /rest/orgs
# Error: invalid header format: InvalidHeader (expected 'Key: Value')

# Authentication failures
snyk-api-cli curl /rest/private-endpoint
# May show 401 Unauthorized with response details
```

## API Version Handling

The CLI automatically adds version parameters to REST API calls:

- **REST endpoints** (`/rest/*`): Automatic version parameter
- **Other endpoints** (`/v1/*`, `/v2/*`, etc.): No version parameter

You can override the default version globally:

```bash
snyk-api-cli --version 2023-05-01 curl /rest/orgs
```

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `SNYK_TOKEN` | Snyk API token for authentication | - |

## Exit Codes

- `0`: Success
- `1`: Error (network, authentication, invalid arguments, etc.)

## Troubleshooting

### OAuth Token Issues

If you're having issues with OAuth authentication:

1. Ensure Snyk CLI is installed and authenticated:
   ```bash
   snyk auth
   ```

2. Check if your token is expired:
   ```bash
   snyk-api-cli curl -v /rest/orgs
   ```

3. Try manual authentication:
   ```bash
   export SNYK_TOKEN="your_token"
   snyk-api-cli curl /rest/orgs
   ```

### Common Issues

**"snyk CLI not found"**: Install the Snyk CLI or use `SNYK_TOKEN` environment variable

**"401 Unauthorized"**: Check your authentication token or permissions

**"Invalid header format"**: Ensure headers follow `Key: Value` format

**Network errors**: Check your internet connection and endpoint configuration

## Development

### Running Tests

```bash
go test ./cmd -v
```

### Building

```bash
go build -o snyk-api-cli
```

### Creating a Release

This project uses [GoReleaser](https://goreleaser.com/) for automated releases.

#### Test Release Locally

```bash
# Install GoReleaser
go install github.com/goreleaser/goreleaser@latest

# Test the release process without publishing
goreleaser release --snapshot --clean
```

#### Create a Release

Releases are automatically created when you push a version tag:

```bash
# Tag the release
git tag -a v1.0.0 -m "Release v1.0.0"

# Push the tag
git push origin v1.0.0
```

The GitHub Actions workflow will automatically:
1. Build binaries for Linux, macOS, and Windows
2. Create archives with checksums
3. Generate release notes from commits
4. Publish the release on GitHub

## Contributing

1. Follow the existing code style
2. Write tests for new functionality
3. Update documentation as needed
4. Test authentication flows thoroughly

## License

[License information] 