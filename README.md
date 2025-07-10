# Snyk API CLI

A command-line interface for exploring the Snyk API with curl-like functionality and automatic authentication.

## Features

- **Curl-like HTTP requests** with familiar flags (`-X`, `-H`, `-d`, `-v`, etc.)
- **Automatic version parameter** addition for REST endpoints
- **Multiple authentication methods** with smart precedence handling:
  - Manual Authorization headers (highest precedence)
  - `SNYK_TOKEN` environment variable
  - OAuth tokens from Snyk CLI (lowest precedence)
- **Automatic token refresh** for OAuth tokens
- **Configurable endpoints** and API versions
- **Comprehensive error handling** and verbose output

## Installation

### Build from Source

```bash
git clone <repository-url>
cd snyk-api-cli
go build -o snyk-api-cli
```

### Prerequisites

- Go 1.19 or later
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

### 2. SNYK_TOKEN Environment Variable

```bash
export SNYK_TOKEN="your_snyk_token_here"
snyk-api-cli curl /rest/orgs
```

### 3. OAuth via Snyk CLI (Lowest Precedence)

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

### Basic Commands

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

### Command-Line Flags

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

### Examples

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

## Contributing

1. Follow the existing code style
2. Write tests for new functionality
3. Update documentation as needed
4. Test authentication flows thoroughly

## License

[License information] 