# Veracode Automated Security Remediation

An automated system that connects to the Veracode API, fetches vulnerability data (SAST and SCA), and applies safe, deterministic fixes automatically.

## Features

- 🔐 **Veracode API Integration**: Connects to Veracode using HMAC authentication
- 🔍 **Vulnerability Detection**: Fetches both SAST and SCA findings
- 🤖 **Automated Fixes**: Applies safe, deterministic fixes for common vulnerabilities
- 📝 **Patch Generation**: Generates Git-compatible patch files
- 📊 **Remediation Reports**: Creates detailed markdown reports with fix summaries

## Supported Auto-Fixes

The system can automatically fix the following types of vulnerabilities:

- **SQL Injection (CWE-89)**: Replaces string concatenation with parameterized queries
- **Command Injection (CWE-78)**: Adds input validation
- **Hardcoded Secrets (CWE-798, CWE-259)**: Moves secrets to environment variables
- **Weak Cryptography (CWE-327, CWE-328)**: Upgrades MD5/SHA1 to SHA-256
- **XSS (CWE-79)**: Adds HTML encoding to output
- **File Upload (CWE-434)**: Adds file type validation
- **Unsafe Deserialization (CWE-502)**: Marks BinaryFormatter usage for replacement
- **URL Redirection (CWE-601)**: Adds URL whitelist validation
- **SCA Dependencies**: Provides upgrade recommendations

## Installation

### Prerequisites

- .NET 8.0 SDK
- Veracode API credentials (API ID and API Key)

### Build

```bash
dotnet build VeracodeRemediation.sln
```

## Configuration

Create an `appsettings.json` file in the CLI project or use environment variables:

```json
{
  "Veracode": {
    "ApiId": "your-api-id",
    "ApiKey": "your-api-key"
  }
}
```

Or set environment variables:
- `Veracode__ApiId`
- `Veracode__ApiKey`

## Usage

### Basic Usage

```bash
dotnet run --project src/VeracodeRemediation.CLI \
  --api-id YOUR_API_ID \
  --api-key YOUR_API_KEY \
  --app-guid YOUR_APP_GUID
```

### Advanced Options

```bash
dotnet run --project src/VeracodeRemediation.CLI \
  --api-id YOUR_API_ID \
  --api-key YOUR_API_KEY \
  --app-guid YOUR_APP_GUID \
  --scan-id SPECIFIC_SCAN_ID \
  --output-dir ./reports \
  --include-sast true \
  --include-sca true \
  --apply-fixes false
```

### Options

- `--api-id`: Veracode API ID (required)
- `--api-key`: Veracode API Key (required)
- `--app-guid`: Veracode Application GUID (required)
- `--scan-id`: Specific scan ID (optional, uses latest if not provided)
- `--output-dir`: Output directory for patches and reports (default: `./reports`)
- `--include-sast`: Include SAST findings (default: `true`)
- `--include-sca`: Include SCA findings (default: `true`)
- `--apply-fixes`: Apply fixes directly to files (default: `false` - generates patch only)

## Output

The tool generates two types of outputs:

### 1. Patch File (`.patch`)

A Git-compatible patch file containing all automated fixes. Apply it using:

```bash
git apply veracode-remediation-YYYYMMDD-HHMMSS.patch
```

### 2. Remediation Report (`.md`)

A detailed markdown report containing:
- Executive summary
- Severity breakdown
- Auto-fixed vulnerabilities
- Vulnerabilities requiring manual review
- SCA dependency update recommendations
- Veracode links

## Architecture

The solution follows Clean Architecture principles:

```
src/
├── VeracodeRemediation.Core/          # Domain entities and interfaces
├── VeracodeRemediation.Application/   # Business logic and services
├── VeracodeRemediation.Infrastructure/# External integrations (Veracode API)
└── VeracodeRemediation.CLI/           # Command-line interface
```

## Security Considerations

- **Only Low/Medium severity** vulnerabilities are auto-fixed
- **High/Critical** vulnerabilities require manual review
- **Authentication/Authorization** logic is never auto-fixed
- **Business rules** are never modified
- All fixes include comments referencing Veracode flaw IDs

## Limitations

- Fixes are pattern-based and may not cover all edge cases
- Some fixes require manual verification
- Complex vulnerabilities may need architectural changes
- SCA dependency updates require manual package manager updates

## Contributing

When adding new fix strategies:

1. Add the CWE to `AutoFixableCwes` in `VulnerabilityClassifier`
2. Implement the fix logic in `FixEngine`
3. Add appropriate tests
4. Update documentation

## License

This project is provided as-is for security remediation purposes.

## Disclaimer

This tool applies automated fixes based on patterns and heuristics. Always:
- Review all generated patches before applying
- Test fixes in a development environment
- Verify that fixes don't introduce breaking changes
- Consult security experts for high-severity vulnerabilities

