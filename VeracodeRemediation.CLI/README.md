# Veracode Automated Security Remediation System

## Overview

This system automatically fetches vulnerabilities from Veracode, classifies them, and applies safe, deterministic fixes. It generates patch files and comprehensive remediation reports.

## Project Structure

```
src/
├── VeracodeRemediation.Core/
│   ├── Models/              # Domain models (Vulnerability, FixResult, etc.)
│   └── Interfaces/          # Core interfaces
│
├── VeracodeRemediation.Application/
│   ├── Classifiers/         # Vulnerability classification logic
│   ├── Fixers/              # Automated fix implementations
│   ├── Generators/          # Patch and report generators
│   └── RemediationService.cs # Main orchestration
│
├── VeracodeRemediation.Infrastructure/
│   └── Veracode/            # Veracode API client with HMAC auth
│
└── VeracodeRemediation.CLI/
    ├── Program.cs           # Entry point
    └── appsettings.json     # Configuration
```

## Key Components

### 1. Veracode API Client
- HMAC-SHA-256 authentication
- Fetches SAST and SCA findings
- Handles application lookup

### 2. Vulnerability Classifier
- Determines which vulnerabilities can be auto-fixed
- Filters by severity, CWE, and complexity
- Provides classification reasoning

### 3. Fix Engine
- Routes vulnerabilities to appropriate fixers
- Supports multiple fix types:
  - SQL Injection → Parameterized queries
  - Hardcoded secrets → Environment variables
  - Insecure hashing → SHA-256
  - Dependency updates → Version upgrades

### 4. Output Generators
- **Patch Generator**: Creates unified diff patch files
- **Report Generator**: Creates markdown remediation reports

## Usage

```bash
# Set credentials
export VERACODE_API_ID="your-api-id"
export VERACODE_API_KEY="your-api-key"

# Run remediation
dotnet run --project src/VeracodeRemediation.CLI "YourApplicationName"
```

## Output

- `veracode-remediation.patch` - Git patch file with all fixes
- `veracode-remediation-report.md` - Detailed markdown report

## Security Considerations

- ⚠️ Always review patches before applying
- ⚠️ Test thoroughly after applying fixes
- ⚠️ Re-scan with Veracode to verify remediation
- ⚠️ Address manual review items separately

