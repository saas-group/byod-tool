# BYOD Security Checker with Google Sign-In

A comprehensive security compliance checker for BYOD (Bring Your Own Device) policies that now includes secure Google Sign-In authentication.

## Features

- **Secure Authentication**: Google Sign-In integration with no API keys stored in code
- **Multi-platform Support**: Works on macOS, Windows, and Linux
- **Comprehensive Security Checks**:
  - OS Firewall status
  - Disk encryption (FileVault/BitLocker/LUKS)
  - Auto-lock timeout configuration
  - Guest account status
- **Automated Reporting**: Sends results to n8n webhook for centralized monitoring

## Authentication Methods

### 1. Google Sign-In (Recommended)
- **Secure**: Uses OAuth 2.0 with no secrets in code
- **User-friendly**: Web-based authentication flow
- **Auditable**: Provides proper authentication logs

### 2. Email Validation (Fallback)
- **Simple**: Direct email input with domain validation
- **Fallback**: Available when Google Sign-In isn't set up

## Setup Instructions

### Quick Start (Email Validation)
```bash
python3 byod_security_check.py --auth-method email
```

### Google Sign-In Setup (Pre-configured)

The Google Client ID is already configured and ready to use!

1. **Run with Google Sign-In**:
   ```bash
   python3 byod_security_check.py
   ```

2. **Authentication Flow**:
   - Browser opens automatically
   - Click "Sign in with Google" 
   - Sign in with your company email
   - Return to terminal to continue

**Note**: The Google Client ID (`405677217769-lh67b56pi6p94gmuoh1q4hrhlkl7ds9f.apps.googleusercontent.com`) is pre-configured for `http://localhost:8080` and `http://localhost:8081`.

## Usage Examples

### Basic Usage
```bash
# Default: Google Sign-In authentication
python3 byod_security_check.py

# Use email validation fallback
python3 byod_security_check.py --auth-method email

# Disable n8n reporting
python3 byod_security_check.py --no-n8n
```

### Advanced Configuration
```bash
# Custom n8n webhook with authentication
python3 byod_security_check.py \
  --n8n-webhook "https://your-n8n.com/webhook/id" \
  --n8n-username "admin" \
  --n8n-password "password"

# Use environment variables for credentials
export N8N_WEBHOOK_URL="https://your-n8n.com/webhook/id"
export N8N_USERNAME="admin"
export N8N_PASSWORD="password"
python3 byod_security_check.py
```

## Security Features

### No Secrets in Code
- Google Client ID is public and safe to store in code
- No API keys, passwords, or tokens in the repository
- All sensitive data handled through secure OAuth flow

### Domain Validation
Validates against approved company domains:
- saas.group (main company)
- Portfolio company domains (addsearch.com, beekast.com, etc.)
- Full list of 50+ approved domains

### Secure Communication
- HTTPS-only communication with Google APIs
- Local HTTP server only for OAuth callback
- No sensitive data transmitted over HTTP

## Troubleshooting

### Google Sign-In Issues
1. **Client ID not configured**: Edit the HTML file or use fallback method
2. **Port conflicts**: The script tries ports 8080-8090 automatically
3. **Browser issues**: Manually open the displayed URL

### Fallback Authentication
```bash
# Skip Google Sign-In entirely
python3 byod_security_check.py --auth-method email
```

### Common Issues
- **Permission denied**: Run with appropriate permissions for system checks
- **Network issues**: Check firewall settings for outbound HTTPS
- **Browser blocked**: Manually copy/paste the authentication URL

## Development

### Dependencies
- Python 3.6+
- Standard library only (no external dependencies for core functionality)
- `requests` for n8n webhook integration

### File Structure
```
byod-tool/
├── byod_security_check.py    # Main security checker
├── google_signin.html        # Google Sign-In interface
└── README.md                # This file
```

## Privacy & Security

- **No data collection**: Only validates domain membership
- **Minimal permissions**: Only reads necessary system information
- **Secure authentication**: Uses industry-standard OAuth 2.0
- **Local processing**: All security checks run locally

## License

This tool is for internal use by saas.group and its portfolio companies.