# BYOD Security Checker with Google Sign-In

A comprehensive security compliance checker for BYOD (Bring Your Own Device) policies that includes secure Google Sign-In authentication.

## Quick Install & Run

### macOS & Linux

**For macOS users: Install bash first (if needed)**
```bash
# Install bash via Homebrew (if not already installed)
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
brew install bash
```

**Simple install and run:**
```bash
curl -sSL https://raw.githubusercontent.com/saas-group/byod-tool/main/download.sh | bash && cd ~/byod-tool && python3 byod_security_check.py
```

### Windows

**Option 1: PowerShell (Recommended)**
```powershell
iwr -useb https://raw.githubusercontent.com/saas-group/byod-tool/main/install.ps1 | iex
```

**Option 2: Download and run batch file**
1. Download: [install.bat](https://raw.githubusercontent.com/saas-group/byod-tool/main/install.bat)
2. Right-click and "Run as administrator" (or double-click)

**Option 3: Manual PowerShell**
```powershell
# Create directory and download files
New-Item -ItemType Directory -Path "$env:USERPROFILE\byod-tool" -Force
Set-Location "$env:USERPROFILE\byod-tool"
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/saas-group/byod-tool/main/byod_security_check.py" -OutFile "byod_security_check.py"
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/saas-group/byod-tool/main/google_signin.html" -OutFile "google_signin.html"

# Run the tool
python byod_security_check.py
```

## Features

- **Secure Authentication**: Google Sign-In integration with no API keys stored in code
- **Multi-platform Support**: Works on macOS, Windows, and Linux
- **Comprehensive Security Checks**:
  - OS Firewall status
  - Disk encryption (FileVault/BitLocker/LUKS)
  - Auto-lock timeout configuration
  - Guest account status
- **Automated Reporting**: Sends results to n8n webhook for centralized monitoring

## Authentication

### Google Sign-In (Required)
- **Secure**: Uses OAuth 2.0 with no secrets in code
- **User-friendly**: Web-based authentication flow
- **Auditable**: Provides proper authentication logs

## Security Features

### No Secrets in Code
- Google Client ID is public and safe to store in code
- No API keys, passwords, or tokens in the repository
- All sensitive data handled through secure OAuth flow
- No admin privileges are needed for the tool to run locally

### Domain Validation
Validates against approved saas.group domains:

### Secure Communication
- HTTPS-only communication with Google APIs
- Local HTTP server only for OAuth callback
- No sensitive data transmitted over HTTP

## Troubleshooting

### Google Sign-In Issues
1. **Port conflicts**: The script tries ports 8080-8090 automatically
2. **Browser issues**: Manually open the displayed URL

### Common Issues
- **Permission denied**: The tool now runs without requiring sudo passwords
- **Network issues**: Check firewall settings for outbound HTTPS
- **Browser blocked**: Manually copy/paste the authentication URL

## Development

### Dependencies
- Python 3.6+
- Standard library only (no external dependencies for core functionality)
- `requests` for n8n webhook integration

## Privacy & Security

- **No data collection**: Only validates domain membership
- **Minimal permissions**: Only reads necessary system information
- **Secure authentication**: Uses industry-standard OAuth 2.0
- **Local processing**: All security checks run locally

## License

This tool is for internal use by saas.group and its portfolio companies.

## Support

If you need support running this tool, please reach the Central IT Team on it-support@saas.group or #it-helpdesk in Slack
