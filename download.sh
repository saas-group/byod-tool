#!/bin/bash

# Simple BYOD Tool Downloader
# Usage: curl -sSL https://raw.githubusercontent.com/saas-group/byod-tool/main/download.sh | bash

echo "📥 Downloading BYOD Security Checker..."

# Create local directory
mkdir -p ~/byod-tool
cd ~/byod-tool

# Download files
curl -sSL "https://raw.githubusercontent.com/saas-group/byod-tool/main/byod_security_check.py" -o byod_security_check.py
curl -sSL "https://raw.githubusercontent.com/saas-group/byod-tool/main/google_signin.html" -o google_signin.html

# Make executable
chmod +x byod_security_check.py

echo "✅ BYOD tool downloaded to ~/byod-tool/"
echo ""
echo "Usage:"
echo "  cd ~/byod-tool"
echo "  python3 byod_security_check.py"
echo ""
echo "🚀 Run: cd ~/byod-tool && python3 byod_security_check.py"