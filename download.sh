#!/usr/bin/env bash

# Simple BYOD Tool Downloader
# Compatible with bash and zsh on macOS/Linux
# Usage: curl -sSL https://raw.githubusercontent.com/saas-group/byod-tool/main/download.sh | sh

set -e  # Exit on any error

echo "📥 Downloading BYOD Security Checker..."

# Check if curl is available
if ! command -v curl >/dev/null 2>&1; then
    echo "❌ Error: curl is required but not installed."
    exit 1
fi

# Check if Python 3 is available
if ! command -v python3 >/dev/null 2>&1; then
    echo "❌ Error: Python 3 is required but not installed."
    echo "Please install Python 3 and try again."
    exit 1
fi

# Create local directory
BYOD_DIR="$HOME/byod-tool"
echo "📁 Creating directory: $BYOD_DIR"
mkdir -p "$BYOD_DIR"
cd "$BYOD_DIR"

# Download files with error checking
echo "⬇️  Downloading main script..."
if ! curl -sSL "https://raw.githubusercontent.com/saas-group/byod-tool/main/byod_security_check.py" -o byod_security_check.py; then
    echo "❌ Error: Failed to download byod_security_check.py"
    echo "Please check that the file exists at: https://github.com/saas-group/byod-tool"
    exit 1
fi

echo "⬇️  Downloading HTML file..."
if ! curl -sSL "https://raw.githubusercontent.com/saas-group/byod-tool/main/google_signin.html" -o google_signin.html; then
    echo "❌ Error: Failed to download google_signin.html"
    echo "Please check that the file exists at: https://github.com/saas-group/byod-tool"
    exit 1
fi

# Make executable
chmod +x byod_security_check.py

echo ""
echo "✅ BYOD Security Checker installed successfully!"
echo "📍 Location: $BYOD_DIR"
echo ""
echo "🚀 To run the security check:"
echo "   cd ~/byod-tool"
echo "   python3 byod_security_check.py"
echo ""
echo "Or run this one-liner:"
echo "   cd ~/byod-tool && python3 byod_security_check.py"