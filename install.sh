#!/bin/bash

# BYOD Tool Installer
# Usage: curl -sSL https://raw.githubusercontent.com/saasgroup/byod-tool/main/install.sh | bash

set -e

INSTALL_DIR="/usr/local/bin"
SHARE_DIR="/usr/local/share/byod-tool"
TOOL_NAME="byod-tool"
GITHUB_REPO="saasgroup/byod-tool"
VERSION="main"

echo "🔧 Installing BYOD Security Checker..."

# Check if running on macOS or Linux
if [[ "$OSTYPE" == "darwin"* ]]; then
    OS="macOS"
elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
    OS="Linux"
else
    echo "❌ Unsupported operating system: $OSTYPE"
    exit 1
fi

echo "📱 Detected OS: $OS"

# Check if Python 3 is installed
if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 is required but not installed."
    echo "Please install Python 3 and try again."
    exit 1
fi

echo "🐍 Python 3 found: $(python3 --version)"

# Create directories
echo "📁 Creating directories..."
sudo mkdir -p "$SHARE_DIR"

# Download files
echo "⬇️  Downloading BYOD tool..."
sudo curl -sSL "https://raw.githubusercontent.com/$GITHUB_REPO/$VERSION/byod_security_check.py" -o "$INSTALL_DIR/$TOOL_NAME"
sudo curl -sSL "https://raw.githubusercontent.com/$GITHUB_REPO/$VERSION/google_signin.html" -o "$SHARE_DIR/google_signin.html"

# Make executable
sudo chmod +x "$INSTALL_DIR/$TOOL_NAME"

# Update HTML file path in the script
sudo sed -i.bak 's|html_file = "google_signin.html"|html_file = "'$SHARE_DIR'/google_signin.html"|g' "$INSTALL_DIR/$TOOL_NAME"
sudo rm "$INSTALL_DIR/$TOOL_NAME.bak"

echo "✅ BYOD tool installed successfully!"
echo ""
echo "Usage:"
echo "  $TOOL_NAME                 # Run security check"
echo "  $TOOL_NAME --help          # Show help"
echo ""
echo "🚀 You can now run: $TOOL_NAME"