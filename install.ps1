# BYOD Security Checker Installer for Windows
# Usage: 
#   PowerShell: iwr -useb https://raw.githubusercontent.com/saas-group/byod-tool/main/install.ps1 | iex
#   Or: Invoke-WebRequest -Uri "https://raw.githubusercontent.com/saas-group/byod-tool/main/install.ps1" -UseBasicParsing | Invoke-Expression

Write-Host "📥 Downloading BYOD Security Checker for Windows..." -ForegroundColor Cyan

# Check if Python 3 is installed
try {
    $pythonVersion = python --version 2>$null
    if ($LASTEXITCODE -ne 0) {
        throw "Python not found"
    }
    Write-Host "🐍 Found: $pythonVersion" -ForegroundColor Green
} catch {
    Write-Host "❌ Error: Python 3 is required but not installed." -ForegroundColor Red
    Write-Host "Please install Python 3 from https://python.org and try again." -ForegroundColor Yellow
    Write-Host "Make sure to check 'Add Python to PATH' during installation." -ForegroundColor Yellow
    exit 1
}

# Create directory
$byodDir = "$env:USERPROFILE\byod-tool"
Write-Host "📁 Creating directory: $byodDir" -ForegroundColor Yellow

if (!(Test-Path $byodDir)) {
    New-Item -ItemType Directory -Path $byodDir -Force | Out-Null
}

Set-Location $byodDir

# Download files
Write-Host "⬇️  Downloading main script..." -ForegroundColor Yellow
try {
    Invoke-WebRequest -Uri "https://raw.githubusercontent.com/saas-group/byod-tool/main/byod_security_check.py" -OutFile "byod_security_check.py" -UseBasicParsing
    Write-Host "✅ Downloaded byod_security_check.py" -ForegroundColor Green
} catch {
    Write-Host "❌ Error: Failed to download byod_security_check.py" -ForegroundColor Red
    Write-Host "Please check that the file exists at: https://github.com/saas-group/byod-tool" -ForegroundColor Yellow
    exit 1
}

Write-Host "⬇️  Downloading HTML file..." -ForegroundColor Yellow
try {
    Invoke-WebRequest -Uri "https://raw.githubusercontent.com/saas-group/byod-tool/main/google_signin.html" -OutFile "google_signin.html" -UseBasicParsing
    Write-Host "✅ Downloaded google_signin.html" -ForegroundColor Green
} catch {
    Write-Host "❌ Error: Failed to download google_signin.html" -ForegroundColor Red
    Write-Host "Please check that the file exists at: https://github.com/saas-group/byod-tool" -ForegroundColor Yellow
    exit 1
}

Write-Host ""
Write-Host "✅ BYOD Security Checker installed successfully!" -ForegroundColor Green
Write-Host "📍 Location: $byodDir" -ForegroundColor Cyan
Write-Host ""
Write-Host "🚀 To run the security check:" -ForegroundColor Cyan
Write-Host "   cd `"$byodDir`"" -ForegroundColor White
Write-Host "   python byod_security_check.py" -ForegroundColor White
Write-Host ""
Write-Host "Or run this one-liner:" -ForegroundColor Cyan
Write-Host "   cd `"$byodDir`"; python byod_security_check.py" -ForegroundColor White