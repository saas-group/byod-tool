@echo off
REM BYOD Security Checker Installer for Windows (Batch)
REM Usage: Download and run this batch file

echo 📥 Downloading BYOD Security Checker for Windows...

REM Check if Python is installed
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo ❌ Error: Python 3 is required but not installed.
    echo Please install Python 3 from https://python.org and try again.
    echo Make sure to check 'Add Python to PATH' during installation.
    pause
    exit /b 1
)

REM Get Python version
for /f "tokens=*" %%i in ('python --version 2^>^&1') do set PYTHON_VERSION=%%i
echo 🐍 Found: %PYTHON_VERSION%

REM Create directory
set BYOD_DIR=%USERPROFILE%\byod-tool
echo 📁 Creating directory: %BYOD_DIR%

if not exist "%BYOD_DIR%" (
    mkdir "%BYOD_DIR%"
)

cd /d "%BYOD_DIR%"

REM Check if curl is available (Windows 10 1803+ has curl built-in)
curl --version >nul 2>&1
if %errorlevel% equ 0 (
    echo ⬇️  Downloading files using curl...
    curl -sSL "https://raw.githubusercontent.com/saas-group/byod-tool/main/byod_security_check.py" -o byod_security_check.py
    if %errorlevel% neq 0 (
        echo ❌ Error: Failed to download byod_security_check.py
        pause
        exit /b 1
    )
    
    curl -sSL "https://raw.githubusercontent.com/saas-group/byod-tool/main/google_signin.html" -o google_signin.html
    if %errorlevel% neq 0 (
        echo ❌ Error: Failed to download google_signin.html
        pause
        exit /b 1
    )
) else (
    echo ⬇️  Downloading files using PowerShell...
    powershell -Command "Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/saas-group/byod-tool/main/byod_security_check.py' -OutFile 'byod_security_check.py' -UseBasicParsing"
    if %errorlevel% neq 0 (
        echo ❌ Error: Failed to download byod_security_check.py
        pause
        exit /b 1
    )
    
    powershell -Command "Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/saas-group/byod-tool/main/google_signin.html' -OutFile 'google_signin.html' -UseBasicParsing"
    if %errorlevel% neq 0 (
        echo ❌ Error: Failed to download google_signin.html
        pause
        exit /b 1
    )
)

echo.
echo ✅ BYOD Security Checker installed successfully!
echo 📍 Location: %BYOD_DIR%
echo.
echo 🚀 To run the security check:
echo    cd "%BYOD_DIR%"
echo    python byod_security_check.py
echo.
echo Press any key to run the security check now...
pause >nul
python byod_security_check.py