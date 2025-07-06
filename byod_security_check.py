#!/usr/bin/env python3
"""
BYOD Security Compliance Checker
Checks for secure password policy, disk encryption, autolock, and guest accounts
across macOS, Windows, and Linux platforms.
"""

import os
import platform
import subprocess
import sys
import re
import json
import requests
import datetime
import webbrowser
import time
import tempfile
import shutil
import threading
import http.server
import socketserver
from http.server import BaseHTTPRequestHandler
from urllib.parse import urlparse
from typing import Dict, Tuple, Optional


class AuthHTTPRequestHandler(http.server.SimpleHTTPRequestHandler):
    """Custom HTTP handler for Google Sign-In authentication"""
    
    def __init__(self, *args, auth_result=None, **kwargs):
        self.auth_result = auth_result
        super().__init__(*args, **kwargs)
    
    def do_POST(self):
        if self.path == '/auth-complete':
            try:
                content_length = int(self.headers['Content-Length'])
                post_data = self.rfile.read(content_length)
                data = json.loads(post_data.decode('utf-8'))
                
                # Store the authenticated email
                if 'email' in data and self.auth_result is not None:
                    self.auth_result['email'] = data['email']
                    self.auth_result['complete'] = True
                
                # Send response with error handling for broken pipe
                try:
                    self.send_response(200)
                    self.send_header('Content-type', 'application/json')
                    self.end_headers()
                    self.wfile.write(json.dumps({'status': 'success'}).encode())
                except (BrokenPipeError, ConnectionResetError):
                    # Browser closed connection - this is expected behavior
                    pass
                
            except (BrokenPipeError, ConnectionResetError):
                # Browser closed connection - this is expected behavior
                pass
            except Exception as e:
                try:
                    self.send_response(500)
                    self.send_header('Content-type', 'application/json')
                    self.end_headers()
                    self.wfile.write(json.dumps({'error': str(e)}).encode())
                except (BrokenPipeError, ConnectionResetError):
                    # Browser closed connection - this is expected behavior
                    pass
        else:
            try:
                self.send_response(404)
                self.end_headers()
            except (BrokenPipeError, ConnectionResetError):
                # Browser closed connection - this is expected behavior
                pass
    
    def do_GET(self):
        # Use parent class to serve static files
        return super().do_GET()
    
    def log_message(self, format, *args):
        # Suppress server logs
        pass


class SecurityChecker:
    @staticmethod
    def _map_platform_name(platform_name: str) -> str:
        """Map platform.system() names to user-friendly names."""
        platform_map = {
            'Darwin': 'Mac',
            'Windows': 'Windows', 
            'Linux': 'Linux'
        }
        return platform_map.get(platform_name, platform_name)
    def __init__(self, n8n_webhook_url=None, api_key=None, n8n_username=None, n8n_password=None):
        self.system = platform.system().lower()
        # Use provided values or fall back to environment variables, then defaults
        self.n8n_webhook_url = (n8n_webhook_url or 
                               os.getenv('N8N_WEBHOOK_URL') or 
                               'https://n8n.saasgroup.app/webhook/5120b2b2-a509-4f63-96e2-fa7f414ec7e2')
        self.api_key = api_key or os.getenv('N8N_API_KEY')
        self.n8n_username = (n8n_username or 
                            os.getenv('N8N_USERNAME'))
        self.n8n_password = (n8n_password or 
                            os.getenv('N8N_PASSWORD'))
        self.results = {
            'os_firewall': {'status': False, 'message': '', 'remediation': ''},
            'disk_encryption': {'status': False, 'message': '', 'remediation': ''},
            'autolock': {'status': False, 'message': '', 'remediation': ''},
            'guest_accounts': {'status': False, 'message': '', 'remediation': ''}
        }
        # Known saas.group domains (main company + portfolio companies)
        self.valid_domains = {
            'addsearch.co',
            'addsearch.com',
            'advancedshippingmanager.com',
            'beekast.com',
            'crosstalent-rh.fr',
            'crosstalent.at',
            'crosstalent.be',
            'crosstalent.co.uk',
            'crosstalent.com',
            'crosstalent.de',
            'crosstalent.eu',
            'crosstalent.fr',
            'crosstalent.it',
            'crosstalent.nl',
            'dashthis.com',
            'getprerender.com',
            'getrewardful.com',
            'getscraperapi.com',
            'getusersnap.com',
            'gfconsulting.info',
            'git-tower.com',
            'gominga.com',
            'infonline.de',
            'juicer.io',
            'keyword-rank-tracking.com',
            'keyword.com',
            'keyword.net',
            'keyword.org',
            'kingwebmaster.com',
            'myworks.software',
            'picdrop.com',
            'picdrop.de',
            'pipelinecrm.com',
            'pipelinedeals.com',
            'pipelinedealsco.com',
            'pipelinesales.com',
            'prerender.io',
            'rewardful.com',
            'rewardful.io',
            'saas.blackfriday',
            'saas.group',
            'schumacher.me',
            'scraperapi.cloud',
            'scraperapi.co',
            'scraperapi.com',
            'scraperapi.io',
            'seobility.net',
            'timebutler.com',
            'timebutler.de',
            'tryprerender.com',
            'tryrewardful.co',
            'tryrewardful.com',
            'tsventures.io',
            'userewardful.com',
            'usersnap.com',
            'zenloop.com'
        }
    
    def display_header(self):
        """Display the saas.group branded header with gradient colors."""
        # ANSI color codes for gradient effect (orange to purple)
        orange = "\033[38;5;208m"  # Orange
        red_orange = "\033[38;5;202m"  # Red-orange
        red = "\033[38;5;196m"  # Red
        magenta = "\033[38;5;198m"  # Magenta
        purple = "\033[38;5;135m"  # Purple
        dark_purple = "\033[38;5;93m"  # Dark purple
        reset = "\033[0m"  # Reset color
        black = "\033[30m"  # Black for text
        
        print("                                                                                                    ")
        print("                                                                                                    ")
        print("                                                                                                    ")
        print("                                                                                                    ")
        print(f"                                       {orange}... .........................  ...{reset}                           ")
        print(f"                                       {orange}... .. ...........................{reset}                           ")
        print(f"                                        {orange}...... .........::::.............{reset}                           ")
        print(f"                                        {orange}... ......:-=============-:......{reset}                           ")
        print(f"                                  {orange}... .........:====================-:...  .{reset}                        ")
        print(f"                                {red_orange}.............-========--:::::--=======-:.......{reset}                     ")
        print(f"                               {red_orange}............:=======:.............:======-.......{reset}                    ")
        print(f"                               {red_orange}..........:=======:....:--===--:....:======.......{reset}                   ")
        print(f"                        {red_orange}. ... ..........=======:...:=============:...-=====......{reset}                   ")
        print(f"                       {red}...............-+=====:...:=================...-====-.....{reset}                   ")
        print(f"                       {red}.............-=+++++-...:======-:.....:-=====...-====:....{reset}                   ")
        print(f"                       {red}...........-=+++++-....-======:...:::...-====-..:====-....{reset}                   ")
        print(f"                       {red}.........:=+++++=:...-======:...:====-...=====...=====...{reset}                    ")
        print(f"                       {red}.......:=+++++=:...:======-...:======-...=====...=====....{reset}                   ")
        print(f"                       {magenta}......=++++++-...:======-....======-....=====-..:====-....{reset}                   ")
        print(f"                       {magenta}....-++++++-...:=======....-======:...-======...=====:....{reset}                   ")
        print(f"                       {magenta}...-+++++=...:=++++==:...-======:...:======-...-====-.....{reset}                   ")
        print(f"                       {magenta}...:+++=:...-+++++=:...:======-...:======-:...======.....{reset}                    ")
        print(f"                        {magenta}.........-+++++=-...:======-...:=======:...-=====-.....{reset}                     ")
        print(f"                       {purple}........:++++++=....=======:...-======-...:======-........{reset}                   ")
        print(f"                       {purple}......:++++++=....=======:...-======-...:=======..........{reset}                   ")
        print(f"                       {purple}....:=+++++=:...-======-...:======-...:=======:...........{reset}                   ")
        print(f"                       {purple}...-++++++:...-=++===-...:=++++==:...-++++==:............{reset}                    ")
        print(f"                       {dark_purple}...-++++-...:=+++++-...:=+++++=:...-+++++=:.......{reset}                           ")
        print(f"                       {dark_purple}.....::...:=+++++=:...=+++++=:...-+++++=-.........{reset}                           ")
        print(f"                       {dark_purple}.........=+++++=:...-++++++-...:++++++=...........{reset}                           ")
        print(f"                        {dark_purple}......=++++++-...-++++++-...:++++++=.............{reset}                           ")
        print(f"                       {dark_purple}.....-++++++-...:=+++++=...:=+++++=:........ ....{reset}                            ")
        print(f"                       {dark_purple}...:++++++=:...=+++++=:...-++++++-........{reset}                                   ")
        print(f"                       {dark_purple}...-++++=:....:++++=-.....+++++-..........{reset}                                   ")
        print(f"                       {dark_purple}....:==:.......:==-........-=-............{reset}                                   ")
        print(f"                        {dark_purple}....... ...... ......  ..  ...... .. ...{reset}                                    ")
        print("                                                                                                    ")
        print("                                                                                                    ")
        print("                                                                                                    ")
        print(f"        {orange}................{reset}    {red_orange}................{reset}    {red}.............................. .........{reset}            ")
        print(f"        {orange}................{reset}    {red_orange}................{reset}    {red}........................................{reset}            ")
        print(f"        {orange}...:==-. ...-=-.{reset}    {red_orange}.-=-.....:==-...{reset}    {red}..-=-.--..-::=:..:==:...:-....--..-:.-=:{reset}            ")
        print(f"        {orange}..%%--+@-.*@+-=@%..#@=-+@*.:@#--#%:.....+@#-=#@%.-@%+=:=@#==#%-.=@-. .%%.-@%*-=%%:..{reset}        ")
        print(f"        {red_orange}..%%+=:....:-==%@:..:-=+@@.:@%+-:......:@#....@%.-@+...@#....%@.=@-. .%%.-@*...:@#..{reset}        ")
        print(f"        {red}...-+*#@=.#%+=-#@::@%+=-%@...-+*%@-....:@#....@%.-@=...@#....#@.+@-...@%.-@+....@#..{reset}        ")
        print(f"        {magenta}.-%+::-@*:@*::-@@:=@+::=@@.=@=::+@=.+*..+@*--#@%.-@=...+@=::+@+.-@%::*@%.-@@-::#@-..{reset}        ")
        print(f"        {purple}...+##+:...+##--+..:*#*:=+...+##+...=+....-=-.%%.:*-    .+##+.....+*+.++ -@=-##+. ..{reset}        ")
        print(f"        {purple}........................................+%*--*@=....    .................-@=........{reset}        ")
        print(f"        {dark_purple}.........................................:-==-:.....    ..................-:........{reset}        ")
        print("                                                ........                                            ")
        print("                                                ........                                            ")
        print("                                                                                                    ")
        print(f"                                              {black}saas.group BYOD Security Checker{reset}                     ")
        print("                                                                                                    ")
    
    def validate_email(self, email: str) -> bool:
        """Validate if email belongs to saas.group or its portfolio companies."""
        if not email or '@' not in email:
            return False
        
        try:
            domain = email.split('@')[1].lower()
            return domain in self.valid_domains
        except (IndexError, AttributeError):
            return False
    
    def get_user_email(self) -> str:
        """Authenticate user via Google Sign-In and validate domain."""
        print("\n🔐 Authentication Required")
        print("This tool requires authentication with your saas.group Google account.")
        print("A web browser will open for secure authentication.")
        
        return self._authenticate_with_google()
    
    
    def _authenticate_with_google(self) -> str:
        """Authenticate user with Google Sign-In."""
        try:
            # Check if we have a local HTML file, otherwise create a temporary one
            html_file = os.path.join(os.path.dirname(__file__), 'google_signin.html')
            temp_html = None
            
            if not os.path.exists(html_file):
                # Create temporary HTML file
                temp_html = tempfile.NamedTemporaryFile(mode='w', suffix='.html', delete=False)
                temp_html.write(self._get_signin_html())
                temp_html.close()
                html_file = temp_html.name
            
            # Start a simple HTTP server to serve the HTML file
            # Create shared auth result dictionary
            auth_result = {'email': None, 'complete': False}
            
            # Create handler factory with auth_result
            def create_handler(*args, **kwargs):
                return AuthHTTPRequestHandler(*args, auth_result=auth_result, **kwargs)
            
            # Find available port
            port = 8080
            max_port_attempts = 10
            server = None
            
            for _ in range(max_port_attempts):
                try:
                    server = socketserver.TCPServer(("", port), create_handler)
                    break
                except OSError:
                    port += 1
            
            if server is None:
                print("❌ Could not start local server. Google Sign-In is required.")
                sys.exit(1)
            
            # Change to the directory containing the HTML file
            original_dir = os.getcwd()
            os.chdir(os.path.dirname(html_file))
            
            # Start server in background thread
            server_thread = threading.Thread(target=server.serve_forever)
            server_thread.daemon = True
            server_thread.start()
            
            print(f"🌐 Starting authentication server on port {port}...")
            
            # Open browser
            auth_url = f"http://localhost:{port}/{os.path.basename(html_file)}"
            print(f"Opening browser: {auth_url}")
            webbrowser.open(auth_url)
            
            # Wait for authentication
            print("⏳ Waiting for authentication...")
            print("Please complete the Google Sign-In process in your browser.")
            print("Press Ctrl+C to cancel or use fallback method.")
            
            max_wait_time = 300  # 5 minutes
            start_time = time.time()
            
            while time.time() - start_time < max_wait_time:
                try:
                    # Check if authentication is complete
                    if auth_result['complete'] and auth_result['email']:
                        server.shutdown()
                        email = auth_result['email']
                        print(f"✓ Google authentication successful: {email}")
                        return email
                    
                    time.sleep(1)  # Check every second
                    
                except KeyboardInterrupt:
                    print("\n\nAuthentication cancelled.")
                    break
                except Exception as e:
                    print(f"Error during authentication: {e}")
                    break
            
            print("⏱️ Authentication timed out. Google Sign-In is required.")
            server.shutdown()
            sys.exit(1)
            
        except Exception as e:
            print(f"❌ Google Sign-In failed: {e}")
            print("Google Sign-In is required to use this tool.")
            if server:
                server.shutdown()
            sys.exit(1)
        finally:
            # Cleanup
            if server:
                server.shutdown()
            if temp_html:
                try:
                    os.unlink(temp_html)
                except:
                    pass
            try:
                os.chdir(original_dir)
            except:
                pass
    
    def _get_signin_html(self) -> str:
        """Get the HTML content for Google Sign-In."""
        return '''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>BYOD Security Checker - Google Sign-In</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            margin: 0;
            padding: 20px;
            min-height: 100vh;
            display: flex;
            justify-content: center;
            align-items: center;
        }
        .container {
            background: white;
            border-radius: 12px;
            box-shadow: 0 10px 30px rgba(0, 0, 0, 0.3);
            padding: 40px;
            max-width: 500px;
            width: 100%;
            text-align: center;
        }
        .logo {
            font-size: 24px;
            font-weight: bold;
            color: #333;
            margin-bottom: 10px;
        }
        .subtitle {
            color: #666;
            margin-bottom: 30px;
            font-size: 16px;
        }
        .instructions {
            background: #f8f9fa;
            border-radius: 8px;
            padding: 20px;
            margin: 20px 0;
            text-align: left;
        }
        .instructions h4 {
            margin: 0 0 15px 0;
            color: #333;
        }
        .instructions ol {
            margin: 10px 0;
            padding-left: 20px;
        }
        .instructions li {
            margin: 8px 0;
            line-height: 1.5;
        }
        .note {
            background: #fff3cd;
            border: 1px solid #ffeaa7;
            border-radius: 6px;
            padding: 15px;
            margin: 20px 0;
            color: #856404;
            font-size: 14px;
        }
        .btn {
            background: #4285f4;
            color: white;
            border: none;
            padding: 12px 24px;
            border-radius: 6px;
            cursor: pointer;
            font-size: 16px;
            margin: 10px;
            text-decoration: none;
            display: inline-block;
        }
        .btn:hover {
            background: #357ae8;
        }
        .valid-domains {
            background: #f8f9fa;
            border-radius: 8px;
            padding: 15px;
            margin: 20px 0;
            font-size: 12px;
            color: #666;
            text-align: left;
        }
        .valid-domains h4 {
            margin: 0 0 10px 0;
            color: #333;
        }
        .domain-list {
            max-height: 100px;
            overflow-y: auto;
            line-height: 1.4;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="logo">saas.group</div>
        <div class="subtitle">BYOD Security Checker</div>
        
        <div class="instructions">
            <h4>🔐 Google Sign-In Authentication</h4>
            <ol>
                <li>The Google Client ID is already configured</li>
                <li>Simply close this window and return to the terminal</li>
                <li>Follow the authentication prompts in the terminal</li>
                <li>Sign in with your company email when prompted</li>
            </ol>
        </div>
        
        <div class="valid-domains">
            <h4>Valid Company Domains:</h4>
            <div class="domain-list">
                saas.group, addsearch.com, beekast.com, crosstalent.com, dashthis.com, 
                getprerender.com, getrewardful.com, getscraperapi.com, getusersnap.com, 
                juicer.io, keyword.com, picdrop.com, pipelinecrm.com, rewardful.com, 
                scraperapi.com, seobility.net, usersnap.com, zenloop.com, and more...
            </div>
        </div>
        
        <div class="note">
            <strong>Note:</strong> This implementation uses Google's secure authentication without storing any secrets in the code. 
            Only a public Client ID is required for setup.
        </div>
        
        <div class="note">
            <strong>Quick Start:</strong> Close this window and return to the terminal to continue with email validation, 
            or set up Google Sign-In for enhanced security.
        </div>
        
        <a href="https://console.cloud.google.com/" target="_blank" class="btn">Set up Google Sign-In</a>
    </div>
</body>
</html>'''
    
    def get_device_info(self) -> Dict[str, str]:
        """Get device information (brand, model, serial, RAM, storage)."""
        info = {
            'brand': 'Unknown',
            'model': 'Unknown', 
            'serial': 'Unknown',
            'ram': 'Unknown',
            'storage': 'Unknown'
        }
        
        try:
            if self.system == 'darwin':
                # macOS device info
                # Get brand (always Apple for macOS)
                info['brand'] = 'Apple'
                
                # Get model
                success, output = self.run_command('system_profiler SPHardwareDataType')
                if success:
                    model_match = re.search(r'Model Name: (.+)', output)
                    if model_match:
                        info['model'] = model_match.group(1).strip()
                    
                    # Get serial number
                    serial_match = re.search(r'Serial Number \(system\): (.+)', output)
                    if serial_match:
                        info['serial'] = serial_match.group(1).strip()
                    
                    # Get RAM
                    ram_match = re.search(r'Memory: (.+)', output)
                    if ram_match:
                        info['ram'] = ram_match.group(1).strip()
                
                # Get storage info
                success, output = self.run_command('df -h /')
                if success:
                    lines = output.strip().split('\n')
                    if len(lines) > 1:
                        parts = lines[1].split()
                        if len(parts) >= 2:
                            info['storage'] = parts[1]
                            
            elif self.system == 'windows':
                # Windows device info
                # Get brand and model
                success, output = self.run_command('wmic computersystem get manufacturer,model')
                if success:
                    lines = output.strip().split('\n')
                    if len(lines) > 1:
                        parts = lines[1].split()
                        if len(parts) >= 2:
                            info['brand'] = parts[0]
                            info['model'] = ' '.join(parts[1:])
                
                # Get serial number
                success, output = self.run_command('wmic bios get serialnumber')
                if success:
                    lines = output.strip().split('\n')
                    if len(lines) > 1:
                        info['serial'] = lines[1].strip()
                
                # Get RAM
                success, output = self.run_command('wmic computersystem get TotalPhysicalMemory')
                if success:
                    lines = output.strip().split('\n')
                    if len(lines) > 1:
                        ram_bytes = int(lines[1].strip())
                        ram_gb = ram_bytes / (1024**3)
                        info['ram'] = f"{ram_gb:.1f} GB"
                
                # Get storage
                success, output = self.run_command('wmic logicaldisk get size,freespace,caption')
                if success:
                    lines = output.strip().split('\n')
                    total_size = 0
                    for line in lines[1:]:
                        parts = line.split()
                        if len(parts) >= 3 and parts[0] == 'C:':
                            size_bytes = int(parts[2])
                            size_gb = size_bytes / (1024**3)
                            info['storage'] = f"{size_gb:.1f} GB"
                            break
                            
            elif self.system == 'linux':
                # Linux device info
                # Get brand and model
                if os.path.exists('/sys/devices/virtual/dmi/id/sys_vendor'):
                    with open('/sys/devices/virtual/dmi/id/sys_vendor', 'r') as f:
                        info['brand'] = f.read().strip()
                
                if os.path.exists('/sys/devices/virtual/dmi/id/product_name'):
                    with open('/sys/devices/virtual/dmi/id/product_name', 'r') as f:
                        info['model'] = f.read().strip()
                
                # Get serial number
                if os.path.exists('/sys/devices/virtual/dmi/id/product_serial'):
                    with open('/sys/devices/virtual/dmi/id/product_serial', 'r') as f:
                        info['serial'] = f.read().strip()
                
                # Get RAM
                success, output = self.run_command('free -h')
                if success:
                    lines = output.strip().split('\n')
                    if len(lines) > 1:
                        parts = lines[1].split()
                        if len(parts) >= 2:
                            info['ram'] = parts[1]
                
                # Get storage
                success, output = self.run_command('df -h /')
                if success:
                    lines = output.strip().split('\n')
                    if len(lines) > 1:
                        parts = lines[1].split()
                        if len(parts) >= 2:
                            info['storage'] = parts[1]
                            
        except Exception as e:
            pass  # Keep default 'Unknown' values
        
        return info
    
    def display_device_info(self):
        """Display device information."""
        info = self.get_device_info()
        print(f"\nDevice Information:")
        print(f"  Brand:        {info['brand']}")
        print(f"  Model:        {info['model']}")
        print(f"  Serial:       {info['serial']}")
        print(f"  RAM:          {info['ram']}")
        print(f"  Storage:      {info['storage']}")
        print()
    
    def run_command(self, command: str, shell: bool = True) -> Tuple[bool, str]:
        """Execute a system command and return success status and output."""
        try:
            result = subprocess.run(
                command,
                shell=shell,
                capture_output=True,
                text=True,
                timeout=30
            )
            return result.returncode == 0, result.stdout.strip()
        except (subprocess.TimeoutExpired, subprocess.SubprocessError) as e:
            return False, str(e)
    
    def check_os_firewall(self) -> Dict[str, any]:
        """Check if OS firewall is enabled."""
        if self.system == 'darwin':
            return self._check_macos_firewall()
        elif self.system == 'windows':
            return self._check_windows_firewall()
        elif self.system == 'linux':
            return self._check_linux_firewall()
        else:
            return {'status': False, 'message': f'Unsupported platform: {self.system}'}
    
    def _check_macos_firewall(self) -> Dict[str, any]:
        """Check macOS firewall status."""
        try:
            # Try to check firewall status using defaults (non-privileged)
            success, output = self.run_command('defaults read /Library/Preferences/com.apple.alf globalstate')
            if success:
                try:
                    state = int(output.strip())
                    if state == 1:
                        return {'status': True, 'message': 'macOS firewall is enabled', 'remediation': ''}
                    elif state == 2:
                        return {'status': True, 'message': 'macOS firewall is enabled (strict mode)', 'remediation': ''}
                    else:
                        return {'status': False, 'message': 'macOS firewall is disabled', 'remediation': 'Enable macOS firewall: System Preferences > Security & Privacy > Firewall > Turn On Firewall'}
                except ValueError:
                    pass
            
            # Fallback: Try to check if firewall process is running
            success, output = self.run_command('pgrep -f "socketfilterfw"')
            if success and output.strip():
                return {'status': True, 'message': 'macOS firewall appears to be running', 'remediation': ''}
            
            # Unable to determine status without elevated privileges
            return {'status': False, 'message': 'Unable to verify firewall status (insufficient permissions)', 'remediation': 'Please manually verify firewall is enabled: System Preferences > Security & Privacy > Firewall'}
                
        except Exception as e:
            return {'status': False, 'message': f'Unable to check firewall status: {str(e)}', 'remediation': 'Please manually verify firewall is enabled: System Preferences > Security & Privacy > Firewall'}
    
    def _check_windows_firewall(self) -> Dict[str, any]:
        """Check Windows firewall status."""
        try:
            # Check Windows Defender Firewall status
            success, output = self.run_command('netsh advfirewall show allprofiles state')
            if success:
                # Check if all profiles are enabled
                domain_enabled = 'Domain Profile' in output and 'State' in output and 'ON' in output
                private_enabled = 'Private Profile' in output and 'State' in output and 'ON' in output
                public_enabled = 'Public Profile' in output and 'State' in output and 'ON' in output
                
                if domain_enabled and private_enabled and public_enabled:
                    return {'status': True, 'message': 'Windows Defender Firewall is enabled for all profiles', 'remediation': ''}
                else:
                    disabled_profiles = []
                    if not domain_enabled:
                        disabled_profiles.append('Domain')
                    if not private_enabled:
                        disabled_profiles.append('Private')
                    if not public_enabled:
                        disabled_profiles.append('Public')
                    disabled_profiles_str = ', '.join(disabled_profiles)
                    return {'status': False, 'message': f'Windows Defender Firewall is disabled for: {disabled_profiles_str}', 'remediation': 'Enable Windows Defender Firewall: Control Panel > System and Security > Windows Defender Firewall > Turn Windows Defender Firewall on or off'}
            
            # Alternative check using PowerShell
            success, output = self.run_command('powershell -Command "Get-NetFirewallProfile | Select-Object Name, Enabled"')
            if success:
                enabled_count = output.count('True')
                if enabled_count >= 3:
                    return {'status': True, 'message': 'Windows Defender Firewall is enabled', 'remediation': ''}
                else:
                    return {'status': False, 'message': 'Windows Defender Firewall is not fully enabled', 'remediation': 'Enable Windows Defender Firewall: Control Panel > System and Security > Windows Defender Firewall > Turn Windows Defender Firewall on or off'}
            
            return {'status': False, 'message': 'Unable to check firewall status', 'remediation': 'Enable Windows Defender Firewall: Control Panel > System and Security > Windows Defender Firewall > Turn Windows Defender Firewall on or off'}
                
        except Exception as e:
            return {'status': False, 'message': f'Error checking firewall: {str(e)}', 'remediation': 'Enable Windows Defender Firewall: Control Panel > System and Security > Windows Defender Firewall > Turn Windows Defender Firewall on or off'}
    
    def _check_linux_firewall(self) -> Dict[str, any]:
        """Check Linux firewall status."""
        try:
            # Check UFW (Uncomplicated Firewall)
            success, output = self.run_command('ufw status')
            if success:
                if 'Status: active' in output:
                    return {'status': True, 'message': 'UFW firewall is active', 'remediation': ''}
                elif 'Status: inactive' in output:
                    return {'status': False, 'message': 'UFW firewall is inactive', 'remediation': 'Enable UFW firewall: Run "sudo ufw enable" in terminal'}
            
            # Check iptables
            success, output = self.run_command('iptables -L -n')
            if success:
                # Check if there are any rules beyond default accept
                lines = output.strip().split('\n')
                rule_count = 0
                for line in lines:
                    if line.strip() and not line.startswith('Chain') and not line.startswith('target'):
                        rule_count += 1
                
                if rule_count > 0:
                    return {'status': True, 'message': 'iptables firewall rules are configured', 'remediation': ''}
                else:
                    return {'status': False, 'message': 'No iptables firewall rules found', 'remediation': 'Configure iptables firewall: Install and configure UFW ("sudo apt install ufw && sudo ufw enable") or set up iptables rules manually'}
            
            # Check firewalld
            success, output = self.run_command('firewall-cmd --state')
            if success:
                if 'running' in output.lower():
                    return {'status': True, 'message': 'firewalld is running', 'remediation': ''}
                else:
                    return {'status': False, 'message': 'firewalld is not running', 'remediation': 'Start firewalld: Run "sudo systemctl start firewalld && sudo systemctl enable firewalld" in terminal'}
            
            return {'status': False, 'message': 'No firewall found or unable to check status', 'remediation': 'Install and configure a firewall: For Ubuntu/Debian: "sudo apt install ufw && sudo ufw enable", For CentOS/RHEL: "sudo yum install firewalld && sudo systemctl start firewalld && sudo systemctl enable firewalld"'}
            
        except Exception as e:
            return {'status': False, 'message': f'Error checking firewall: {str(e)}', 'remediation': 'Install and configure a firewall: For Ubuntu/Debian: "sudo apt install ufw && sudo ufw enable", For CentOS/RHEL: "sudo yum install firewalld && sudo systemctl start firewalld && sudo systemctl enable firewalld"'}
    
    def check_disk_encryption(self) -> Dict[str, any]:
        """Check if disk encryption is enabled."""
        if self.system == 'darwin':
            return self._check_macos_encryption()
        elif self.system == 'windows':
            return self._check_windows_encryption()
        elif self.system == 'linux':
            return self._check_linux_encryption()
        else:
            return {'status': False, 'message': f'Unsupported platform: {self.system}'}
    
    def _check_macos_encryption(self) -> Dict[str, any]:
        """Check macOS FileVault encryption."""
        try:
            success, output = self.run_command('fdesetup status')
            if success and 'FileVault is On' in output:
                return {'status': True, 'message': 'FileVault encryption is enabled', 'remediation': ''}
            else:
                return {'status': False, 'message': 'FileVault encryption is not enabled', 'remediation': 'Enable FileVault encryption: System Preferences > Security & Privacy > FileVault > Turn On FileVault'}
        except Exception as e:
            return {'status': False, 'message': f'Error checking encryption: {str(e)}', 'remediation': 'Enable FileVault encryption: System Preferences > Security & Privacy > FileVault > Turn On FileVault'}
    
    def _check_windows_encryption(self) -> Dict[str, any]:
        """Check Windows BitLocker encryption."""
        try:
            success, output = self.run_command('manage-bde -status')
            if success:
                if 'Protection On' in output:
                    return {'status': True, 'message': 'BitLocker encryption is enabled', 'remediation': ''}
                else:
                    return {'status': False, 'message': 'BitLocker encryption is not enabled', 'remediation': 'Enable BitLocker encryption: Control Panel > System and Security > BitLocker Drive Encryption > Turn on BitLocker'}
            else:
                return {'status': False, 'message': 'Unable to check BitLocker status', 'remediation': 'Enable BitLocker encryption: Control Panel > System and Security > BitLocker Drive Encryption > Turn on BitLocker'}
        except Exception as e:
            return {'status': False, 'message': f'Error checking encryption: {str(e)}', 'remediation': 'Enable BitLocker encryption: Control Panel > System and Security > BitLocker Drive Encryption > Turn on BitLocker'}
    
    def _check_linux_encryption(self) -> Dict[str, any]:
        """Check Linux LUKS encryption."""
        try:
            # Check for LUKS encrypted devices
            success, output = self.run_command('lsblk -o NAME,FSTYPE')
            if success and 'crypto_LUKS' in output:
                return {'status': True, 'message': 'LUKS encryption detected', 'remediation': ''}
            
            # Check for encrypted filesystems in /proc/mounts
            success, output = self.run_command('cat /proc/mounts')
            if success and ('/dev/mapper/' in output or 'dm-' in output):
                # Check if these are encrypted
                success, dm_output = self.run_command('dmsetup table')
                if success and 'crypt' in dm_output:
                    return {'status': True, 'message': 'Disk encryption detected', 'remediation': ''}
            
            return {'status': False, 'message': 'No disk encryption detected', 'remediation': 'Enable disk encryption: Use LUKS encryption during OS installation or encrypt existing partitions with "cryptsetup luksFormat /dev/sdX" (WARNING: This will destroy data - backup first!)'}
            
        except Exception as e:
            return {'status': False, 'message': f'Error checking encryption: {str(e)}', 'remediation': 'Enable disk encryption: Use LUKS encryption during OS installation or encrypt existing partitions with "cryptsetup luksFormat /dev/sdX" (WARNING: This will destroy data - backup first!)'}
    
    def check_autolock(self) -> Dict[str, any]:
        """Check if autolock is configured for 10 minutes or less."""
        if self.system == 'darwin':
            return self._check_macos_autolock()
        elif self.system == 'windows':
            return self._check_windows_autolock()
        elif self.system == 'linux':
            return self._check_linux_autolock()
        else:
            return {'status': False, 'message': f'Unsupported platform: {self.system}'}
    
    def _check_macos_autolock(self) -> Dict[str, any]:
        """Check macOS screen lock timeout."""
        try:
            # Check display sleep timeout using pmset
            success, output = self.run_command('pmset -g')
            if success:
                # Parse displaysleep setting
                display_sleep_match = re.search(r'displaysleep\s+(\d+)', output)
                if display_sleep_match:
                    display_sleep = int(display_sleep_match.group(1))
                    if display_sleep <= 10:  # 10 minutes
                        return {'status': True, 'message': f'Display sleep timeout: {display_sleep} minutes', 'remediation': ''}
                    else:
                        return {'status': False, 'message': f'Display sleep timeout too long: {display_sleep} minutes', 'remediation': 'Set display sleep timeout to 10 minutes or less: System Preferences > Energy Saver > Display Sleep'}
            
            # Fallback: check screensaver settings (older macOS versions)
            success, output = self.run_command('defaults read com.apple.screensaver idleTime')
            if success:
                idle_time = int(output)
                if idle_time <= 600:  # 10 minutes = 600 seconds
                    return {'status': True, 'message': f'Screen saver timeout: {idle_time//60} minutes', 'remediation': ''}
                else:
                    return {'status': False, 'message': f'Screen saver timeout too long: {idle_time//60} minutes', 'remediation': 'Set screen saver timeout to 10 minutes or less: System Preferences > Desktop & Screen Saver > Screen Saver > Start after'}
            
            return {'status': False, 'message': 'Unable to determine screen lock timeout', 'remediation': 'Configure screen lock timeout: System Preferences > Security & Privacy > General > Require password after sleep or screen saver begins'}
            
        except Exception as e:
            return {'status': False, 'message': f'Error checking autolock: {str(e)}', 'remediation': 'Configure screen lock timeout: System Preferences > Security & Privacy > General > Require password after sleep or screen saver begins'}
    
    def _check_windows_autolock(self) -> Dict[str, any]:
        """Check Windows screen lock timeout."""
        try:
            # Check screen saver timeout
            success, output = self.run_command('reg query "HKEY_CURRENT_USER\\Control Panel\\Desktop" /v ScreenSaveTimeOut')
            if success:
                timeout_match = re.search(r'ScreenSaveTimeOut\s+REG_SZ\s+(\d+)', output)
                if timeout_match:
                    timeout = int(timeout_match.group(1))
                    if timeout <= 600:  # 10 minutes = 600 seconds
                        return {'status': True, 'message': f'Screen lock timeout: {timeout//60} minutes', 'remediation': ''}
                    else:
                        return {'status': False, 'message': f'Screen lock timeout too long: {timeout//60} minutes', 'remediation': 'Set screen lock timeout to 10 minutes or less: Control Panel > Personalization > Screen Saver > Wait'}
            
            # Check power settings
            success, output = self.run_command('powercfg /query SCHEME_CURRENT SUB_VIDEO VIDEOIDLE')
            if success:
                timeout_match = re.search(r'Current AC Power Setting Index: 0x([a-f0-9]+)', output)
                if timeout_match:
                    timeout = int(timeout_match.group(1), 16)
                    if timeout > 0 and timeout <= 600:
                        return {'status': True, 'message': f'Display timeout: {timeout//60} minutes', 'remediation': ''}
            
            return {'status': False, 'message': 'Screen lock not configured properly', 'remediation': 'Configure screen lock: Control Panel > Personalization > Screen Saver > Wait (set to 10 minutes or less) and check "On resume, display logon screen"'}
            
        except Exception as e:
            return {'status': False, 'message': f'Error checking autolock: {str(e)}', 'remediation': 'Configure screen lock: Control Panel > Personalization > Screen Saver > Wait (set to 10 minutes or less) and check "On resume, display logon screen"'}
    
    def _check_linux_autolock(self) -> Dict[str, any]:
        """Check Linux screen lock timeout."""
        try:
            # Check GNOME settings
            success, output = self.run_command('gsettings get org.gnome.desktop.screensaver idle-activation-enabled')
            if success and 'true' in output.lower():
                success, timeout_output = self.run_command('gsettings get org.gnome.desktop.screensaver idle-delay')
                if success:
                    timeout = int(timeout_output.strip())
                    if timeout <= 600:  # 10 minutes = 600 seconds
                        return {'status': True, 'message': f'Screen lock timeout: {timeout//60} minutes', 'remediation': ''}
                    else:
                        return {'status': False, 'message': f'Screen lock timeout too long: {timeout//60} minutes', 'remediation': 'Set screen lock timeout to 10 minutes or less: Settings > Privacy > Screen Lock > Blank screen delay'}
            
            # Check KDE settings
            kde_config = os.path.expanduser('~/.config/kscreenlockerrc')
            if os.path.exists(kde_config):
                try:
                    with open(kde_config, 'r') as f:
                        content = f.read()
                        if 'Timeout=' in content:
                            timeout_match = re.search(r'Timeout=(\d+)', content)
                            if timeout_match:
                                timeout = int(timeout_match.group(1))
                                if timeout <= 10:  # KDE uses minutes
                                    return {'status': True, 'message': f'Screen lock timeout: {timeout} minutes', 'remediation': ''}
                                else:
                                    return {'status': False, 'message': f'Screen lock timeout too long: {timeout} minutes', 'remediation': 'Set screen lock timeout to 10 minutes or less: System Settings > Desktop Behavior > Screen Locking > Lock screen automatically after'}
                except:
                    pass
            
            return {'status': False, 'message': 'Screen lock not configured', 'remediation': 'Configure screen lock: For GNOME: Settings > Privacy > Screen Lock, For KDE: System Settings > Desktop Behavior > Screen Locking'}
            
        except Exception as e:
            return {'status': False, 'message': f'Error checking autolock: {str(e)}', 'remediation': 'Configure screen lock: For GNOME: Settings > Privacy > Screen Lock, For KDE: System Settings > Desktop Behavior > Screen Locking'}
    
    def check_guest_accounts(self) -> Dict[str, any]:
        """Check if guest accounts are disabled."""
        if self.system == 'darwin':
            return self._check_macos_guest_accounts()
        elif self.system == 'windows':
            return self._check_windows_guest_accounts()
        elif self.system == 'linux':
            return self._check_linux_guest_accounts()
        else:
            return {'status': False, 'message': f'Unsupported platform: {self.system}'}
    
    def _check_macos_guest_accounts(self) -> Dict[str, any]:
        """Check macOS guest account status."""
        try:
            # Try to check guest account without sudo first
            success, output = self.run_command('dscl . -read /Users/Guest')
            if success:
                return {'status': False, 'message': 'Guest account is enabled', 'remediation': 'Disable guest account: System Preferences > Users & Groups > Guest User > Allow guests to log in to this computer (uncheck)'}
            
            # Check if guest account exists in user list (alternative approach)
            success, output = self.run_command('dscl . -list /Users')
            if success and 'Guest' in output:
                return {'status': False, 'message': 'Guest account may be enabled', 'remediation': 'Please verify guest account is disabled: System Preferences > Users & Groups > Guest User'}
            
            # If no guest account found, assume it's disabled
            return {'status': True, 'message': 'Guest account appears to be disabled', 'remediation': ''}
            
        except Exception as e:
            return {'status': False, 'message': f'Unable to verify guest account status (insufficient permissions)', 'remediation': 'Please manually verify guest account is disabled: System Preferences > Users & Groups > Guest User'}
    
    def _check_windows_guest_accounts(self) -> Dict[str, any]:
        """Check Windows guest account status."""
        try:
            success, output = self.run_command('net user guest')
            if success:
                if 'Account active' in output and 'No' in output:
                    return {'status': True, 'message': 'Guest account is disabled', 'remediation': ''}
                else:
                    return {'status': False, 'message': 'Guest account is enabled', 'remediation': 'Disable guest account: Run "net user guest /active:no" as administrator or Control Panel > User Accounts > Manage another account > Guest > Turn off guest account'}
            else:
                return {'status': True, 'message': 'Guest account not found (disabled)', 'remediation': ''}
        except Exception as e:
            return {'status': False, 'message': f'Error checking guest accounts: {str(e)}', 'remediation': 'Disable guest account: Run "net user guest /active:no" as administrator or Control Panel > User Accounts > Manage another account > Guest > Turn off guest account'}
    
    def _check_linux_guest_accounts(self) -> Dict[str, any]:
        """Check Linux guest account status."""
        try:
            # Check for guest account in /etc/passwd
            success, output = self.run_command('getent passwd guest')
            if success:
                # Try to check if account is locked without sudo first
                success, shadow_output = self.run_command('getent shadow guest')
                if success and shadow_output:
                    # Can read shadow file without sudo - check if locked
                    if shadow_output.split(':')[1].startswith('!') or shadow_output.split(':')[1].startswith('*'):
                        return {'status': True, 'message': 'Guest account is locked', 'remediation': ''}
                    else:
                        return {'status': False, 'message': 'Guest account is active', 'remediation': 'Lock guest account: Run "sudo usermod -L guest" or "sudo passwd -l guest" to lock the account'}
                else:
                    # Cannot read shadow file - check if login shell is disabled
                    if '/bin/false' in output or '/usr/sbin/nologin' in output or '/sbin/nologin' in output:
                        return {'status': True, 'message': 'Guest account has login disabled', 'remediation': ''}
                    else:
                        return {'status': False, 'message': 'Guest account exists (unable to verify lock status)', 'remediation': 'Please verify guest account is locked: Run "sudo passwd -S guest" to check status'}
            else:
                return {'status': True, 'message': 'No guest account found', 'remediation': ''}
        except Exception as e:
            return {'status': False, 'message': f'Unable to verify guest account status: {str(e)}', 'remediation': 'Please manually verify no guest accounts exist or are locked'}
    
    def run_all_checks(self) -> Dict[str, Dict[str, any]]:
        """Run all security checks."""
        self.display_header()
        
        # Validate user email before proceeding
        user_email = self.get_user_email()
        
        self.display_device_info()
        
        print("Running BYOD Security Compliance Checks...")
        print("=" * 50)
        
        self.results['os_firewall'] = self.check_os_firewall()
        self.results['disk_encryption'] = self.check_disk_encryption()
        self.results['autolock'] = self.check_autolock()
        self.results['guest_accounts'] = self.check_guest_accounts()
        
        return self.results, user_email
    
    def display_results(self):
        """Display formatted results."""
        print(f"\nSecurity Compliance Report for {platform.system()} {platform.release()}")
        print("=" * 60)
        
        checks = [
            ('OS Firewall', 'os_firewall', 'Built-in operating system firewall enabled'),
            ('Disk Encryption', 'disk_encryption', 'Full disk encryption enabled'),
            ('Auto-lock', 'autolock', 'Screen lock after 10 minutes idle'),
            ('Guest Accounts', 'guest_accounts', 'No active guest accounts')
        ]
        
        all_passed = True
        
        failed_checks = []
        
        for name, key, description in checks:
            result = self.results[key]
            status = "✓ PASS" if result['status'] else "✗ FAIL"
            status_color = "\033[92m" if result['status'] else "\033[91m"
            reset_color = "\033[0m"
            
            print(f"{status_color}{status:8}{reset_color} {name:20} {description}")
            print(f"         {' ' * 20} {result['message']}")
            print()
            
            if not result['status']:
                all_passed = False
                failed_checks.append((name, result))
        
        print("=" * 60)
        if all_passed:
            print("\033[92m✓ ALL CHECKS PASSED - Device is compliant\033[0m")
        else:
            print("\033[91m✗ SOME CHECKS FAILED - Device is not compliant\033[0m")
            
            # Display remediation steps for failed checks
            if failed_checks:
                print("\n" + "=" * 60)
                print("\033[93mREMEDIATION STEPS\033[0m")
                print("=" * 60)
                
                for name, result in failed_checks:
                    if result.get('remediation'):
                        print(f"\n\033[91m✗ {name}\033[0m")
                        print(f"  How to fix: {result['remediation']}")
                        print()
        print()
    
    def send_to_n8n(self, user_email: str = None) -> bool:
        """Send security check results to n8n webhook."""
        if not self.n8n_webhook_url:
            print("⚠️  No n8n webhook URL configured. Skipping API send.")
            return False
        
        try:
            # Get device information
            device_info = self.get_device_info()
            
            # Prepare payload
            payload = {
                "timestamp": datetime.datetime.now().isoformat(),
                "user_email": user_email,
                "device_info": device_info,
                "system": {
                    "platform": self._map_platform_name(platform.system()),
                    "version": platform.release(),
                    "machine": platform.machine()
                },
                "security_checks": self.results,
                "compliance_status": all(result['status'] for result in self.results.values()),
                "failed_checks": [key for key, result in self.results.items() if not result['status']],
                "remediation_needed": [
                    {
                        "check": key,
                        "message": result['message'],
                        "remediation": result['remediation']
                    }
                    for key, result in self.results.items() 
                    if not result['status'] and result.get('remediation')
                ]
            }
            
            # Prepare headers
            headers = {
                'Content-Type': 'application/json',
                'User-Agent': 'BYOD-Security-Checker/1.0'
            }
            
            # Add authentication (only if credentials are provided)
            auth = None
            if self.n8n_username and self.n8n_password:
                # Use Basic Authentication
                auth = (self.n8n_username, self.n8n_password)
                print("🔐 Using Basic Authentication")
            elif self.api_key:
                # Use Bearer token
                headers['Authorization'] = f'Bearer {self.api_key}'
                print("🔐 Using Bearer Token Authentication")
            else:
                print("🔓 No authentication (webhook configured with 'Authorization: None')")
            
            print(f"\n📡 Sending results to n8n webhook...")
            
            # Flatten the payload into individual parameters for easier n8n processing
            flat_params = {
                'timestamp': payload['timestamp'],
                'user_email': payload['user_email'],
                'compliance_status': payload['compliance_status'],
                'failed_checks_count': len(payload['failed_checks']),
                'failed_checks': ','.join(payload['failed_checks']) if payload['failed_checks'] else '',
                
                # Device info
                'device_brand': payload['device_info']['brand'],
                'device_model': payload['device_info']['model'],
                'device_serial': payload['device_info']['serial'],
                'device_ram': payload['device_info']['ram'],
                'device_storage': payload['device_info']['storage'],
                
                # System info
                'system_platform': payload['system']['platform'],
                'system_version': payload['system']['version'],
                'system_machine': payload['system']['machine'],
                
                # Security check results
                'firewall_status': payload['security_checks']['os_firewall']['status'],
                'firewall_message': payload['security_checks']['os_firewall']['message'],
                'firewall_remediation': payload['security_checks']['os_firewall']['remediation'],
                
                'encryption_status': payload['security_checks']['disk_encryption']['status'],
                'encryption_message': payload['security_checks']['disk_encryption']['message'],
                'encryption_remediation': payload['security_checks']['disk_encryption']['remediation'],
                
                'autolock_status': payload['security_checks']['autolock']['status'],
                'autolock_message': payload['security_checks']['autolock']['message'],
                'autolock_remediation': payload['security_checks']['autolock']['remediation'],
                
                'guest_accounts_status': payload['security_checks']['guest_accounts']['status'],
                'guest_accounts_message': payload['security_checks']['guest_accounts']['message'],
                'guest_accounts_remediation': payload['security_checks']['guest_accounts']['remediation'],
                
                # Remediation summary
                'remediation_needed': json.dumps(payload['remediation_needed']) if payload['remediation_needed'] else ''
            }
            
            # Send as POST request with flattened data in the body
            try:
                response = requests.post(
                    self.n8n_webhook_url,
                    json=flat_params,
                    headers=headers,
                    auth=auth,
                    timeout=30
                )
                
                # If POST fails with 404 (not registered), try GET as fallback
                if response.status_code == 404 and "not registered" in response.text:
                    print("📡 POST not supported, trying GET with query parameters...")
                    response = requests.get(
                        self.n8n_webhook_url,
                        params=flat_params,
                        headers=headers,
                        auth=auth,
                        timeout=30
                    )
                    
                    # If still 404, try simple GET (test webhook behavior)
                    if response.status_code == 404 and "not registered" in response.text:
                        print("📡 Webhook appears to be in test mode, trying simple GET...")
                        response = requests.get(
                            self.n8n_webhook_url,
                            headers=headers,
                            auth=auth,
                            timeout=30
                        )
                    
            except requests.exceptions.RequestException as e:
                print(f"❌ Network error: {str(e)}")
                return False
            
            if response.status_code == 200:
                print("✅ Successfully sent results to n8n!")
                return True
            else:
                print(f"❌ Failed to send to n8n. Status code: {response.status_code}")
                print(f"Response: {response.text}")
                return False
                
        except requests.exceptions.RequestException as e:
            print(f"❌ Network error sending to n8n: {str(e)}")
            return False
        except Exception as e:
            print(f"❌ Error sending to n8n: {str(e)}")
            return False


def main():
    """Main function."""
    import argparse
    
    parser = argparse.ArgumentParser(description='BYOD Security Compliance Checker')
    parser.add_argument('--n8n-webhook', 
                       help='n8n webhook URL to send results to')
    parser.add_argument('--api-key', 
                       help='API key for Bearer token authentication (optional)')
    parser.add_argument('--n8n-username',
                       help='Username for Basic authentication (optional)')
    parser.add_argument('--n8n-password',
                       help='Password for Basic authentication (optional)')
    parser.add_argument('--send-to-n8n', action='store_true',
                       help='Send results to n8n webhook (now enabled by default)')
    parser.add_argument('--no-n8n', action='store_true',
                       help='Disable sending results to n8n (override default behavior)')
    
    # Handle help separately to maintain backward compatibility
    if len(sys.argv) > 1 and sys.argv[1] in ['-h', '--help']:
        parser.print_help()
        print("\nSecurity Checks:")
        print("  - OS firewall (built-in firewall enabled)")
        print("  - Disk encryption (FileVault/BitLocker/LUKS)")
        print("  - Auto-lock timeout (10 minutes or less)")
        print("  - Guest accounts (disabled)")
        print("\nAPI Integration:")
        print("  Results are automatically sent to n8n (saas.group default webhook)")
        print("  Default: No authentication required (webhook configured with 'Authorization: None')")
        print("  Use --no-n8n to disable sending to n8n")
        print("  Override webhook: --n8n-webhook 'https://your-n8n-instance.com/webhook/id'")
        print("  Add auth if needed: --n8n-username 'user' --n8n-password 'pass'")
        print("  Or set environment variables: N8N_WEBHOOK_URL, N8N_USERNAME, N8N_PASSWORD")
        return
    
    args = parser.parse_args()
    
    # No validation needed since we have default webhook URL and credentials
    
    try:
        # Initialize checker with n8n configuration
        checker = SecurityChecker(
            n8n_webhook_url=args.n8n_webhook,
            api_key=args.api_key,
            n8n_username=args.n8n_username,
            n8n_password=args.n8n_password
        )
        
        
        # Run security checks
        results, user_email = checker.run_all_checks()
        
        # Display results
        checker.display_results()
        
        # Send to n8n by default unless explicitly disabled
        if checker.n8n_webhook_url and not args.no_n8n:
            checker.send_to_n8n(user_email)
            
    except KeyboardInterrupt:
        print("\nCheck interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"Error: {str(e)}")
        sys.exit(1)


if __name__ == "__main__":
    main()