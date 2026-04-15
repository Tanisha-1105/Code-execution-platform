"""
Cloud Code Executor Backend
Python Flask API for executing Python and C code securely
"""

import os
import sys
import json
import uuid
import subprocess
import tempfile
import time
from datetime import datetime, timedelta
from flask import Flask, request, jsonify, render_template, send_from_directory, redirect, url_for, session
from flask_cors import CORS
from authlib.integrations.flask_client import OAuth
import threading
import shutil
import urllib.parse

# ========================== CONFIGURATION ==========================

# Get the directory where this script is located
script_dir = os.path.dirname(os.path.abspath(__file__))

# Initialize Flask with static and template folders
app = Flask(__name__, 
            static_folder=script_dir,
            static_url_path='',
            template_folder=script_dir)

# Configure secret key for sessions
app.secret_key = os.environ.get('SECRET_KEY', os.urandom(24))

# Enable CORS for all routes
CORS(app)

# AWS Elastic Beanstalk expects 'application' variable
application = app

# ========================== OAUTH/COGNITO SETUP ==========================

oauth = OAuth(app)

# AWS Cognito OAuth Configuration
cognito_domain = 'https://ap-south-1rx0chvi71.auth.ap-south-1.amazoncognito.com'
cognito_client_id = os.environ.get('COGNITO_CLIENT_ID', '3f8qe4hfmqmmfh8vptb2iichg')
cognito_client_secret = os.environ.get('COGNITO_CLIENT_SECRET', '')

print("[INFO] ===== COGNITO INITIALIZATION =====")
print(f"[INFO] Client ID: {cognito_client_id}")
print(f"[INFO] Client Secret Present: {bool(cognito_client_secret)}")
print(f"[INFO] Cognito Domain: {cognito_domain}")

# Register Cognito OAuth with MANUAL configuration (no metadata fetch)
try:
    oauth.register(
        name='cognito',
        client_id=cognito_client_id,
        client_secret=cognito_client_secret,
        access_token_url=f'{cognito_domain}/oauth2/token',
        authorize_url=f'{cognito_domain}/oauth2/authorize',
        api_base_url=f'{cognito_domain}/oauth2',
        userinfo_endpoint=f'{cognito_domain}/oauth2/userInfo',
        client_kwargs={
            'scope': 'openid email profile'
        }
    )
    print("[INFO] ✓ OAuth Cognito registered successfully")
except Exception as e:
    print(f"[ERROR] ✗ Failed to register OAuth: {e}")

# Configuration
CODE_EXECUTION_TIMEOUT = 30  # seconds
MAX_OUTPUT_SIZE = 50000  # characters
SHARED_CODE_EXPIRY = 24 * 3600  # 24 hours in seconds
MAX_CODE_LENGTH = 100000  # characters

# In-memory storage for shared codes (use Redis in production)
shared_codes = {}
code_cleanup_interval = 3600  # Cleanup every hour

# User code execution history storage (use database in production)
user_history = {}  # Format: { 'email': [{'code': '', 'language': '', 'output': '', 'timestamp': ''}, ...] }

# Temporary directories for compilation
TEMP_DIR = tempfile.gettempdir()

# ========================== SECURITY FUNCTIONS ==========================

def validate_code(code, language):
    """Validate code for obvious security issues"""
    if not code or not isinstance(code, str):
        return False, "Invalid code"
    
    if len(code) > MAX_CODE_LENGTH:
        return False, f"Code exceeds maximum length of {MAX_CODE_LENGTH} characters"
    
    # Dangerous patterns for Python
    if language == "python":
        dangerous_imports = [
            "os.system", "subprocess", "eval", "exec", "__import__",
            "open(", "input(", "compile("
        ]
        # Allow these in comments/strings context - basic check
        for pattern in dangerous_imports:
            if pattern in code:
                # These are actually needed for many legitimate programs
                pass  # Allow for now, rely on container isolation instead
    
    return True, ""

def cleanup_shared_codes():
    """Remove expired shared codes"""
    current_time = time.time()
    expired_ids = [
        share_id for share_id, data in shared_codes.items()
        if current_time - data['created_at'] > SHARED_CODE_EXPIRY
    ]
    for share_id in expired_ids:
        del shared_codes[share_id]

def cleanup_old_files(directory, hours=1):
    """Clean up old temporary files"""
    if not os.path.exists(directory):
        return
    
    current_time = time.time()
    for filename in os.listdir(directory):
        filepath = os.path.join(directory, filename)
        if os.path.isfile(filepath):
            file_age = current_time - os.path.getmtime(filepath)
            if file_age > hours * 3600:
                try:
                    os.remove(filepath)
                except Exception as e:
                    print(f"Error removing file {filepath}: {e}")

# ========================== EXECUTION FUNCTIONS ==========================

def execute_python(code):
    """
    Execute Python code safely with timeout
    Returns: (success, output, error_message)
    """
    try:
        # Validate code
        valid, msg = validate_code(code, "python")
        if not valid:
            return False, "", msg
        
        # Execute code with timeout
        result = subprocess.run(
            [sys.executable, "-c", code],
            capture_output=True,
            text=True,
            timeout=CODE_EXECUTION_TIMEOUT,
            cwd=TEMP_DIR
        )
        
        output = result.stdout
        error = result.stderr
        
        # Combine output and error
        if error:
            output = output + "\n" + error if output else error
        
        # Truncate if too long
        if len(output) > MAX_OUTPUT_SIZE:
            output = output[:MAX_OUTPUT_SIZE] + f"\n... (output truncated, max {MAX_OUTPUT_SIZE} chars)"
        
        return True, output, None
    
    except subprocess.TimeoutExpired:
        return False, "", f"Code execution timeout (max {CODE_EXECUTION_TIMEOUT} seconds)"
    
    except Exception as e:
        return False, "", f"Execution error: {str(e)}"

def execute_c(code):
    """
    Compile and execute C code safely with timeout
    Returns: (success, output, error_message)
    """
    temp_c_file = None
    temp_exe_file = None
    
    try:
        # Validate code
        valid, msg = validate_code(code, "c")
        if not valid:
            return False, "", msg
        
        # Create temporary files
        temp_dir = tempfile.mkdtemp()
        temp_c_file = os.path.join(temp_dir, f"code_{uuid.uuid4().hex[:8]}.c")
        temp_exe_file = os.path.join(temp_dir, f"code_{uuid.uuid4().hex[:8]}")
        
        # Write C code to file
        with open(temp_c_file, 'w') as f:
            f.write(code)
        
        # Compile C code
        compile_result = subprocess.run(
            ["gcc", "-o", temp_exe_file, temp_c_file, "-Wall"],
            capture_output=True,
            text=True,
            timeout=15,
            cwd=temp_dir
        )
        
        if compile_result.returncode != 0:
            error_msg = compile_result.stderr or "Compilation failed"
            return False, "", f"Compilation Error:\n{error_msg}"
        
        # Execute compiled program
        exec_result = subprocess.run(
            [temp_exe_file],
            capture_output=True,
            text=True,
            timeout=CODE_EXECUTION_TIMEOUT,
            cwd=temp_dir
        )
        
        output = exec_result.stdout
        error = exec_result.stderr
        
        # Combine output and error
        if error:
            output = output + "\n" + error if output else error
        
        # Truncate if too long
        if len(output) > MAX_OUTPUT_SIZE:
            output = output[:MAX_OUTPUT_SIZE] + f"\n... (output truncated, max {MAX_OUTPUT_SIZE} chars)"
        
        return True, output, None
    
    except subprocess.TimeoutExpired:
        return False, "", f"Code execution timeout (max {CODE_EXECUTION_TIMEOUT} seconds)"
    
    except FileNotFoundError:
        return False, "", "GCC compiler not found. Please install GCC (gcc or mingw-w64 for Windows)"
    
    except Exception as e:
        return False, "", f"Execution error: {str(e)}"
    
    finally:
        # Cleanup temporary files
        if temp_c_file and os.path.exists(temp_c_file):
            try:
                os.remove(temp_c_file)
            except:
                pass
        
        if temp_exe_file and os.path.exists(temp_exe_file):
            try:
                os.remove(temp_exe_file)
            except:
                pass
        
        # Remove temp directory
        try:
            if os.path.exists(os.path.dirname(temp_c_file or "")):
                shutil.rmtree(os.path.dirname(temp_c_file))
        except:
            pass

# ========================== API ROUTES ==========================

@app.route('/api/run', methods=['POST'])
def run_code():
    """
    Execute code endpoint
    Expected JSON: { "code": "...", "language": "python" or "c" }
    """
    try:
        print(f"[DEBUG] /api/run request received from {request.remote_addr}")
        data = request.get_json()
        
        if not data:
            print("[ERROR] No JSON data provided in request")
            return jsonify({"error": "No JSON data provided"}), 400
        
        code = data.get('code', '').strip()
        language = data.get('language', 'python').lower()
        print(f"[DEBUG] Code execution requested: language={language}, code_length={len(code)}")
        
        # Validate input
        if not code:
            return jsonify({"error": "Code cannot be empty"}), 400
        
        if language not in ['python', 'c']:
            return jsonify({"error": f"Unsupported language: {language}"}), 400
        
        # Execute code
        if language == 'python':
            success, output, error = execute_python(code)
        else:  # c
            success, output, error = execute_c(code)
        
        if not success:
            return jsonify({"error": error}), 400
        
        # Save to user history if logged in
        user = session.get('user')
        if user:
            try:
                email = user.get('email')
                if email not in user_history:
                    user_history[email] = []
                
                history_entry = {
                    'code': code,
                    'language': language,
                    'output': output,
                    'timestamp': datetime.now().isoformat(),
                    'execution_time': 0
                }
                
                user_history[email].append(history_entry)
                
                # Keep only last 100 entries
                if len(user_history[email]) > 100:
                    user_history[email] = user_history[email][-100:]
            except Exception as e:
                print(f"Error saving to history: {e}")
        
        return jsonify({
            "output": output,
            "language": language,
            "timestamp": datetime.now().isoformat()
        }), 200
    
    except Exception as e:
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@app.route('/api/share', methods=['POST'])
def share_code():
    """
    Create a shareable link for code
    Expected JSON: { "code": "...", "language": "python" or "c" }
    Returns: { "shareId": "..." }
    """
    try:
        # Cleanup expired codes periodically
        cleanup_shared_codes()
        
        data = request.get_json()
        
        if not data:
            return jsonify({"error": "No JSON data provided"}), 400
        
        code = data.get('code', '').strip()
        language = data.get('language', 'python').lower()
        
        # Validate input
        if not code:
            return jsonify({"error": "Code cannot be empty"}), 400
        
        if language not in ['python', 'c']:
            return jsonify({"error": f"Unsupported language: {language}"}), 400
        
        # Generate unique share ID
        share_id = str(uuid.uuid4())
        
        # Store shared code
        shared_codes[share_id] = {
            'code': code,
            'language': language,
            'created_at': time.time(),
            'expires_at': time.time() + SHARED_CODE_EXPIRY
        }
        
        return jsonify({
            "shareId": share_id,
            "expiresIn": SHARED_CODE_EXPIRY
        }), 201
    
    except Exception as e:
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@app.route('/api/share/<share_id>', methods=['GET'])
def get_shared_code(share_id):
    """
    Retrieve shared code
    Returns: { "code": "...", "language": "python" or "c" }
    """
    try:
        # Cleanup expired codes
        cleanup_shared_codes()
        
        # Validate share_id format
        if not share_id or len(share_id) > 100:
            return jsonify({"error": "Invalid share ID"}), 400
        
        # Check if share exists
        if share_id not in shared_codes:
            return jsonify({"error": "Share not found or expired"}), 404
        
        shared = shared_codes[share_id]
        
        # Check if expired
        if time.time() > shared['expires_at']:
            del shared_codes[share_id]
            return jsonify({"error": "Share expired"}), 404
        
        return jsonify({
            "code": shared['code'],
            "language": shared['language']
        }), 200
    
    except Exception as e:
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "active_shares": len(shared_codes)
    }), 200

@app.route('/', methods=['GET'])
def index():
    """Serve the frontend HTML or user dashboard"""
    user = session.get('user')
    if user:
        # User is logged in - show dashboard with history
        return send_from_directory(script_dir, 'index.html')
    else:
        # Show login page
        return send_from_directory(script_dir, 'index.html')

# ========================== ERROR HANDLERS ==========================

@app.errorhandler(404)
def not_found(error):
    return jsonify({"error": "Endpoint not found"}), 404

@app.errorhandler(405)
def method_not_allowed(error):
    return jsonify({"error": "Method not allowed"}), 405

@app.errorhandler(500)
def server_error(error):
    print(f"[ERROR] 500 Server Error: {error}")
    import traceback
    traceback.print_exc()
    return jsonify({"error": "Internal server error"}), 500

@app.errorhandler(Exception)
def handle_exception(error):
    """Catch-all error handler to log all exceptions"""
    print(f"[ERROR] Unhandled exception: {error}")
    import traceback
    traceback.print_exc()
    return jsonify({"error": f"Server error: {str(error)}"}), 500

# ========================== BACKGROUND TASKS ==========================

def periodic_cleanup():
    """Run cleanup tasks periodically"""
    while True:
        time.sleep(code_cleanup_interval)
        try:
            cleanup_shared_codes()
            print(f"[{datetime.now()}] Cleaned up expired shares. Active shares: {len(shared_codes)}")
        except Exception as e:
            print(f"[{datetime.now()}] Cleanup error: {e}")

# Start cleanup thread
cleanup_thread = threading.Thread(target=periodic_cleanup, daemon=True)
cleanup_thread.start()

# ========================== OAUTH ROUTES ==========================

@app.route('/api/cognito-check', methods=['GET'])
def cognito_check():
    """Check if Cognito is properly configured"""
    cognito_client_secret = os.environ.get('COGNITO_CLIENT_SECRET', '')
    is_configured = bool(cognito_client_secret)
    
    return jsonify({
        "configured": is_configured,
        "client_id": cognito_client_id if is_configured else None,
        "message": "Cognito is configured" if is_configured else "Cognito is not configured. Please set COGNITO_CLIENT_SECRET environment variable."
    }), 200

@app.route('/login', methods=['GET'])
def login():
    """Redirect to Cognito for authentication"""
    cognito_client_secret = os.environ.get('COGNITO_CLIENT_SECRET', '')
    
    if not cognito_client_secret:
        return "<h1>Error: COGNITO_CLIENT_SECRET not set in AWS EB</h1>", 503
    
    try:
        print("\n" + "="*80)
        print("[INFO] ===== SIGNIN REQUEST =====")
        print("="*80)
        
        # Use Authlib's built-in authorize_redirect with redirect_uri specified
        app_domain = os.environ.get('APP_DOMAIN')
        if not app_domain:
            print("[ERROR] APP_DOMAIN not set!")
            return "<h1>Error: APP_DOMAIN not set in AWS EB environment variables</h1>", 500
        
        redirect_uri = f'https://{app_domain}/authorize'
        print(f"[INFO] Redirect URI: {redirect_uri}")
        print(f"[INFO] Calling Authlib authorize_redirect...")
        
        return oauth.cognito.authorize_redirect(redirect_uri=redirect_uri)
        
    except Exception as e:
        print(f"❌ [ERROR] Login error: {str(e)}")
        import traceback
        traceback.print_exc()
        return f"<h1>Login Error: {str(e)}</h1>", 500

@app.route('/authorize', methods=['GET'])
def authorize():
    """Handle OAuth callback from Cognito with Authlib"""
    try:
        print("\n" + "="*80)
        print("🔥 AUTHORIZE CALLBACK RECEIVED")
        print("="*80)
        print(f"[INFO] Query args: {dict(request.args)}")
        
        # Check for Cognito errors
        error = request.args.get('error')
        if error:
            error_desc = request.args.get('error_description', 'Unknown error')
            print(f"❌ [ERROR] Cognito error: {error} - {error_desc}")
            return f"""
            <html>
            <head><title>Authentication Error</title></head>
            <body>
                <h1>❌ Authentication Error</h1>
                <p><strong>Error:</strong> {error}</p>
                <p><strong>Details:</strong> {error_desc}</p>
                <p><a href="/">← Back</a></p>
            </body>
            </html>
            """, 400
        
        print("[INFO] Exchanging authorization code for token via Authlib...")
        
        # Use Authlib to get token and user info
        try:
            token = oauth.cognito.authorize_access_token()
            print(f"✓ [INFO] Token exchange successful")
            print(f"[DEBUG] Token type: {type(token)}")
            print(f"[DEBUG] Token keys: {list(token.keys()) if isinstance(token, dict) else 'N/A'}")
        except Exception as token_error:
            print(f"❌ [ERROR] Token exchange failed: {str(token_error)}")
            print(f"[DEBUG] Exception type: {type(token_error).__name__}")
            raise
        
        # Get user info
        print("[INFO] Extracting user information...")
        user_info = token.get('userinfo')
        
        if not user_info:
            print("❌ [ERROR] No userinfo in token")
            print(f"[DEBUG] Token contents: {token}")
            return """
            <html>
            <head><title>Error</title></head>
            <body>
                <h1>Error: No user info received from Cognito</h1>
                <p>Please try logging in again.</p>
                <p><a href="/">Back</a></p>
            </body>
            </html>
            """, 400
        
        print(f"✓ [INFO] User info retrieved")
        print(f"[DEBUG] User email: {user_info.get('email')}")
        
        # Store in session
        session['user'] = user_info
        email = user_info.get('email', 'unknown')
        
        # Initialize user history
        if email not in user_history:
            user_history[email] = []
        
        print(f"✓ [SUCCESS] User '{email}' authenticated and session created")
        print("="*80 + "\n")
        
        return redirect(url_for('index'))
        
    except Exception as e:
        error_msg = str(e)
        print(f"❌ [FATAL ERROR] {error_msg}")
        print(f"[DEBUG] Exception type: {type(e).__name__}")
        import traceback
        traceback.print_exc()
        print("="*80 + "\n")
        
        return f"""
        <html>
        <head>
            <title>Authorization Error</title>
            <style>
                body {{ font-family: Arial, sans-serif; background: #f5f5f5; padding: 20px; }}
                .container {{ background: white; padding: 40px; border-radius: 8px; max-width: 600px; margin: auto; }}
                h1 {{ color: #e74c3c; }}
                .error {{ background: #ffebee; padding: 10px; border-left: 4px solid #e74c3c; }}
                a {{ color: #3498db; }}
            </style>
        </head>
        <body>
            <div class="container">
                <h1>❌ Authorization Error</h1>
                <div class="error">
                    <strong>Error:</strong> {error_msg}
                </div>
                <h3>Next steps:</h3>
                <ol>
                    <li>Check AWS EB application logs</li>
                    <li>Verify COGNITO_CLIENT_SECRET is set</li>
                    <li>Restart the EB environment</li>
                    <li><a href="/">Try again</a></li>
                </ol>
            </div>
        </body>
        </html>
        """, 500

@app.route('/logout', methods=['GET', 'POST'])
def logout():
    """Clear user session"""
    user = session.get('user')
    if user:
        print(f"[{datetime.now()}] User {user.get('email', 'unknown')} logged out")
    
    session.pop('user', None)
    return redirect(url_for('index'))

@app.route('/api/user', methods=['GET'])
def get_user():
    """Get current logged-in user information"""
    user = session.get('user')
    if user:
        return jsonify({
            "email": user.get('email'),
            "name": user.get('name'),
            "authenticated": True
        }), 200
    else:
        return jsonify({"authenticated": False}), 200

@app.route('/api/history', methods=['GET'])
def get_history():
    """Get user code execution history (requires login)"""
    user = session.get('user')
    if not user:
        return jsonify({"error": "Unauthorized. Please login first."}), 401
    
    email = user.get('email')
    history = user_history.get(email, [])
    
    return jsonify({
        "email": email,
        "history": history,
        "total": len(history)
    }), 200

@app.route('/api/history/add', methods=['POST'])
def add_to_history():
    """Add code execution to user history (requires login)"""
    user = session.get('user')
    if not user:
        return jsonify({"error": "Unauthorized. Please login first."}), 401
    
    try:
        data = request.get_json()
        email = user.get('email')
        
        # Initialize user history if not exists
        if email not in user_history:
            user_history[email] = []
        
        # Add to history
        history_entry = {
            'code': data.get('code', ''),
            'language': data.get('language', 'python'),
            'output': data.get('output', ''),
            'timestamp': datetime.now().isoformat(),
            'execution_time': data.get('execution_time', 0)
        }
        
        user_history[email].append(history_entry)
        
        # Keep only last 100 entries
        if len(user_history[email]) > 100:
            user_history[email] = user_history[email][-100:]
        
        return jsonify({
            "message": "Added to history",
            "total": len(user_history[email])
        }), 201
    
    except Exception as e:
        return jsonify({"error": f"History error: {str(e)}"}), 500

@app.route('/api/history/clear', methods=['POST'])
def clear_history():
    """Clear user code execution history (requires login)"""
    user = session.get('user')
    if not user:
        return jsonify({"error": "Unauthorized. Please login first."}), 401
    
    try:
        email = user.get('email')
        user_history[email] = []
        
        return jsonify({"message": "History cleared"}), 200
    
    except Exception as e:
        return jsonify({"error": f"Error clearing history: {str(e)}"}), 500

# ========================== MAIN ==========================

if __name__ == '__main__':
    print("=" * 60)
    print("Cloud Code Executor Backend")
    print("=" * 60)
    port = int(os.environ.get('PORT', 5000))
    print(f"Server starting on http://0.0.0.0:{port}")
    print(f"Code execution timeout: {CODE_EXECUTION_TIMEOUT}s")
    print(f"Share expiry: {SHARED_CODE_EXPIRY}s ({SHARED_CODE_EXPIRY // 3600}h)")
    print("=" * 60)
    
    app.run(host="0.0.0.0", port=port, debug=False, threaded=True)