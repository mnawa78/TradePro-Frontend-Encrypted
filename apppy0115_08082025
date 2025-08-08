# import eventlet
# eventlet.monkey_patch()
from gevent import monkey
monkey.patch_all()

import os
import json
import time
import requests
import logging
import secrets
import re
import base64
from flask import Flask, request, render_template, jsonify, abort, redirect, url_for, session, flash
from flask_socketio import SocketIO, emit, disconnect
from datetime import datetime, timedelta
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
import redis
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# at the very top of app.py
heartbeat_started = False

def spawn_heartbeat_once():
    global heartbeat_started
    if not heartbeat_started:
        app.logger.info("Spawning heartbeat background task")
        socketio.start_background_task(target=start_heartbeat_check)
        heartbeat_started = True

# ============================================================================
# ENCRYPTION SYSTEM FOR REDIS DATA
# ============================================================================

class RedisEncryption:
    """Handles encryption/decryption of sensitive data stored in Redis"""
    
    def __init__(self):
        self.fernet = None
        self._initialize_encryption()
    
    def _initialize_encryption(self):
        """Initialize encryption with key derived from environment variables"""
        # Get encryption password from environment (REQUIRED for production)
        encryption_password = os.environ.get("REDIS_ENCRYPTION_KEY")
        
        if not encryption_password:
            # For development only - generate a temporary key
            app.logger.warning("⚠️  REDIS_ENCRYPTION_KEY not set! Using temporary key for development.")
            app.logger.warning("⚠️  SET REDIS_ENCRYPTION_KEY environment variable for production!")
            encryption_password = "DEV_TEMPORARY_KEY_NOT_FOR_PRODUCTION_USE_12345"
        
        # Derive a proper encryption key from the password
        password_bytes = encryption_password.encode('utf-8')
        salt = b'tradepro_redis_salt_2025'  # Fixed salt for consistency
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        
        key = base64.urlsafe_b64encode(kdf.derive(password_bytes))
        self.fernet = Fernet(key)
        
        app.logger.info("✅ Redis encryption initialized successfully")
    
    def encrypt_data(self, data):
        """Encrypt data for Redis storage"""
        try:
            if isinstance(data, dict):
                data = json.dumps(data)
            elif not isinstance(data, str):
                data = str(data)
            
            encrypted_bytes = self.fernet.encrypt(data.encode('utf-8'))
            return base64.urlsafe_b64encode(encrypted_bytes).decode('utf-8')
            
        except Exception as e:
            app.logger.error(f"Encryption error: {e}")
            raise
    
    def decrypt_data(self, encrypted_data):
        """Decrypt data from Redis storage"""
        try:
            encrypted_bytes = base64.urlsafe_b64decode(encrypted_data.encode('utf-8'))
            decrypted_bytes = self.fernet.decrypt(encrypted_bytes)
            return decrypted_bytes.decode('utf-8')
            
        except Exception as e:
            app.logger.error(f"Decryption error: {e}")
            raise

# Initialize encryption system
redis_encryption = None

# pick up the Redis Cloud URL from Heroku config
REDIS_URL = os.environ.get("REDISCLOUD_URL")
redis_client = redis.from_url(REDIS_URL, decode_responses=True)

# ============================================================================
# ENCRYPTED REDIS STORAGE FUNCTIONS
# ============================================================================

def save_users():
    """Save users database to Redis with encryption"""
    try:
        encrypted_data = {}
        for username, user_data in users_db.items():
            # Encrypt each user's data individually
            encrypted_user_data = redis_encryption.encrypt_data(user_data)
            encrypted_data[username] = encrypted_user_data
        
        # Store encrypted data in Redis
        redis_client.delete("users_database_encrypted")  # Clear old data
        if encrypted_data:
            redis_client.hset("users_database_encrypted", mapping=encrypted_data)
        
        app.logger.info(f"✅ Saved {len(users_db)} encrypted users to Redis")
        
    except Exception as e:
        app.logger.error(f"❌ Error saving encrypted users to Redis: {e}")
        raise

def load_users():
    """Load and decrypt users database from Redis"""
    try:
        encrypted_data = redis_client.hgetall("users_database_encrypted")
        
        if not encrypted_data:
            app.logger.info("No encrypted users found in Redis, starting with empty database")
            return {}
        
        # Decrypt each user's data
        decrypted_users = {}
        for username, encrypted_user_data in encrypted_data.items():
            try:
                decrypted_json = redis_encryption.decrypt_data(encrypted_user_data)
                user_data = json.loads(decrypted_json)
                decrypted_users[username] = user_data
            except Exception as e:
                app.logger.error(f"❌ Failed to decrypt user data for {username}: {e}")
                continue
        
        app.logger.info(f"✅ Loaded {len(decrypted_users)} encrypted users from Redis")
        return decrypted_users
        
    except Exception as e:
        app.logger.error(f"❌ Error loading encrypted users from Redis: {e}")
        return {}

def save_webhook_tokens():
    """Save webhook tokens to Redis with encryption"""
    try:
        encrypted_data = {}
        for token, token_data in webhook_tokens.items():
            # Encrypt each token's metadata (but keep token itself as key)
            encrypted_token_data = redis_encryption.encrypt_data(token_data)
            encrypted_data[token] = encrypted_token_data
        
        # Store encrypted data in Redis
        redis_client.delete("webhook_tokens_encrypted")  # Clear old data
        if encrypted_data:
            redis_client.hset("webhook_tokens_encrypted", mapping=encrypted_data)
        
        app.logger.info(f"✅ Saved {len(webhook_tokens)} encrypted webhook tokens to Redis")
        
    except Exception as e:
        app.logger.error(f"❌ Error saving encrypted webhook tokens to Redis: {e}")
        raise

def load_webhook_tokens():
    """Load and decrypt webhook tokens from Redis"""
    try:
        encrypted_data = redis_client.hgetall("webhook_tokens_encrypted")
        
        if not encrypted_data:
            app.logger.info("No encrypted webhook tokens found in Redis, starting with empty database")
            return {}
        
        # Decrypt each token's metadata
        decrypted_tokens = {}
        for token, encrypted_token_data in encrypted_data.items():
            try:
                decrypted_json = redis_encryption.decrypt_data(encrypted_token_data)
                token_data = json.loads(decrypted_json)
                decrypted_tokens[token] = token_data
            except Exception as e:
                app.logger.error(f"❌ Failed to decrypt webhook token data for {token}: {e}")
                continue
        
        app.logger.info(f"✅ Loaded {len(decrypted_tokens)} encrypted webhook tokens from Redis")
        return decrypted_tokens
        
    except Exception as e:
        app.logger.error(f"❌ Error loading encrypted webhook tokens from Redis: {e}")
        return {}

def save_params(params: dict):
    """Save the last-connection params into Redis with encryption"""
    try:
        encrypted_params = redis_encryption.encrypt_data(params)
        redis_client.set("last_connection_params_encrypted", encrypted_params)
        app.logger.info("✅ Saved encrypted connection params to Redis")
    except Exception as e:
        app.logger.error(f"❌ Error saving encrypted connection params: {e}")

def load_params() -> dict:
    """Load and decrypt connection params from Redis. Returns {} if none."""
    try:
        encrypted_data = redis_client.get("last_connection_params_encrypted")
        if not encrypted_data:
            return {}
        
        decrypted_json = redis_encryption.decrypt_data(encrypted_data)
        params = json.loads(decrypted_json)
        app.logger.info("✅ Loaded encrypted connection params from Redis")
        return params
        
    except Exception as e:
        app.logger.error(f"❌ Error loading encrypted connection params: {e}")
        return {}

# ============================================================================
# FLASK APPLICATION SETUP
# ============================================================================

# Configure enhanced logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - [%(filename)s:%(lineno)d] - %(message)s'
)

app = Flask(__name__)
# Use environment variable for secret key with a fallback
app.config['SECRET_KEY'] = os.environ.get("SECRET_KEY", secrets.token_hex(32))

# Improved SocketIO configuration with reconnection settings
socketio = SocketIO(
    app, 
    async_mode=None,  # Let Flask-SocketIO choose the best mode
    cors_allowed_origins='*',
    ping_timeout=60,
    ping_interval=25,
    reconnection=True,
    reconnection_attempts=5,
    reconnection_delay=1,
    reconnection_delay_max=10
)

# Configuration from Heroku config vars
CONNECTOR_URL = os.environ.get("CONNECTOR_URL")
CONNECTOR_API_KEY = os.environ.get("CONNECTOR_API_KEY")
# Timeout configuration - can be adjusted via environment variables
DEFAULT_TIMEOUT = int(os.environ.get("DEFAULT_TIMEOUT", 60))
# Max consecutive heartbeat failures before considering disconnected
MAX_HEARTBEAT_FAILURES = int(os.environ.get("MAX_HEARTBEAT_FAILURES", 3))

# Global state tracking with separated concerns
connection_state = {
    "ibkr_connected": False,        # True when backend reports IBKR is connected
    "last_backend_heartbeat": None, # Last successful backend heartbeat
    "heartbeat_failures": 0,        # Count of consecutive failures
    "reconnect_in_progress": False, # Whether auto-reconnect is in progress
    "last_ibkr_status": None        # Last known IBKR connection status from backend
}

# Socket connection is tracked separately
socket_state = {
    "connected": False,             # Current socket.io connection status
    "last_connected": None,         # When socket was last connected
    "clients": set()                # Set of connected socket client IDs
}

# User database and webhook tokens (will be loaded from encrypted Redis)
users_db = {}
webhook_tokens = {}

# Helper function for custom domain webhook URLs
def get_webhook_base_url():
    """Get the base URL for webhooks - custom domain if available, otherwise Heroku URL"""
    custom_domain = os.environ.get("CUSTOM_DOMAIN")
    if custom_domain:
        return f"https://{custom_domain}"
    else:
        return request.host_url.rstrip('/')

# Authentication decorator for routes that require login
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

# Initialize admin user and load encrypted data from Redis
@app.before_first_request
def initialize_admin_user():
    global users_db, webhook_tokens, redis_encryption
    
    # Initialize encryption system first
    redis_encryption = RedisEncryption()
    
    # Load existing encrypted data from Redis FIRST
    users_db = load_users()
    webhook_tokens = load_webhook_tokens()
    
    # Only create admin user if it doesn't exist in Redis
    admin_username = os.environ.get("ADMIN_USERNAME")
    admin_password = os.environ.get("ADMIN_PASSWORD")
    
    if admin_username and admin_password and admin_username not in users_db:
        app.logger.info(f"Creating new admin user: {admin_username}")
        users_db[admin_username] = {
            "password_hash": generate_password_hash(admin_password),
            "is_admin": True,
            "created_at": datetime.now().isoformat()
        }
        save_users()  # Save encrypted to Redis
    else:
        app.logger.info(f"Admin user already exists or not configured")
    
    # DO NOT create default webhook token (Option 2/3 implementation)
    # Customer will create their own tokens
    
    # Start heartbeat once
    spawn_heartbeat_once()

# ============================================================================
# USER MANAGEMENT ROUTES
# ============================================================================

@app.route('/login', methods=['GET', 'POST'])
def login():
    # If already logged in, redirect to index
    if 'user_id' in session:
        return redirect(url_for('index'))
        
    error = None
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if username in users_db and check_password_hash(users_db[username]['password_hash'], password):
            session.permanent = True  # Make session permanent for 24/7 operation
            session['user_id'] = username
            session['is_admin'] = users_db[username].get('is_admin', False)
            
            app.logger.info(f"User logged in: {username}")
            next_page = request.args.get('next', url_for('index'))
            return redirect(next_page)
        else:
            error = "Invalid username or password"
            app.logger.warning(f"Failed login attempt for user: {username}")
    
    return render_template('login.html', error=error)

@app.route('/logout')
def logout():
    username = session.get('user_id', 'Unknown')
    session.clear()
    app.logger.info(f"User logged out: {username}")
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

@app.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    error = None
    success = None
    
    if request.method == 'POST':
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')
        
        username = session['user_id']
        
        # Verify current password
        if not check_password_hash(users_db[username]['password_hash'], current_password):
            error = "Current password is incorrect"
        elif new_password != confirm_password:
            error = "New passwords do not match"
        elif len(new_password) < 8:
            error = "Password must be at least 8 characters long"
        else:
            # Update password
            users_db[username]['password_hash'] = generate_password_hash(new_password)
            users_db[username]['password_updated_at'] = datetime.now().isoformat()
            save_users()  # Save encrypted to Redis
            success = "Password changed successfully"
            app.logger.info(f"Password changed for user: {username}")
    
    return render_template('change_password.html', error=error, success=success)

# Admin routes for user management
@app.route('/admin/users', methods=['GET'])
@login_required
def admin_users():
    if not session.get('is_admin', False):
        flash('You do not have permission to access this page.', 'danger')
        return redirect(url_for('index'))
    
    return render_template('admin_users.html', users=users_db)

@app.route('/admin/add_user', methods=['GET', 'POST'])
@login_required
def add_user():
    if not session.get('is_admin', False):
        flash('You do not have permission to access this page.', 'danger')
        return redirect(url_for('index'))
    
    error = None
    success = None
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        is_admin = 'is_admin' in request.form
        
        if username in users_db:
            error = f"Username '{username}' already exists"
        elif len(password) < 8:
            error = "Password must be at least 8 characters long"
        else:
            users_db[username] = {
                "password_hash": generate_password_hash(password),
                "is_admin": is_admin,
                "created_at": datetime.now().isoformat(),
                "created_by": session['user_id']
            }
            save_users()  # Save encrypted to Redis
            success = f"User '{username}' created successfully"
            app.logger.info(f"New user created: {username} by {session['user_id']}")
    
    return render_template('add_user.html', error=error, success=success)

@app.route('/admin/delete_user/<username>', methods=['POST'])
@login_required
def delete_user(username):
    if not session.get('is_admin', False):
        flash('You do not have permission to perform this action.', 'danger')
        return redirect(url_for('index'))
    
    if username == session['user_id']:
        flash('You cannot delete your own account.', 'danger')
    elif username in users_db:
        del users_db[username]
        save_users()  # Save encrypted to Redis
        flash(f"User '{username}' deleted successfully.", 'success')
        app.logger.info(f"User deleted: {username} by {session['user_id']}")
    else:
        flash(f"User '{username}' not found.", 'danger')
    
    return redirect(url_for('admin_users'))

# ============================================================================
# WEBHOOK TOKEN MANAGEMENT
# ============================================================================

@app.route('/admin/webhook_tokens', methods=['GET'])
@login_required
def admin_webhook_tokens():
    if not session.get('is_admin', False):
        flash('You do not have permission to access this page.', 'danger')
        return redirect(url_for('index'))
    
    # Generate full webhook URLs for each token using custom domain if available
    webhook_urls = {}
    base_url = get_webhook_base_url()
    for token, details in webhook_tokens.items():
        webhook_urls[token] = f"{base_url}/webhook/{token}"
    
    return render_template('admin_webhook_tokens.html', webhook_tokens=webhook_tokens, webhook_urls=webhook_urls)

@app.route('/admin/generate_webhook_token', methods=['GET', 'POST'])
@login_required
def generate_webhook_token():
    if not session.get('is_admin', False):
        flash('You do not have permission to access this page.', 'danger')
        return redirect(url_for('index'))
    
    error = None
    success = None
    new_token = None
    webhook_url = None
    
    if request.method == 'POST':
        token_name = request.form.get('token_name')
        
        if not token_name:
            error = "Token name is required"
        else:
            # Generate a secure webhook token
            new_token = secrets.token_hex(16)
            webhook_tokens[new_token] = {
                "name": token_name,
                "created_at": datetime.now().isoformat(),
                "created_by": session['user_id']
            }
            save_webhook_tokens()  # Save encrypted to Redis
            webhook_url = get_webhook_base_url() + f"/webhook/{new_token}"
            success = "Webhook token created successfully"
            app.logger.info(f"New webhook token created: {token_name} by {session['user_id']}")
    
    return render_template('generate_webhook_token.html', error=error, success=success, new_token=new_token, webhook_url=webhook_url)

@app.route('/admin/delete_webhook_token/<token>', methods=['POST'])
@login_required
def delete_webhook_token(token):
    if not session.get('is_admin', False):
        flash('You do not have permission to perform this action.', 'danger')
        return redirect(url_for('index'))
    
    if token in webhook_tokens:
        token_name = webhook_tokens[token]['name']
        del webhook_tokens[token]
        save_webhook_tokens()  # Save encrypted to Redis
        flash(f"Webhook token '{token_name}' deleted successfully.", 'success')
        app.logger.info(f"Webhook token deleted: {token_name} by {session['user_id']}")
    else:
        flash("Webhook token not found.", 'danger')
    
    return redirect(url_for('admin_webhook_tokens'))

# ============================================================================
# MAIN APPLICATION ROUTES
# ============================================================================

@app.route('/')
@login_required
def index():
    # Get the default webhook URL (first token or empty string) using custom domain if available
    default_token = next(iter(webhook_tokens.keys()), "")
    webhook_url = get_webhook_base_url() + f"/webhook/{default_token}" if default_token else ""
    
    app.logger.info(f"Serving index page. Webhook URL: {webhook_url}")
    return render_template('index.html', webhook_url=webhook_url, username=session.get('user_id', 'User'))

def send_backend_request(endpoint, method="POST", json_data=None, form_data=None, timeout=None):
    """Centralized function to handle backend requests with proper error handling"""
    if timeout is None:
        timeout = DEFAULT_TIMEOUT
    
    url = f"{CONNECTOR_URL}/{endpoint}"
    headers = {}
    if CONNECTOR_API_KEY:
        headers['X-API-KEY'] = CONNECTOR_API_KEY

    app.logger.info(f"Sending {method} request to backend: {url}")
    
    try:
        if method.upper() == "POST":
            if json_data is not None:
                response = requests.post(url, json=json_data, headers=headers, timeout=timeout)
            elif form_data is not None:
                response = requests.post(url, data=form_data, headers=headers, timeout=timeout)
            else:
                response = requests.post(url, headers=headers, timeout=timeout)
        else:
            response = requests.get(url, headers=headers, timeout=timeout)

        response.raise_for_status()
        return response.json(), None
    
    except requests.exceptions.Timeout:
        error_msg = f"Request to backend timed out after {timeout}s."
        app.logger.error(error_msg)
        return None, {"error": error_msg, "status_code": 504}
    except requests.exceptions.ConnectionError:
        error_msg = "Failed to connect to backend server. Please check if it's running."
        app.logger.error(error_msg)
        return None, {"error": error_msg, "status_code": 502}
    except requests.exceptions.RequestException as e:
        error_msg = f"Request failed: {str(e)}"
        status_code = getattr(e.response, 'status_code', 500) if hasattr(e, 'response') else 500
        app.logger.error(error_msg)
        return None, {"error": error_msg, "status_code": status_code}
    except Exception as e:
        error_msg = f"Unexpected error: {str(e)}"
        app.logger.error(error_msg, exc_info=True)
        return None, {"error": error_msg, "status_code": 500}

@app.route('/connect', methods=['POST'])
@login_required
def connect_route():
    app.logger.info("Received request on /connect route")

    # Read the HTML form
    data = request.form
    payload = {
        "ip":           data.get("ip"),
        "user_id":      data.get("user_id"),
        "account_type": data.get("account_type")
    }

    # Reject if any field is missing
    missing_fields = [f for f, v in payload.items() if not v]
    if missing_fields:
        error_msg = f"Missing required fields: {', '.join(missing_fields)}"
        app.logger.warning(f"Connection request missing fields: {error_msg}")
        socketio.emit('connection_status', {
            "success": False,
            "message": error_msg,
            "socket_connected": socket_state["connected"]
        })
        return jsonify({"success": False, "message": error_msg}), 400

    # Forward to IBKR-connector as JSON
    result, error = send_backend_request("connect", json_data=payload)
    if error:
        app.logger.error(f"IBKR connector rejected /connect: {error['error']}")
        socketio.emit('connection_status', {
            "success": False,
            "message": error["error"],
            "socket_connected": socket_state["connected"]
        })
        return jsonify({"success": False, "message": error["error"]}), error["status_code"]

    # Persist encrypted connection params to Redis for auto-reconnect
    save_params(payload)
    app.logger.info(f"Saved encrypted connection params to Redis: {payload!r}")

    # Tell the front-end it worked
    socketio.emit('connection_status', {
        "success": True,
        "message": result.get("message", "Connected successfully."),
        "socket_connected": socket_state["connected"]
    })
    return jsonify(result), 200

@app.route('/disconnect', methods=['POST'])
@login_required
def disconnect_route():
    app.logger.info("Received request on /disconnect route")
    
    # Make the backend request
    result, error = send_backend_request("disconnect")
    
    if error:
        socketio.emit('connection_status', {
            "success": False, 
            "message": error['error'],
            "socket_connected": socket_state["connected"]
        })
        return jsonify({"success": False, "message": error['error']}), error['status_code']
    
    # Update connection state
    connection_state["ibkr_connected"] = False
    connection_state["last_ibkr_status"] = False
    
    # Add socket_connected to the status
    result["socket_connected"] = socket_state["connected"]
    socketio.emit('connection_status', result)
    
    return jsonify(result)

# Modified webhook route to use token in URL instead of header
@app.route('/webhook/<token>', methods=['POST'])
def webhook_receiver(token):
    # Validate the token
    if token not in webhook_tokens:
        app.logger.warning(f"Unauthorized webhook attempt with invalid token: {token}")
        return jsonify({"error": "Unauthorized. Invalid webhook token."}), 401
        
    data = request.json
    if not data:
        app.logger.warning("Received invalid data on /webhook")
        socketio.emit('webhook_error', {"message": "Invalid webhook data received"})
        return "Invalid data", 400

    app.logger.info(f"[WEBHOOK] Received data: {json.dumps(data)}")
    socketio.emit('new_webhook', data)

    # Save order in memory in case we need to retry
    order_id = data.get('ORDER_ID', str(time.time()))
    socketio.emit('order_status', {
        "order_id": order_id,
        "status": "received",
        "message": "Order received, forwarding to backend"
    })

    # Forward to backend
    result, error = send_backend_request("order", json_data=data)
    
    if error:
        error_msg = f"Error forwarding order: {error['error']}"
        app.logger.error(error_msg)
        socketio.emit('order_status', {
            "order_id": order_id,
            "status": "failed",
            "message": error_msg
        })
        return error_msg, error['status_code']
    
    # Success
    socketio.emit('order_status', {
        "order_id": order_id,
        "status": "processed",
        "message": "Order successfully processed by backend",
        "details": result
    })
    
    return "Webhook received and processed successfully", 200

@app.route('/webhook', methods=['POST'])
def webhook_legacy():
    app.logger.warning("Received request to deprecated webhook URL without token")
    return jsonify({
        "error": "This webhook URL is deprecated. Please use the new URL format with your authentication token."
    }), 403

@app.route('/status', methods=['GET'])
@login_required
def status():
    """Check connection status with backend"""
    if not CONNECTOR_URL:
        return jsonify({
            "frontend": "running",
            "backend_configured": False,
            "message": "Backend URL not configured",
            "socket_connected": socket_state["connected"]
        })
    
    try:
        result, error = send_backend_request("heartbeat", method="GET", timeout=5)
        backend_status = "running" if not error else "unreachable"
        
        # If backend is reachable, also get the IBKR status
        ibkr_status = connection_state["ibkr_connected"]
        if not error and backend_status == "running":
            # Try to get the current IBKR status from backend
            ibkr_result, ibkr_error = send_backend_request("heartbeat", method="GET", timeout=5)
            if not ibkr_error and ibkr_result and "connected_to_ibkr" in ibkr_result:
                ibkr_status = ibkr_result["connected_to_ibkr"]
                # Update our state if it's different
                if connection_state["ibkr_connected"] != ibkr_status:
                    connection_state["ibkr_connected"] = ibkr_status
                    connection_state["last_ibkr_status"] = ibkr_status
        
        return jsonify({
            "frontend": "running",
            "backend": backend_status,
            "backend_configured": True,
            "connected_to_ibkr": ibkr_status,
            "last_heartbeat": connection_state["last_backend_heartbeat"].isoformat() if connection_state["last_backend_heartbeat"] else None,
            "heartbeat_failures": connection_state["heartbeat_failures"],
            "reconnect_in_progress": connection_state["reconnect_in_progress"],
            "socket_connected": socket_state["connected"],
            "socket_clients": len(socket_state["clients"])
        })
    except Exception as e:
        app.logger.error(f"Status check error: {str(e)}")
        return jsonify({
            "frontend": "running",
            "backend": "error",
            "backend_configured": True,
            "connected_to_ibkr": connection_state["ibkr_connected"],
            "heartbeat_failures": connection_state["heartbeat_failures"],
            "error": str(e),
            "socket_connected": socket_state["connected"]
        })

# Enhanced heartbeat route to include IBKR status
@app.route('/heartbeat', methods=['GET'])
def heartbeat():
    """Enhanced endpoint to check server heartbeat and IBKR status"""
    try:
        # Get IBKR connection status from backend if possible
        result, error = send_backend_request("heartbeat", method="GET", timeout=5)
        ibkr_connected = False
        
        if not error and result and "connected_to_ibkr" in result:
            ibkr_connected = result["connected_to_ibkr"]
            # Update our internal state if it's different
            if connection_state["ibkr_connected"] != ibkr_connected:
                connection_state["ibkr_connected"] = ibkr_connected
                connection_state["last_ibkr_status"] = ibkr_connected
        else:
            # Use our internal state if we can't get from backend
            ibkr_connected = connection_state["ibkr_connected"]
        
        return jsonify({
            "status": "alive", 
            "timestamp": datetime.now().isoformat(),
            "connected_to_ibkr": ibkr_connected
        })
    except Exception as e:
        app.logger.error(f"Heartbeat error: {str(e)}")
        return jsonify({
            "status": "error",
            "timestamp": datetime.now().isoformat(),
            "connected_to_ibkr": connection_state["ibkr_connected"],
            "error": str(e)
        })

# Add new monitoring endpoint for UptimeRobot
@app.route('/monitor', methods=['GET'])
def monitor():
    """Dedicated endpoint for external monitoring services"""
    try:
        # Check IBKR connection status
        ibkr_connected = connection_state["ibkr_connected"]
        
        # Return HTTP error when IBKR disconnected
        if not ibkr_connected:
            return jsonify({
                "status": "ibkr_disconnected",
                "timestamp": datetime.now().isoformat()
            }), 503  # HTTP error for UptimeRobot
        
        # Return HTTP 200 when IBKR connected
        return jsonify({
            "status": "monitoring_ok",
            "timestamp": datetime.now().isoformat()
        })
        
    except Exception as e:
        return jsonify({
            "status": "error",
            "error": str(e)
        }), 500

# ============================================================================
# HEARTBEAT AND RECONNECTION SYSTEM
# ============================================================================

def heartbeat_check():
    """Enhanced background task to periodically check backend connectivity with focus on IBKR status"""
    while True:  # Always keep running, don't depend on connection_state["ibkr_connected"]
        try:
            result, error = send_backend_request("heartbeat", method="GET", timeout=5)
            
            if not error and result:
                # Update last backend heartbeat timestamp
                connection_state["last_backend_heartbeat"] = datetime.now()
                
                # Check for IBKR status from backend response
                # The backend should return 'connected_to_ibkr' in its response
                ibkr_status = False
                if "connected_to_ibkr" in result:
                    ibkr_status = result["connected_to_ibkr"]
                    
                    # Only update the UI if the status has changed
                    if connection_state["last_ibkr_status"] != ibkr_status:
                        app.logger.info(f"IBKR connection status changed: {connection_state['last_ibkr_status']} -> {ibkr_status}")
                        connection_state["ibkr_connected"] = ibkr_status
                        connection_state["last_ibkr_status"] = ibkr_status
                        
                        # Broadcast status change to all connected clients
                        socketio.emit('connection_status', {
                            "success": ibkr_status,
                            "message": "Connected to IBKR" if ibkr_status else "Not Connected to IBKR",
                            "reconnect_in_progress": connection_state["reconnect_in_progress"],
                            "socket_connected": socket_state["connected"]
                        })
                
                # IMPORTANT CHANGE: Only reset heartbeat failures if both backend and IBKR are connected
                if ibkr_status:
                    connection_state["heartbeat_failures"] = 0
                else:
                    # Increment failures if IBKR is disconnected
                    app.logger.warning("Backend is reachable but IBKR is disconnected")
                    connection_state["heartbeat_failures"] += 1
                
                socketio.emit('heartbeat', {
                    "status": "alive",
                    "timestamp": connection_state["last_backend_heartbeat"].isoformat(),
                    "ibkr_connected": ibkr_status
                })
            else:
                connection_state["heartbeat_failures"] += 1
                app.logger.warning(f"Heartbeat failure #{connection_state['heartbeat_failures']}: {error['error'] if error else 'Unknown error'}")
                
                socketio.emit('heartbeat', {
                    "status": "warning",
                    "error": error['error'] if error else "Unknown error",
                    "consecutive_failures": connection_state["heartbeat_failures"],
                    "max_failures": MAX_HEARTBEAT_FAILURES,
                    "ibkr_connected": connection_state["ibkr_connected"]  # Keep previous status
                })
            
            # Try to reconnect if either the backend is unreachable OR IBKR is disconnected
            # after multiple consecutive failures
            if connection_state["heartbeat_failures"] >= MAX_HEARTBEAT_FAILURES and not connection_state["reconnect_in_progress"]:
                app.logger.error(f"Maximum heartbeat failures reached ({MAX_HEARTBEAT_FAILURES}). Attempting verification...")
                verify_and_reconnect()
            
        except Exception as e:
            connection_state["heartbeat_failures"] += 1
            app.logger.error(f"Heartbeat check exception: {str(e)}")
            
            socketio.emit('heartbeat', {
                "status": "error",
                "error": str(e),
                "consecutive_failures": connection_state["heartbeat_failures"],
                "max_failures": MAX_HEARTBEAT_FAILURES,
                "ibkr_connected": connection_state["ibkr_connected"]  # Keep previous status
            })
            
            if connection_state["heartbeat_failures"] >= MAX_HEARTBEAT_FAILURES and not connection_state["reconnect_in_progress"]:
                app.logger.error(f"Maximum heartbeat failures reached ({MAX_HEARTBEAT_FAILURES}). Attempting verification...")
                verify_and_reconnect()
        
        # Wait before next check - should be at least 30 seconds to avoid too frequent checks
        socketio.sleep(30)

def start_heartbeat_check():
    """Start the continuous heartbeat check without the reconnection logic"""
    socketio.start_background_task(target=heartbeat_check)

def verify_and_reconnect():
    """Verify IBKR connection and attempt reconnection if needed"""
    # Only proceed if we're not already trying to reconnect
    if connection_state["reconnect_in_progress"]:
        return
        
    connection_state["reconnect_in_progress"] = True
    socketio.emit('connection_status', {
        "success": connection_state["ibkr_connected"],
        "message": "Verifying connection status...",
        "verifying": True,
        "socket_connected": socket_state["connected"]
    })
    
    try:
        # Check if backend is still alive
        backend_result, backend_error = send_backend_request("heartbeat", method="GET", timeout=10)
        
        if not backend_error:
            # Backend is responding, try to check actual connection status
            verify_result, verify_error = send_backend_request(
                "heartbeat",
                method="GET",
                timeout=10
            )
            
            if not verify_error and verify_result:
                # Get the actual IBKR connection status
                ibkr_status = verify_result.get('connected', False)
                
                # Update our connection status
                connection_state["ibkr_connected"] = ibkr_status
                connection_state["last_ibkr_status"] = ibkr_status
                
                if ibkr_status:
                    # We're actually still connected! Reset the heartbeat failure counter
                    app.logger.info("Connection verification successful - IBKR is connected!")
                    connection_state["heartbeat_failures"] = 0
                    connection_state["last_backend_heartbeat"] = datetime.now()
                    connection_state["reconnect_in_progress"] = False
                    
                    socketio.emit('connection_status', {
                        "success": True,
                        "message": "IBKR connection verified successfully",
                        "verified": True,
                        "socket_connected": socket_state["connected"]
                    })
                    return
                else:
                    # IBKR is not connected according to backend
                    app.logger.warning("Backend reports IBKR is not connected. Trying to reconnect...")
                    try_reconnect()
            else:
                # Verification failed
                app.logger.warning(f"IBKR connection verification failed with error: {verify_error['error'] if verify_error else 'Unknown error'}")
                try_reconnect()
        else:
            app.logger.warning(f"Backend verification failed with error: {backend_error['error']}")
            # Backend is unreachable, but we'll try reconnecting anyway
            try_reconnect()
            
    except Exception as e:
        app.logger.error(f"Connection verification failed: {str(e)}")
        try_reconnect()
    finally:
        # Make sure we reset the reconnect flag if something went wrong
        if connection_state["reconnect_in_progress"]:
            connection_state["reconnect_in_progress"] = False

def try_reconnect():
    """Attempt to reconnect to backend using stored encrypted connection parameters"""
    if not connection_state["reconnect_in_progress"]:
        connection_state["reconnect_in_progress"] = True
    
    socketio.emit('connection_status', {
        "success": connection_state["ibkr_connected"],
        "message": "Connection lost or unstable. Attempting to reconnect...",
        "reconnecting": True,
        "socket_connected": socket_state["connected"]
    })
    
    # Load the encrypted params we saved earlier
    params = load_params()
    if not params:
        app.logger.warning("Cannot auto-reconnect: no stored connection parameters in Redis")
        connection_state["reconnect_in_progress"] = False
        socketio.emit('connection_status', {
            "success": False,
            "message": "Cannot auto-reconnect: no stored connection parameters",
            "reconnecting": False,
            "socket_connected": socket_state["connected"]
        })
        return

    # Attempt to reconnect using the stored parameters
    app.logger.info(f"Attempting automatic reconnect with stored parameters: {params!r}")
    result, error = send_backend_request(
        "connect",
        method="POST",
        json_data=params
    )

    if error:
        app.logger.error(f"Auto-reconnect failed: {error['error']}")
        connection_state["reconnect_in_progress"] = False
        socketio.emit('connection_status', {
            "success": connection_state["ibkr_connected"],  # Keep previous status
            "message": f"Auto-reconnect failed: {error['error']}",
            "reconnecting": False,
            "socket_connected": socket_state["connected"]
        })
    elif result and result.get('success'):
        app.logger.info("Auto-reconnect successful!")
        connection_state["ibkr_connected"] = True
        connection_state["last_ibkr_status"] = True
        connection_state["last_backend_heartbeat"] = datetime.now()
        connection_state["heartbeat_failures"] = 0
        connection_state["reconnect_in_progress"] = False
        
        socketio.emit('connection_status', {
            "success": True,
            "message": "Auto-reconnect successful",
            "reconnected": True,
            "socket_connected": socket_state["connected"]
        })
    else:
        app.logger.warning(f"Auto-reconnect received unexpected response: {json.dumps(result)}")
        connection_state["reconnect_in_progress"] = False
        socketio.emit('connection_status', {
            "success": connection_state["ibkr_connected"],  # Keep previous status
            "message": "Auto-reconnect failed with unexpected response from backend",
            "reconnecting": False,
            "socket_connected": socket_state["connected"],
            "details": result
        })

# ============================================================================
# SOCKET.IO EVENT HANDLERS
# ============================================================================

@socketio.on('connect')
def socket_connect():
    app.logger.info(f"Socket.IO client connected: {request.sid}")
    
    # Check if user is logged in (for authenticated sockets)
    if 'user_id' not in session:
        app.logger.warning(f"Unauthenticated socket connection attempt: {request.sid}")
        disconnect()
        return
    
    # Update socket state
    socket_state["connected"] = True
    socket_state["last_connected"] = datetime.now()
    socket_state["clients"].add(request.sid)

@socketio.on('disconnect')
def socket_disconnect():
    app.logger.info(f"Socket.IO client disconnected: {request.sid}")
    # Remove client from tracked clients
    if request.sid in socket_state["clients"]:
        socket_state["clients"].remove(request.sid)
    
    # Update socket state
    if len(socket_state["clients"]) == 0:
        socket_state["connected"] = False

@socketio.on('force_reconnect')
def force_reconnect():
    """Handle manual reconnect request from client"""
    # Check if user is logged in
    if 'user_id' not in session:
        app.logger.warning(f"Unauthenticated socket reconnect attempt: {request.sid}")
        disconnect()
        return
        
    app.logger.info(f"Manual reconnect requested by client: {request.sid}")
    if not connection_state["reconnect_in_progress"]:
        socketio.emit('connection_status', {
            "success": connection_state["ibkr_connected"],
            "message": "Initiating reconnection...",
            "reconnecting": True,
            "socket_connected": socket_state["connected"]
        })
        socketio.start_background_task(target=verify_and_reconnect)
    else:
        emit('connection_status', {
            "success": connection_state["ibkr_connected"],
            "message": "Reconnection already in progress",
            "reconnecting": True,
            "socket_connected": socket_state["connected"]
        })

@socketio.on_error()
def error_handler(e):
    app.logger.error(f"Socket.IO error: {str(e)}")

# ============================================================================
# ADDITIONAL UTILITY ROUTES
# ============================================================================

@app.route('/backend_heartbeat', methods=['GET'])
def backend_heartbeat():
    """Check if backend is responsive"""
    try:
        # Try to connect to backend with a short timeout
        result, error = send_backend_request("heartbeat", method="GET", timeout=5)
        if error:
            return jsonify({
                "status": "unreachable",
                "error": error['error']
            }), 503
        return jsonify({
            "status": "reachable",
            "backend_response": result
        })
    except Exception as e:
        app.logger.error(f"Backend heartbeat check failed: {str(e)}")
        return jsonify({
            "status": "error",
            "error": str(e)
        }), 500

@app.route('/reset_heartbeat_failures', methods=['POST'])
@login_required
def reset_heartbeat_failures():
    """Manually reset heartbeat failures counter"""
    connection_state["heartbeat_failures"] = 0
    app.logger.info("Heartbeat failures counter manually reset")
    return jsonify({
        "success": True,
        "message": "Heartbeat failures counter reset",
        "heartbeat_failures": connection_state["heartbeat_failures"]
    })

# ============================================================================
# ADMIN UTILITIES FOR ENCRYPTED DATA MANAGEMENT
# ============================================================================

@app.route('/admin/clear_encrypted_data', methods=['POST'])
@login_required
def clear_encrypted_data():
    """Clear all encrypted data from Redis (admin only, for testing)"""
    if not session.get('is_admin', False):
        flash('You do not have permission to perform this action.', 'danger')
        return redirect(url_for('index'))
    
    try:
        # Clear encrypted data from Redis
        redis_client.delete(
            "users_database_encrypted", 
            "webhook_tokens_encrypted", 
            "last_connection_params_encrypted"
        )
        
        # Clear in-memory data
        global users_db, webhook_tokens
        users_db = {}
        webhook_tokens = {}
        
        flash("All encrypted Redis data cleared successfully.", 'success')
        app.logger.info(f"Encrypted Redis data cleared by {session['user_id']}")
        
    except Exception as e:
        flash(f"Error clearing encrypted Redis data: {e}", 'danger')
        app.logger.error(f"Error clearing encrypted Redis data: {e}")
    
    return redirect(url_for('admin_users'))

@app.route('/admin/encryption_status', methods=['GET'])
@login_required
def encryption_status():
    """Show encryption status and Redis data info (admin only)"""
    if not session.get('is_admin', False):
        flash('You do not have permission to access this page.', 'danger')
        return redirect(url_for('index'))
    
    try:
        # Check what's in Redis
        redis_info = {
            "encrypted_users": len(redis_client.hgetall("users_database_encrypted")),
            "encrypted_tokens": len(redis_client.hgetall("webhook_tokens_encrypted")),
            "encrypted_params": bool(redis_client.get("last_connection_params_encrypted")),
            "encryption_initialized": redis_encryption is not None,
            "redis_connected": redis_client.ping()
        }
        
        return jsonify({
            "status": "success",
            "encryption_status": "✅ Active",
            "redis_info": redis_info,
            "memory_data": {
                "users_loaded": len(users_db),
                "tokens_loaded": len(webhook_tokens)
            }
        })
        
    except Exception as e:
        return jsonify({
            "status": "error",
            "error": str(e)
        }), 500

# ============================================================================
# APPLICATION STARTUP
# ============================================================================

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    use_debug = os.environ.get("FLASK_DEBUG", "False").lower() == "true"
    app.logger.info(f"🚀 Starting Frontend Flask app on 0.0.0.0:{port} (Debug Mode: {use_debug})")
    app.logger.info("🔒 Redis encryption enabled for sensitive data storage")
    socketio.run(app, host="0.0.0.0", port=port, debug=use_debug)
