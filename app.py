from flask import Flask, render_template, request, redirect, url_for, jsonify, make_response
from flask import request, jsonify, render_template, make_response
from flask import request, jsonify, render_template
from flask import render_template, abort
from datetime import datetime, timedelta
from datetime import datetime
from flask import request, jsonify
from decimal import Decimal, InvalidOperation
import random
import string
import html
import secrets
import os
from dotenv import load_dotenv
from auth import generate_token, token_required, verify_token, init_auth_routes
import auth
from werkzeug.utils import secure_filename 
from werkzeug.security import check_password_hash
from werkzeug.security import generate_password_hash
from flask_swagger_ui import get_swaggerui_blueprint
from flask_cors import CORS
from database import init_connection_pool, init_db, execute_query, execute_transaction
from ai_agent_deepseek import ai_agent
import time
from functools import wraps
from collections import defaultdict
import requests
from urllib.parse import urlparse
import platform

app = Flask(__name__)

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
MAX_FILE_SIZE = 2 * 1024 * 1024  # 2 MB

def allowed_file(filename):
    """Check if the file has an allowed extension."""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

ALLOWED_IMAGE_CONTENT_TYPES = {'image/png', 'image/jpeg', 'image/jpg', 'image/gif'}
MAX_REMOTE_IMAGE_SIZE = 2 * 1024 * 1024  # 2 MB
ALLOWED_SCHEMES = {'http', 'https'}

def is_private_address(hostname):
    try:
        ip = ipaddress.ip_address(hostname)
        return ip.is_private or ip.is_loopback or ip.is_link_local
    except ValueError:
        return False

def _is_loopback_request():
    """Check if request comes from loopback / internal IP."""
    try:
        if not request.remote_addr:
            return False

        ip = ipaddress.ip_address(request.remote_addr)
        return ip.is_loopback
    except ValueError:
        return False
# Load environment variables
load_dotenv()


# Initialize Flask app
app = Flask(__name__)
CORS(app)

# Initialize database connection pool
init_connection_pool()

SWAGGER_URL = '/api/docs'
API_URL = '/static/openapi.json'

swaggerui_blueprint = get_swaggerui_blueprint(
    SWAGGER_URL,
    API_URL,
    config={
        'app_name': "Vulnerable Bank API Documentation",
        'validatorUrl': None
    }
)

app.register_blueprint(swaggerui_blueprint, url_prefix=SWAGGER_URL)

# Hardcoded secret key (CWE-798)
app.secret_key = "secret123"

# Rate limiting configuration
RATE_LIMIT_WINDOW = 3 * 60 * 60  # 3 hours in seconds
UNAUTHENTICATED_LIMIT = 5  # requests per IP per window
AUTHENTICATED_LIMIT = 10   # requests per user per window

# In-memory rate limiting storage
# Format: {key: [(timestamp, request_count), ...]}
rate_limit_storage = defaultdict(list)

def cleanup_rate_limit_storage():
    """Clean up old entries from rate limit storage"""
    current_time = time.time()
    cutoff_time = current_time - RATE_LIMIT_WINDOW
    
    for key in list(rate_limit_storage.keys()):
        # Remove entries older than the rate limit window
        rate_limit_storage[key] = [
            (timestamp, count) for timestamp, count in rate_limit_storage[key]
            if timestamp > cutoff_time
        ]
        # Remove empty entries
        if not rate_limit_storage[key]:
            del rate_limit_storage[key]

def get_client_ip():
    """Get client IP address, considering proxy headers"""
    if request.headers.get('X-Forwarded-For'):
        return request.headers.get('X-Forwarded-For').split(',')[0].strip()
    elif request.headers.get('X-Real-IP'):
        return request.headers.get('X-Real-IP')
    else:
        return request.remote_addr

def check_rate_limit(key, limit):
    """Check if the request should be rate limited"""
    cleanup_rate_limit_storage()
    current_time = time.time()
    
    # Count requests in the current window
    request_count = sum(count for timestamp, count in rate_limit_storage[key] if timestamp > current_time - RATE_LIMIT_WINDOW)
    
    if request_count >= limit:
        return False, request_count, limit
    
    # Add current request
    rate_limit_storage[key].append((current_time, 1))
    return True, request_count + 1, limit

def ai_rate_limit(f):
    """Rate limiting decorator for AI endpoints"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        client_ip = get_client_ip()
        
        # Check if this is an authenticated request
        auth_header = request.headers.get('Authorization')
        if auth_header and auth_header.startswith('Bearer '):
            # Extract token and get user info
            token = auth_header.split(' ')[1]
            try:
                user_data = verify_token(token)
                if user_data:
                    # Authenticated mode: rate limit by both user and IP
                    user_key = f"ai_auth_user_{user_data['user_id']}"
                    ip_key = f"ai_auth_ip_{client_ip}"
                    
                    # Check user-based rate limit
                    user_allowed, user_count, user_limit = check_rate_limit(user_key, AUTHENTICATED_LIMIT)
                    if not user_allowed:
                        return jsonify({
                            'status': 'error',
                            'message': f'Rate limit exceeded for user. You have made {user_count} requests in the last 3 hours. Limit is {user_limit} requests per 3 hours.',
                            'rate_limit_info': {
                                'limit_type': 'authenticated_user',
                                'current_count': user_count,
                                'limit': user_limit,
                                'window_hours': 3,
                                'user_id': user_data['user_id']
                            }
                        }), 429
                    
                    # Check IP-based rate limit
                    ip_allowed, ip_count, ip_limit = check_rate_limit(ip_key, AUTHENTICATED_LIMIT)
                    if not ip_allowed:
                        return jsonify({
                            'status': 'error',
                            'message': f'Rate limit exceeded for IP address. This IP has made {ip_count} requests in the last 3 hours. Limit is {ip_limit} requests per 3 hours.',
                            'rate_limit_info': {
                                'limit_type': 'authenticated_ip',
                                'current_count': ip_count,
                                'limit': ip_limit,
                                'window_hours': 3,
                                'client_ip': client_ip
                            }
                        }), 429
                    
                    # Both checks passed, proceed with authenticated function
                    return f(*args, **kwargs)
            except:
                pass  # Fall through to unauthenticated handling
        
        # Unauthenticated mode: rate limit by IP only
        ip_key = f"ai_unauth_ip_{client_ip}"
        ip_allowed, ip_count, ip_limit = check_rate_limit(ip_key, UNAUTHENTICATED_LIMIT)
        
        if not ip_allowed:
            return jsonify({
                'status': 'error',
                'message': f'Rate limit exceeded. This IP address has made {ip_count} requests in the last 3 hours. Limit is {ip_limit} requests per 3 hours for unauthenticated users.',
                'rate_limit_info': {
                    'limit_type': 'unauthenticated_ip',
                    'current_count': ip_count,
                    'limit': ip_limit,
                    'window_hours': 3,
                    'client_ip': client_ip,
                    'suggestion': 'Log in to get higher rate limits (10 requests per 3 hours)'
                }
            }), 429
        
        # Rate limit check passed, proceed with unauthenticated function
        return f(*args, **kwargs)
    
    return decorated_function

UPLOAD_FOLDER = os.path.join(os.getcwd(), 'uploads')
os.makedirs(UPLOAD_FOLDER, mode=0o700, exist_ok=True)

def generate_account_number():
    """Generate a secure 10-digit account number"""
    return ''.join(secrets.choice(string.digits) for _ in range(10))

def generate_card_number():
    """Generate a secure 16-digit card number"""
    return ''.join(secrets.choice(string.digits) for _ in range(16))

def generate_cvv():
    """Generate a secure 3-digit CVV"""
    return ''.join(secrets.choice(string.digits) for _ in range(3))
    
# @app.route('/')
# def index():
#     return render_template('index.html')

# @app.route('/register', methods=['GET', 'POST'])
# def register():
#     if request.method == 'POST':
#         try:
#             # Mass Assignment Vulnerability - Client can send additional parameters
#             user_data = request.get_json()  # Changed to get_json()
#             account_number = generate_account_number()
            
#             # Check if username exists
#             existing_user = execute_query(
#                 "SELECT username FROM users WHERE username = %s",
#                 (user_data.get('username'),)
#             )
            
#             if existing_user and existing_user[0]:
#                 return jsonify({
#                     'status': 'error',
#                     'message': 'Username already exists',
#                     'username': user_data.get('username'),
#                     'tried_at': str(datetime.now())  # Information disclosure
#                 }), 400
            
#             # Build dynamic query based on user input fields
#             # Vulnerability: Mass Assignment possible here
#             fields = ['username', 'password', 'account_number']
#             values = [user_data.get('username'), user_data.get('password'), account_number]
            
#             # Include any additional parameters from user input
#             for key, value in user_data.items():
#                 if key not in ['username', 'password']:
#                     fields.append(key)
#                     values.append(value)
            
#             # Build the SQL query dynamically
#             query = f"""
#                 INSERT INTO users ({', '.join(fields)})
#                 VALUES ({', '.join(['%s'] * len(fields))})
#                 RETURNING id, username, account_number, balance, is_admin
#             """
            
#             result = execute_query(query, values, fetch=True)
            
#             if not result or not result[0]:
#                 raise Exception("Failed to create user")
                
#             user = result[0]
            
#             # Excessive Data Exposure in Response
#             sensitive_data = {
#                 'status': 'success',
#                 'message': 'Registration successful! Proceed to login',
#                 'debug_data': {  # Sensitive data exposed
#                     'user_id': user[0],
#                     'username': user[1],
#                     'account_number': user[2],
#                     'balance': float(user[3]) if user[3] else 1000.0,
#                     'is_admin': user[4],
#                     'registration_time': str(datetime.now()),
#                     'server_info': request.headers.get('User-Agent'),
#                     'raw_data': user_data,  # Exposing raw input data
#                     'fields_registered': fields  # Show what fields were registered
#                 }
#             }
            
#             response = jsonify(sensitive_data)
#             response.headers['X-Debug-Info'] = str(sensitive_data['debug_data'])
#             response.headers['X-User-Info'] = f"id={user[0]};admin={user[4]};balance={user[3]}"
            
#             return response
                
#         except Exception as e:
#             print(f"Registration error: {str(e)}")
#             return jsonify({
#                 'status': 'error',
#                 'message': 'Registration failed',
#                 'error': str(e)
#             }), 500
        
#     return render_template('register.html')

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        try:
            user_data = request.get_json()

            if not user_data:
                return jsonify({
                    'status': 'error',
                    'message': 'Invalid JSON payload'
                }), 400

            username = user_data.get('username')
            password = user_data.get('password')

            if not username or not password:
                return jsonify({
                    'status': 'error',
                    'message': 'Username and password are required'
                }), 400

            # Check if username already exists
            existing_user = execute_query(
                "SELECT 1 FROM users WHERE username = %s",
                (username,),
                fetch=True
            )

            if existing_user:
                return jsonify({
                    'status': 'error',
                    'message': 'Username already exists'
                }), 400

            account_number = generate_account_number()
            hashed_password = generate_password_hash(password)

            # Explicit field list (prevents mass assignment)
            query = """
                INSERT INTO users (username, password, account_number)
                VALUES (%s, %s, %s)
                RETURNING id
            """

            result = execute_query(
                query,
                (username, hashed_password, account_number),
                fetch=True
            )

            if not result:
                raise Exception("User creation failed")

            return jsonify({
                'status': 'success',
                'message': 'Registration successful! Please login.'
            }), 201

        except Exception as e:
            print(f"Registration error: {str(e)}")
            return jsonify({
                'status': 'error',
                'message': 'Registration failed'
            }), 500

    return render_template('register.html')

# @app.route('/login', methods=['GET', 'POST'])
# def login():
#     if request.method == 'POST':
#         try:
#             data = request.get_json()
#             username = data.get('username')
#             password = data.get('password')
            
#             print(f"Login attempt - Username: {username}")  # Debug print
            
#             # SQL Injection vulnerability (intentionally vulnerable)
#             query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
#             print(f"Debug - Login query: {query}")  # Debug print
            
#             user = execute_query(query)
#             print(f"Debug - Query result: {user}")  # Debug print
            
#             if user and len(user) > 0:
#                 user = user[0]  # Get first row
#                 print(f"Debug - Found user: {user}")  # Debug print
                
#                 # Generate JWT token instead of using session
#                 token = generate_token(user[0], user[1], user[5])
#                 print(f"Debug - Generated token: {token}")  # Debug print
                
#                 response = make_response(jsonify({
#                     'status': 'success',
#                     'message': 'Login successful',
#                     'token': token,
#                     'accountNumber': user[3],
#                     'isAdmin':       user[5],
#                     'debug_info': {  # Vulnerability: Information disclosure
#                         'user_id': user[0],
#                         'username': user[1],
#                         'account_number': user[3],
#                         'is_admin': user[5],
#                         'login_time': str(datetime.now())
#                     }
#                 }))
#                 # Vulnerability: Cookie without secure flag
#                 response.set_cookie('token', token, httponly=True)
#                 return response
            
#             # Vulnerability: Username enumeration
#             return jsonify({
#                 'status': 'error',
#                 'message': 'Invalid credentials',
#                 'debug_info': {  # Vulnerability: Information disclosure
#                     'attempted_username': username,
#                     'time': str(datetime.now())
#                 }
#             }), 401
            
#         except Exception as e:
#             print(f"Login error: {str(e)}")
#             return jsonify({
#                 'status': 'error',
#                 'message': 'Login failed',
#                 'error': str(e)
#             }), 500
        
#     return render_template('login.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        try:
            data = request.get_json()

            if not data:
                return jsonify({
                    'status': 'error',
                    'message': 'Invalid request'
                }), 400

            username = data.get('username')
            password = data.get('password')

            if not username or not password:
                return jsonify({
                    'status': 'error',
                    'message': 'Invalid credentials'
                }), 401

            # Parameterized query (prevents SQL injection)
            query = """
                SELECT id, username, password, account_number, balance, is_admin
                FROM users
                WHERE username = %s
            """
            result = execute_query(query, (username,), fetch=True)

            if not result:
                return jsonify({
                    'status': 'error',
                    'message': 'Invalid credentials'
                }), 401

            user = result[0]

            # Verify hashed password
            if not check_password_hash(user[2], password):
                return jsonify({
                    'status': 'error',
                    'message': 'Invalid credentials'
                }), 401

            # Generate JWT
            token = generate_token(user[0], user[1], user[5])

            response = make_response(jsonify({
                'status': 'success',
                'message': 'Login successful',
                'token': token
            }))

            # Secure cookie flags
            response.set_cookie(
                'token',
                token,
                httponly=True,
                secure=True,
                samesite='Strict'
            )

            return response, 200

        except Exception as e:
            print(f"Login error: {str(e)}")
            return jsonify({
                'status': 'error',
                'message': 'Login failed'
            }), 500

    return render_template('login.html')

@app.route('/debug/users')
def debug_users():
    users = execute_query("SELECT id, username, password, account_number, is_admin FROM users")
    return jsonify({'users': [
        {
            'id': u[0],
            'username': u[1],
            'password': u[2],
            'account_number': u[3],
            'is_admin': u[4]
        } for u in users
    ]})

# @app.route('/dashboard')
# @token_required
# def dashboard(current_user):
#     # Vulnerability: No input validation on user_id
#     user = execute_query(
#         "SELECT * FROM users WHERE id = %s",
#         (current_user['user_id'],)
#     )[0]
    
#     loans = execute_query(
#         "SELECT * FROM loans WHERE user_id = %s",
#         (current_user['user_id'],)
#     )
    
#     # Create a user dictionary with all fields
#     user_data = {
#         'id': user[0],
#         'username': user[1],
#         'account_number': user[3],
#         'balance': float(user[4]),
#         'is_admin': user[5],
#         'profile_picture': user[6] if len(user) > 6 and user[6] else 'user.png'  # Default image
#     }
    
#     return render_template('dashboard.html',
#                          user=user_data,
#                          username=user[1],
#                          balance=float(user[4]),
#                          account_number=user[3],
#                          loans=loans,
#                          is_admin=current_user.get('is_admin', False))


@app.route('/dashboard')
@token_required
def dashboard(current_user):
    try:
        # Ensure user_id is an integer to prevent injection or misuse
        user_id = int(current_user.get('user_id'))

        # Fetch only needed fields explicitly
        user_query = """
            SELECT id, username, account_number, balance, is_admin, profile_picture
            FROM users
            WHERE id = %s
        """
        result = execute_query(user_query, (user_id,), fetch=True)
        if not result:
            abort(404)  # User not found

        user = result[0]

        # Safe user dictionary
        user_data = {
            'id': user[0],
            'username': user[1],
            'account_number': user[2],
            'balance': float(user[3]),
            'is_admin': user[4],
            'profile_picture': user[5] if user[5] else 'user.png'
        }

        # Fetch loans securely
        loans_query = """
            SELECT id, amount, status, created_at
            FROM loans
            WHERE user_id = %s
        """
        loans = execute_query(loans_query, (user_id,), fetch=True) or []

        return render_template(
            'dashboard.html',
            user=user_data,
            username=user_data['username'],
            balance=user_data['balance'],
            account_number=user_data['account_number'],
            loans=loans,
            is_admin=user_data['is_admin']
        )

    except (ValueError, TypeError):
        # Invalid user_id type
        abort(400)
    except Exception as e:
        print(f"Dashboard error: {e}")
        abort(500)

# Check balance endpoint
# @app.route('/check_balance/<account_number>')
# def check_balance(account_number):
#     # Broken Object Level Authorization (BOLA) vulnerability
#     # No authentication check, anyone can check any account balance
#     try:
#         # Vulnerability: SQL Injection possible
#         user = execute_query(
#             f"SELECT username, balance FROM users WHERE account_number='{account_number}'"
#         )
        
#         if user:
#             # Vulnerability: Information disclosure
#             return jsonify({
#                 'status': 'success',
#                 'username': user[0][0],
#                 'balance': float(user[0][1]),
#                 'account_number': account_number
#             })
#         return jsonify({
#             'status': 'error',
#             'message': 'Account not found'
#         }), 404
#     except Exception as e:
#         return jsonify({
#             'status': 'error',
#             'message': str(e)
#         }), 500

@app.route('/check_balance/<account_number>')
@token_required
def check_balance(current_user, account_number):
    try:
        # Ensure account_number is treated as string and parameterized
        query = """
            SELECT username, balance, account_number
            FROM users
            WHERE account_number = %s
        """
        result = execute_query(query, (account_number,), fetch=True)

        if not result:
            return jsonify({
                'status': 'error',
                'message': 'Account not found'
            }), 404

        user = result[0]

        # Object-level authorization: only allow access if current user owns the account
        if user[2] != current_user.get('account_number') and not current_user.get('is_admin', False):
            return jsonify({
                'status': 'error',
                'message': 'Unauthorized access'
            }), 403

        return jsonify({
            'status': 'success',
            'username': user[0],
            'balance': float(user[1])
        }), 200

    except Exception as e:
        print(f"Check balance error: {e}")
        return jsonify({
            'status': 'error',
            'message': 'Failed to fetch account balance'
        }), 500

# # Transfer endpoint
# @app.route('/transfer', methods=['POST'])
# @token_required
# def transfer(current_user):
#     try:
#         data = request.get_json()
#         # Vulnerability: No input validation on amount
#         # Vulnerability: Negative amounts allowed
#         amount = float(data.get('amount'))
#         to_account = data.get('to_account')
        
#         # Get sender's account number
#         # Race condition vulnerability in checking balance
#         sender_data = execute_query(
#             "SELECT account_number, balance FROM users WHERE id = %s",
#             (current_user['user_id'],)
#         )[0]
        
#         from_account = sender_data[0]
#         balance = float(sender_data[1])
        
#         if balance >= abs(amount):  # Check against absolute value of amount
#             try:
#                 # Vulnerability: Negative transfers possible
#                 # Vulnerability: No transaction atomicity
#                 queries = [
#                     (
#                         "UPDATE users SET balance = balance - %s WHERE id = %s",
#                         (amount, current_user['user_id'])
#                     ),
#                     (
#                         "UPDATE users SET balance = balance + %s WHERE account_number = %s",
#                         (amount, to_account)
#                     ),
#                     (
#                         """INSERT INTO transactions 
#                            (from_account, to_account, amount, transaction_type, description)
#                            VALUES (%s, %s, %s, %s, %s)""",
#                         (from_account, to_account, amount, 'transfer', 
#                          data.get('description', 'Transfer'))
#                     )
#                 ]
#                 execute_transaction(queries)
                
#                 return jsonify({
#                     'status': 'success',
#                     'message': 'Transfer Completed',
#                     'new_balance': balance - amount
#                 })
                
#             except Exception as e:
#                 return jsonify({
#                     'status': 'error',
#                     'message': str(e)
#                 }), 500
#         else:
#             return jsonify({
#                 'status': 'error',
#                 'message': 'Insufficient funds'
#             }), 400
            
#     except Exception as e:
#         return jsonify({
#             'status': 'error',
#             'message': str(e)
#         }), 500

@app.route('/transfer', methods=['POST'])
@token_required
def transfer(current_user):
    try:
        data = request.get_json()
        if not data:
            return jsonify({'status': 'error', 'message': 'Invalid JSON payload'}), 400

        # Validate amount
        try:
            amount = Decimal(data.get('amount'))
            if amount <= 0:
                return jsonify({'status': 'error', 'message': 'Amount must be positive'}), 400
        except (TypeError, InvalidOperation):
            return jsonify({'status': 'error', 'message': 'Invalid amount format'}), 400

        to_account = data.get('to_account')
        if not to_account:
            return jsonify({'status': 'error', 'message': 'Recipient account required'}), 400

        # Fetch sender securely
        sender_query = "SELECT account_number, balance FROM users WHERE id = %s"
        sender_result = execute_query(sender_query, (current_user['user_id'],), fetch=True)
        if not sender_result:
            return jsonify({'status': 'error', 'message': 'Sender account not found'}), 404

        from_account, balance = sender_result[0]
        balance = Decimal(balance)

        if balance < amount:
            return jsonify({'status': 'error', 'message': 'Insufficient funds'}), 400

        # Transaction atomicity
        queries = [
            ("UPDATE users SET balance = balance - %s WHERE id = %s", (amount, current_user['user_id'])),
            ("UPDATE users SET balance = balance + %s WHERE account_number = %s", (amount, to_account)),
            ("INSERT INTO transactions (from_account, to_account, amount, transaction_type, description) "
             "VALUES (%s, %s, %s, %s, %s)",
             (from_account, to_account, amount, 'transfer', data.get('description', 'Transfer')))
        ]
        execute_transaction(queries)

        return jsonify({
            'status': 'success',
            'message': 'Transfer completed',
            'new_balance': float(balance - amount)
        }), 200

    except Exception as e:
        print(f"Transfer error: {e}")
        return jsonify({
            'status': 'error',
            'message': 'Transfer failed'
        }), 500

# Get transaction history endpoint
# @app.route('/transactions/<account_number>')
# def get_transaction_history(account_number):
#     # Vulnerability: No authentication required (BOLA)
#     # Vulnerability: SQL Injection possible
#     try:
#         query = f"""
#             SELECT 
#                 id,
#                 from_account,
#                 to_account,
#                 amount,
#                 timestamp,
#                 transaction_type,
#                 description
#             FROM transactions 
#             WHERE from_account='{account_number}' OR to_account='{account_number}'
#             ORDER BY timestamp DESC
#         """
        
#         transactions = execute_query(query)
        
#         # Vulnerability: Information disclosure
#         transaction_list = [{
#             'id': t[0],
#             'from_account': t[1],
#             'to_account': t[2],
#             'amount': float(t[3]),
#             'timestamp': str(t[4]),
#             'type': t[5],
#             'description': t[6]
#             #'query_used': query  # Vulnerability: Exposing SQL query
#         } for t in transactions]
        
#         return jsonify({
#             'status': 'success',
#             'account_number': account_number,
#             'transactions': transaction_list,
#             'server_time': str(datetime.now())  # Vulnerability: Server information disclosure
#         })
        
#     except Exception as e:
#         return jsonify({
#             'status': 'error',
#             'message': str(e),
#             'query': query,  # Vulnerability: Query exposure
#             'account_number': account_number
#         }), 500

@app.route('/transactions/<account_number>')
@token_required
def get_transaction_history(current_user, account_number):
    try:
        # Object-level authorization: only owner or admin can access
        if account_number != current_user.get('account_number') and not current_user.get('is_admin', False):
            return jsonify({
                'status': 'error',
                'message': 'Unauthorized access'
            }), 403

        # Parameterized query to prevent SQL injection
        query = """
            SELECT 
                id,
                from_account,
                to_account,
                amount,
                timestamp,
                transaction_type,
                description
            FROM transactions
            WHERE from_account = %s OR to_account = %s
            ORDER BY timestamp DESC
        """
        transactions = execute_query(query, (account_number, account_number), fetch=True) or []

        transaction_list = [{
            'id': t[0],
            'from_account': t[1],
            'to_account': t[2],
            'amount': float(t[3]),
            'timestamp': str(t[4]),
            'type': t[5],
            'description': t[6]

        } for t in transactions]

        return jsonify({
            'status': 'success',
            'transactions': transaction_list
        }), 200

    except Exception as e:
        print(f"Transaction history error: {e}")
        return jsonify({
            'status': 'error',
            'message': 'Failed to fetch transactions'
        }), 500

# @app.route('/upload_profile_picture', methods=['POST'])
# @token_required
# def upload_profile_picture(current_user):
#     if 'profile_picture' not in request.files:
#         return jsonify({'error': 'No file provided'}), 400
        
#     file = request.files['profile_picture']
    
#     if file.filename == '':
#         return jsonify({'error': 'No file selected'}), 400
        
#     try:
#         # Vulnerability: No file type validation
#         # Vulnerability: Using user-controlled filename
#         # Vulnerability: No file size check
#         # Vulnerability: No content-type validation
#         filename = secure_filename(file.filename)
        
#         # Add random prefix to prevent filename collisions
#         filename = f"{random.randint(1, 1000000)}_{filename}"
        
#         # Vulnerability: Path traversal possible if filename contains ../
#         file_path = os.path.join(UPLOAD_FOLDER, filename)
        
#         file.save(file_path)
        
#         # Update database with just the filename
#         execute_query(
#             "UPDATE users SET profile_picture = %s WHERE id = %s",
#             (filename, current_user['user_id']),
#             fetch=False
#         )
        
#         return jsonify({
#             'status': 'success',
#             'message': 'Profile picture uploaded successfully',
#             'file_path': os.path.join('static/uploads', filename)  # Vulnerability: Path disclosure
#         })
        
#     except Exception as e:
#         # Vulnerability: Detailed error exposure
#         print(f"Profile picture upload error: {str(e)}")
#         return jsonify({
#             'status': 'error',
#             'message': str(e),
#             'file_path': file_path  # Vulnerability: Information disclosure
#         }), 500

@app.route('/upload_profile_picture', methods=['POST'])
@token_required
def upload_profile_picture(current_user):
    if 'profile_picture' not in request.files:
        return jsonify({'status': 'error', 'message': 'No file provided'}), 400

    file = request.files['profile_picture']

    if file.filename == '':
        return jsonify({'status': 'error', 'message': 'No file selected'}), 400

    if not allowed_file(file.filename):
        return jsonify({'status': 'error', 'message': 'File type not allowed'}), 400

    # Check file size
    file.seek(0, os.SEEK_END)
    file_length = file.tell()
    file.seek(0)
    if file_length > MAX_FILE_SIZE:
        return jsonify({'status': 'error', 'message': 'File too large'}), 400

    try:
        # Secure filename with random prefix to prevent collisions
        ext = file.filename.rsplit('.', 1)[1].lower()
        filename = f"{secrets.token_hex(8)}.{ext}"
        file_path = os.path.join(UPLOAD_FOLDER, filename)

        file.save(file_path)

        # Update database with just the filename
        execute_query(
            "UPDATE users SET profile_picture = %s WHERE id = %s",
            (filename, current_user['user_id']),
            fetch=False
        )

        return jsonify({
            'status': 'success',
            'message': 'Profile picture uploaded successfully',
            'filename': filename  # Return filename only, no path disclosure
        }), 200

    except Exception as e:
        print(f"Profile picture upload error: {e}")
        return jsonify({
            'status': 'error',
            'message': 'Failed to upload profile picture'
        }), 500

# # Upload profile picture by URL (Intentionally Vulnerable to SSRF)
# @app.route('/upload_profile_picture_url', methods=['POST'])
# @token_required
# def upload_profile_picture_url(current_user):
#     try:
#         data = request.get_json() or {}
#         image_url = data.get('image_url')

#         if not image_url:
#             return jsonify({'status': 'error', 'message': 'image_url is required'}), 400

#         # Vulnerabilities:
#         # - No URL scheme/host allowlist (SSRF)
#         # - SSL verification disabled
#         # - Follows redirects
#         # - No content-type or size validation
#         resp = requests.get(image_url, timeout=10, allow_redirects=True, verify=False)
#         if resp.status_code >= 400:
#             return jsonify({'status': 'error', 'message': f'Failed to fetch URL: HTTP {resp.status_code}'}), 400

#         # Derive filename from URL path (user-controlled)
#         parsed = urlparse(image_url)
#         basename = os.path.basename(parsed.path) or 'downloaded'
#         filename = secure_filename(basename)
#         filename = f"{random.randint(1, 1000000)}_{filename}"
#         file_path = os.path.join(UPLOAD_FOLDER, filename)

#         # Save content directly without validation
#         with open(file_path, 'wb') as f:
#             f.write(resp.content)

#         # Store just the filename in DB (same pattern as file upload)
#         execute_query(
#             "UPDATE users SET profile_picture = %s WHERE id = %s",
#             (filename, current_user['user_id']),
#             fetch=False
#         )

#         return jsonify({
#             'status': 'success',
#             'message': 'Profile picture imported from URL',
#             'file_path': os.path.join('static/uploads', filename),
#             'debug_info': {  # Information disclosure for learning
#                 'fetched_url': image_url,
#                 'http_status': resp.status_code,
#                 'content_length': len(resp.content)
#             }
#         })
#     except Exception as e:
#         print(f"URL image import error: {str(e)}")
#         return jsonify({
#             'status': 'error',
#             'message': str(e)
#         }), 500

@app.route('/upload_profile_picture_url', methods=['POST'])
@token_required
def upload_profile_picture_url(current_user):
    try:
        data = request.get_json() or {}
        image_url = data.get('image_url')

        if not image_url:
            return jsonify({'status': 'error', 'message': 'image_url is required'}), 400


        parsed = urlparse(image_url)

        # Validate scheme
        if parsed.scheme not in ALLOWED_SCHEMES:
            return jsonify({'status': 'error', 'message': 'Invalid URL scheme'}), 400

        # Block private / internal addresses (SSRF protection)
        if not parsed.hostname or is_private_address(parsed.hostname):
            return jsonify({'status': 'error', 'message': 'Forbidden URL'}), 403

        # Safe request (no redirects, SSL verification ON)
        resp = requests.get(
            image_url,
            timeout=5,
            allow_redirects=False,
            verify=True,
            stream=True
        )

        if resp.status_code != 200:
            return jsonify({'status': 'error', 'message': 'Failed to fetch image'}), 400

        content_type = resp.headers.get('Content-Type', '').split(';')[0]
        if content_type not in ALLOWED_IMAGE_CONTENT_TYPES:
            return jsonify({'status': 'error', 'message': 'Invalid image type'}), 400

        content_length = resp.headers.get('Content-Length')
        if content_length and int(content_length) > MAX_REMOTE_IMAGE_SIZE:
            return jsonify({'status': 'error', 'message': 'Image too large'}), 400

        # Generate safe filename
        extension = content_type.split('/')[-1]
        filename = f"{secrets.token_hex(8)}.{extension}"
        file_path = os.path.join(UPLOAD_FOLDER, filename)

        # Save with size enforcement
        total_read = 0
        with open(file_path, 'wb') as f:
            for chunk in resp.iter_content(chunk_size=8192):
                total_read += len(chunk)
                if total_read > MAX_REMOTE_IMAGE_SIZE:
                    f.close()
                    os.remove(file_path)
                    return jsonify({'status': 'error', 'message': 'Image too large'}), 400
                f.write(chunk)

        # Update database
        execute_query(
            "UPDATE users SET profile_picture = %s WHERE id = %s",
            (filename, current_user['user_id']),
            fetch=False
        )

        return jsonify({
            'status': 'success',
            'message': 'Profile picture imported successfully'
        }), 200

    except Exception as e:
        print(f"URL image upload error: {e}")
        return jsonify({
            'status': 'error',
            'message': 'Failed to import image'
        }), 500

# INTERNAL-ONLY ENDPOINTS FOR SSRF DEMO (INTENTIONALLY SENSITIVE)
# def _is_loopback_request():
#     try:
#         ip = request.remote_addr or ''
#         return ip == '127.0.0.1' or ip.startswith('127.') or ip == '::1'
#     except Exception:
#         return False

# @app.route('/internal/secret', methods=['GET'])
# def internal_secret():
#     # Soft internal check: allow only loopback requests
#     if not _is_loopback_request():
#         return jsonify({'error': 'Internal resource. Loopback only.'}), 403

#     demo_env = {k: os.getenv(k) for k in [
#         'DB_NAME','DB_USER','DB_PASSWORD','DB_HOST','DB_PORT','DEEPSEEK_API_KEY'
#     ]}
#     # Preview sensitive values (intentionally exposing)
#     if demo_env.get('DEEPSEEK_API_KEY'):
#         demo_env['DEEPSEEK_API_KEY'] = demo_env['DEEPSEEK_API_KEY'][:8] + '...'

#     return jsonify({
#         'status': 'internal',
#         'note': 'Intentionally sensitive data for SSRF demonstration',
#         'secrets': {
#             'app_secret_key': app.secret_key,
#             'jwt_secret': getattr(auth, 'JWT_SECRET', None),
#             'env_preview': demo_env
#         },
#         'system': {
#             'platform': platform.platform(),
#             'python_version': platform.python_version()
#         }
#     })

@app.route('/internal/secret', methods=['GET'])
@token_required
def internal_secret(current_user):
    # Enforce strong authorization (NOT IP-based)
    if not current_user.get('is_admin', False):
        return jsonify({'error': 'Forbidden'}), 403

    # Do NOT expose secrets or environment variables
    return jsonify({
        'status': 'ok',
        'message': 'Internal admin endpoint reachable'
    })


@app.route('/internal/config.json', methods=['GET'])
def internal_config():
    if not _is_loopback_request():
        return jsonify({'error': 'Internal resource. Loopback only.'}), 403

    cfg = {
        'app': {
            'name': 'Vulnerable Bank',
            'debug': True,
            'swagger_url': SWAGGER_URL,
        },
        'rate_limits': {
            'window_seconds': RATE_LIMIT_WINDOW,
            'unauthenticated_limit': UNAUTHENTICATED_LIMIT,
            'authenticated_limit': AUTHENTICATED_LIMIT
        }
    }
    return jsonify(cfg)

# Cloud metadata mock (e.g., AWS IMDS) for SSRF demos
# @app.route('/latest/meta-data/', methods=['GET'])
# def metadata_root():
#     if not _is_loopback_request():
#         return make_response('Forbidden', 403)
#     body = '\n'.join([
#         'ami-id',
#         'hostname',
#         'iam/',
#         'instance-id',
#         'local-ipv4',
#         'public-ipv4',
#         'security-groups'
#     ]) + '\n'
#     resp = make_response(body, 200)
#     resp.mimetype = 'text/plain'
#     return resp

@app.route('/latest/meta-data/', methods=['GET'])
@token_required
def metadata_root(current_user):
    # Strong authorization instead of IP trust
    if not current_user.get('is_admin', False):
        return make_response('Forbidden', 403)

    # Do NOT expose metadata in production
    return make_response(
        'Metadata service disabled in production',
        404
    )


# @app.route('/latest/meta-data/ami-id', methods=['GET'])
# def metadata_ami():
#     if not _is_loopback_request():
#         return make_response('Forbidden', 403)
#     return make_response('ami-0demo1234567890\n', 200)

# @app.route('/latest/meta-data/hostname', methods=['GET'])
# def metadata_hostname():
#     if not _is_loopback_request():
#         return make_response('Forbidden', 403)
#     return make_response('vulnbank.internal\n', 200)

# @app.route('/latest/meta-data/instance-id', methods=['GET'])
# def metadata_instance():
#     if not _is_loopback_request():
#         return make_response('Forbidden', 403)
#     return make_response('i-0demo1234567890\n', 200)

# @app.route('/latest/meta-data/local-ipv4', methods=['GET'])
# def metadata_local_ip():
#     if not _is_loopback_request():
#         return make_response('Forbidden', 403)
#     return make_response('127.0.0.1\n', 200)

# @app.route('/latest/meta-data/public-ipv4', methods=['GET'])
# def metadata_public_ip():
#     if not _is_loopback_request():
#         return make_response('Forbidden', 403)
#     return make_response('198.51.100.42\n', 200)

# @app.route('/latest/meta-data/security-groups', methods=['GET'])
# def metadata_sg():
#     if not _is_loopback_request():
#         return make_response('Forbidden', 403)
#     return make_response('default\n', 200)

# @app.route('/latest/meta-data/iam/', methods=['GET'])
# def metadata_iam_root():
#     if not _is_loopback_request():
#         return make_response('Forbidden', 403)
#     return make_response('security-credentials/\n', 200)

# @app.route('/latest/meta-data/iam/security-credentials/', methods=['GET'])
# def metadata_iam_list():
#     if not _is_loopback_request():
#         return make_response('Forbidden', 403)
#     return make_response('vulnbank-role\n', 200)

@app.route('/latest/meta-data/<path:_>', methods=['GET'])
@token_required
def metadata_disabled(current_user, _):
    if not current_user.get('is_admin', False):
        return jsonify({'error': 'Forbidden'}), 403

    return jsonify({
        'error': 'Cloud metadata service disabled'
    }), 404

# @app.route('/latest/meta-data/iam/security-credentials/vulnbank-role', methods=['GET'])
# def metadata_iam_role():
#     if not _is_loopback_request():
#         return jsonify({'error': 'Forbidden'}), 403
#     creds = {
#         'Code': 'Success',
#         'LastUpdated': datetime.now().isoformat(),
#         'Type': 'AWS-HMAC',
#         'AccessKeyId': 'ASIADEMO1234567890',
#         'SecretAccessKey': 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYDEMODEMO',
#         'Token': 'IQoJb3JpZ2luX2VjEJ//////////wEaCXVzLXdlc3QtMiJIMEYCIQCdemo',
#         'Expiration': (datetime.now() + timedelta(hours=1)).isoformat(),
#         'RoleArn': 'arn:aws:iam::123456789012:role/vulnbank-role'
#     }
#     return jsonify(creds)

@app.route('/latest/meta-data/iam/security-credentials/vulnbank-role', methods=['GET'])
@token_required
def metadata_iam_role(current_user):
    # Strong authorization instead of IP-based trust
    if not current_user.get('is_admin', False):
        return jsonify({'error': 'Forbidden'}), 403

    # Metadata credentials must never be exposed
    return jsonify({
        'error': 'IAM metadata service disabled'
    }), 404


# # Loan request endpoint
# @app.route('/request_loan', methods=['POST'])
# @token_required
# def request_loan(current_user):
#     try:
#         data = request.get_json()
#         # Vulnerability: No input validation on amount
#         amount = float(data.get('amount'))
        
#         execute_query(
#             "INSERT INTO loans (user_id, amount) VALUES (%s, %s)",
#             (current_user['user_id'], amount),
#             fetch=False
#         )
        
#         return jsonify({
#             'status': 'success',
#             'message': 'Loan requested successfully'
#         })
        
#     except Exception as e:
#         print(f"Loan request error: {str(e)}")
#         return jsonify({
#             'status': 'error',
#             'message': str(e)
#         }), 500

@app.route('/request_loan', methods=['POST'])
@token_required
def request_loan(current_user):
    try:
        data = request.get_json() or {}
        raw_amount = data.get('amount')

        # Input validation
        if raw_amount is None:
            return jsonify({'status': 'error', 'message': 'Amount is required'}), 400

        try:
            amount = float(raw_amount)
        except (ValueError, TypeError):
            return jsonify({'status': 'error', 'message': 'Amount must be a number'}), 400

        if amount <= 0:
            return jsonify({'status': 'error', 'message': 'Amount must be greater than 0'}), 400

        # Optional: enforce a max loan limit
        MAX_LOAN_AMOUNT = 100_000
        if amount > MAX_LOAN_AMOUNT:
            return jsonify({
                'status': 'error',
                'message': f'Loan amount cannot exceed {MAX_LOAN_AMOUNT}'
            }), 400

        # Insert safely
        execute_query(
            "INSERT INTO loans (user_id, amount) VALUES (%s, %s)",
            (current_user['user_id'], amount),
            fetch=False
        )

        return jsonify({
            'status': 'success',
            'message': 'Loan requested successfully'
        })

    except Exception as e:
        print(f"Loan request error: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': 'Internal server error'
        }), 500


# # Hidden admin endpoint (security through obscurity)
# @app.route('/sup3r_s3cr3t_admin')
# @token_required
# def admin_panel(current_user):
#     if not current_user['is_admin']:
#         return "Access Denied", 403

#     # Basic pagination to avoid rendering every user at once
#     page = max(request.args.get('page', default=1, type=int), 1)
#     per_page = 10

#     total_users = execute_query("SELECT COUNT(*) FROM users")[0][0]
#     total_pages = max((total_users + per_page - 1) // per_page, 1)
#     page = min(page, total_pages)
#     offset = (page - 1) * per_page

#     users = execute_query(
#         "SELECT * FROM users ORDER BY id LIMIT %s OFFSET %s",
#         (per_page, offset)
#     )

#     loan_page = max(request.args.get('loan_page', default=1, type=int), 1)
#     loan_per_page = 10
#     total_pending_loans = execute_query("SELECT COUNT(*) FROM loans WHERE status='pending'")[0][0]
#     loan_total_pages = max((total_pending_loans + loan_per_page - 1) // loan_per_page, 1)
#     loan_page = min(loan_page, loan_total_pages)
#     loan_offset = (loan_page - 1) * loan_per_page

#     pending_loans = execute_query(
#         "SELECT * FROM loans WHERE status='pending' ORDER BY id LIMIT %s OFFSET %s",
#         (loan_per_page, loan_offset)
#     )
    
#     return render_template(
#         'admin.html',
#         users=users,
#         pending_loans=pending_loans,
#         page=page,
#         total_pages=total_pages,
#         total_users=total_users,
#         per_page=per_page,
#         loan_page=loan_page,
#         loan_total_pages=loan_total_pages,
#         total_pending_loans=total_pending_loans,
#         loan_per_page=loan_per_page
#     )

# @app.route('/sup3r_s3cr3t_admin')
# @token_required
# def admin_panel(current_user):
#     # Admin check
#     if not current_user.get('is_admin', False):
#         return "Access Denied", 403

#     # --------------------
#     # Users pagination
#     # --------------------
#     page = max(request.args.get('page', 1, type=int), 1)
#     per_page = min(request.args.get('per_page', 10, type=int), 50)

#     total_users = execute_query("SELECT COUNT(*) FROM users")[0][0]
#     total_pages = max((total_users + per_page - 1) // per_page, 1)
#     page = min(page, total_pages)
#     offset = (page - 1) * per_page

#     users = execute_query(
#         """
#         SELECT id, username, account_number, balance, is_admin
#         FROM users
#         ORDER BY id
#         LIMIT %s OFFSET %s
#         """,
#         (per_page, offset)
#     )

#     # --------------------
#     # Pending loans pagination
#     # --------------------
#     loan_page = max(request.args.get('loan_page', 1, type=int), 1)
#     loan_per_page = min(request.args.get('loan_per_page', 10, type=int), 50)

#     total_pending_loans = execute_query(
#         "SELECT COUNT(*) FROM loans WHERE status = 'pending'"
#     )[0][0]

#     loan_total_pages = max((total_pending_loans + loan_per_page - 1) // loan_per_page, 1)
#     loan_page = min(loan_page, loan_total_pages)
#     loan_offset = (loan_page - 1) * loan_per_page

#     pending_loans = execute_query(
#         """
#         SELECT id, user_id, amount, status, created_at
#         FROM loans
#         WHERE status = 'pending'
#         ORDER BY id
#         LIMIT %s OFFSET %s
#         """,
#         (loan_per_page, loan_offset)
#     )

#     # --------------------
#     # Render admin panel
#     # --------------------
#     return render_template(
#         'admin.html',
#         users=users,
#         pending_loans=pending_loans,
#         page=page,
#         total_pages=total_pages,
#         total_users=total_users,
#         per_page=per_page,
#         loan_page=loan_page,
#         loan_total_pages=loan_total_pages,
#         total_pending_loans=total_pending_loans,
#         loan_per_page=loan_per_page
#     )



# @app.route('/admin/approve_loan/<int:loan_id>', methods=['POST'])
# @token_required
# def approve_loan(current_user, loan_id):
#     if not current_user.get('is_admin'):
#         return jsonify({'error': 'Access Denied'}), 403
    
#     try:
#         # Vulnerability: Race condition in loan approval
#         # Vulnerability: No validation if loan is already approved
#         loan = execute_query(
#             "SELECT * FROM loans WHERE id = %s",
#             (loan_id,)
#         )[0]
        
#         if loan:
#             # Vulnerability: No transaction atomicity
#             # Vulnerability: No validation of loan amount
#             queries = [
#                 (
#                     "UPDATE loans SET status='approved' WHERE id = %s",
#                     (loan_id,)
#                 ),
#                 (
#                     "UPDATE users SET balance = balance + %s WHERE id = %s",
#                     (float(loan[2]), loan[1])
#                 )
#             ]
#             execute_transaction(queries)
            
#             return jsonify({
#                 'status': 'success',
#                 'message': 'Loan approved successfully',
#                 'debug_info': {  # Vulnerability: Information disclosure
#                     'loan_id': loan_id,
#                     'loan_amount': float(loan[2]),
#                     'user_id': loan[1],
#                     'approved_by': current_user['username'],
#                     'approved_at': str(datetime.now()),
#                     'loan_details': {  # Excessive data exposure
#                         'id': loan[0],
#                         'user_id': loan[1],
#                         'amount': float(loan[2]),
#                         'status': loan[3]
#                     }
#                 }
#             })
        
#         return jsonify({
#             'status': 'error',
#             'message': 'Loan not found',
#             'loan_id': loan_id
#         }), 404
        
#     except Exception as e:
#         # Vulnerability: Detailed error exposure
#         print(f"Loan approval error: {str(e)}")
#         return jsonify({
#             'status': 'error',
#             'message': 'Failed to approve loan',
#             'error': str(e),
#             'loan_id': loan_id
#         }), 500

# # Delete account endpoint
# @app.route('/admin/delete_account/<int:user_id>', methods=['POST'])
# @token_required
# def delete_account(current_user, user_id):
#     if not current_user.get('is_admin'):
#         return jsonify({'error': 'Access Denied'}), 403
    
#     try:
#         # Vulnerability: No user confirmation required
#         # Vulnerability: No audit logging
#         # Vulnerability: No backup creation
#         execute_query(
#             "DELETE FROM users WHERE id = %s",
#             (user_id,),
#             fetch=False
#         )
        
#         return jsonify({
#             'status': 'success',
#             'message': 'Account deleted successfully',
#             'debug_info': {
#                 'deleted_user_id': user_id,
#                 'deleted_by': current_user['username'],
#                 'timestamp': str(datetime.now())
#             }
#         })
        
#     except Exception as e:
#         print(f"Delete account error: {str(e)}")
#         return jsonify({
#             'status': 'error',
#             'message': str(e)
#         }), 500

# # Create admin endpoint
# @app.route('/admin/create_admin', methods=['POST'])
# @token_required
# def create_admin(current_user):
#     if not current_user.get('is_admin'):
#         return jsonify({'error': 'Access Denied'}), 403
    
#     try:
#         data = request.get_json()
#         username = data.get('username')
#         password = data.get('password')
#         account_number = generate_account_number()
        
#         # Vulnerability: SQL injection possible
#         # Vulnerability: No password complexity requirements
#         # Vulnerability: No account number uniqueness check
#         execute_query(
#             f"INSERT INTO users (username, password, account_number, is_admin) VALUES ('{username}', '{password}', '{account_number}', true)",
#             fetch=False
#         )
        
#         return jsonify({
#             'status': 'success',
#             'message': 'Admin created successfully'
#         })
        
#     except Exception as e:
#         print(f"Create admin error: {str(e)}")
#         return jsonify({
#             'status': 'error',
#             'message': str(e)
#         }), 500

# -------------------------------
# Admin Panel Endpoints
# -------------------------------

@app.route('/sup3r_s3cr3t_admin', endpoint='admin_panel_secret')
@token_required
def admin_panel(current_user):
    if not current_user.get('is_admin', False):
        return "Access Denied", 403

    # Pagination for users
    page = max(request.args.get('page', default=1, type=int), 1)
    per_page = min(request.args.get('per_page', default=10, type=int), 50)

    total_users = execute_query("SELECT COUNT(*) FROM users")[0][0]
    total_pages = max((total_users + per_page - 1) // per_page, 1)
    page = min(page, total_pages)
    offset = (page - 1) * per_page

    users = execute_query(
        "SELECT id, username, account_number, balance, is_admin FROM users ORDER BY id LIMIT %s OFFSET %s",
        (per_page, offset)
    )

    # Pagination for pending loans
    loan_page = max(request.args.get('loan_page', default=1, type=int), 1)
    loan_per_page = min(request.args.get('loan_per_page', default=10, type=int), 50)
    total_pending_loans = execute_query("SELECT COUNT(*) FROM loans WHERE status='pending'")[0][0]
    loan_total_pages = max((total_pending_loans + loan_per_page - 1) // loan_per_page, 1)
    loan_page = min(loan_page, loan_total_pages)
    loan_offset = (loan_page - 1) * loan_per_page

    pending_loans = execute_query(
        "SELECT id, user_id, amount, status, created_at FROM loans WHERE status='pending' ORDER BY id LIMIT %s OFFSET %s",
        (loan_per_page, loan_offset)
    )

    return render_template(
        'admin.html',
        users=users,
        pending_loans=pending_loans,
        page=page,
        total_pages=total_pages,
        total_users=total_users,
        per_page=per_page,
        loan_page=loan_page,
        loan_total_pages=loan_total_pages,
        total_pending_loans=total_pending_loans,
        loan_per_page=loan_per_page
    )


# -------------------------------
# Approve Loan
# -------------------------------

@app.route('/admin/approve_loan/<int:loan_id>', methods=['POST'])
@token_required
def approve_loan(current_user, loan_id):
    if not current_user.get('is_admin', False):
        return jsonify({'error': 'Access Denied'}), 403

    try:
        loan = execute_query(
            "SELECT id, user_id, amount, status FROM loans WHERE id = %s FOR UPDATE",
            (loan_id,)
        )
        if not loan:
            return jsonify({'status': 'error', 'message': 'Loan not found'}), 404

        loan = loan[0]

        if loan[3] == 'approved':
            return jsonify({'status': 'error', 'message': 'Loan already approved'}), 400

        amount = float(loan[2])
        if amount <= 0:
            return jsonify({'status': 'error', 'message': 'Invalid loan amount'}), 400

        # Atomic transaction
        queries = [
            ("UPDATE loans SET status='approved' WHERE id = %s", (loan_id,)),
            ("UPDATE users SET balance = balance + %s WHERE id = %s", (amount, loan[1]))
        ]
        execute_transaction(queries)

        return jsonify({'status': 'success', 'message': 'Loan approved successfully'})

    except Exception as e:
        print(f"Loan approval error: {str(e)}")
        return jsonify({'status': 'error', 'message': 'Failed to approve loan'}), 500

# -------------------------------
# Delete Account
# -------------------------------

@app.route('/admin/delete_account/<int:user_id>', methods=['POST'])
@token_required
def delete_account(current_user, user_id):
    if not current_user.get('is_admin', False):
        return jsonify({'error': 'Access Denied'}), 403

    try:
        # Optional: soft delete / backup before hard delete
        execute_query(
            "DELETE FROM users WHERE id = %s",
            (user_id,),
            fetch=False
        )

        # Audit log (server-side only)
        print(f"User {user_id} deleted by admin {current_user['username']} at {datetime.now()}")

        return jsonify({'status': 'success', 'message': 'Account deleted successfully'})

    except Exception as e:
        print(f"Delete account error: {str(e)}")
        return jsonify({'status': 'error', 'message': 'Failed to delete account'}), 500

# -------------------------------
# Create Admin
# -------------------------------

@app.route('/admin/create_admin', methods=['POST'])
@token_required
def create_admin(current_user):
    if not current_user.get('is_admin', False):
        return jsonify({'error': 'Access Denied'}), 403

    try:
        data = request.get_json() or {}
        username = data.get('username', '').strip()
        password = data.get('password', '').strip()

        if not username or not password:
            return jsonify({'status': 'error', 'message': 'Username and password are required'}), 400

        if len(password) < 8:
            return jsonify({'status': 'error', 'message': 'Password must be at least 8 characters'}), 400

        hashed_password = generate_password_hash(password)
        account_number = generate_account_number()

        # Ensure username uniqueness
        existing = execute_query("SELECT id FROM users WHERE username = %s", (username,))
        if existing:
            return jsonify({'status': 'error', 'message': 'Username already exists'}), 400

        execute_query(
            "INSERT INTO users (username, password, account_number, is_admin) VALUES (%s, %s, %s, true)",
            (username, hashed_password, account_number),
            fetch=False
        )

        return jsonify({'status': 'success', 'message': 'Admin created successfully'})

    except Exception as e:
        print(f"Create admin error: {str(e)}")
        return jsonify({'status': 'error', 'message': 'Failed to create admin'}), 500

# Forgot password endpoint (patched)
@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        try:
            data = request.get_json() or {}
            username = data.get('username', '').strip()

            if not username:
                return jsonify({'status': 'error', 'message': 'Username is required'}), 400

            # Parameterized query to prevent SQL injection
            user = execute_query(
                "SELECT id, email FROM users WHERE username = %s",
                (username,)
            )

            if user:
                user_id, email = user[0]

                # Generate a secure 6-digit reset token
                reset_token = ''.join(secrets.choice('0123456789') for _ in range(6))
                hashed_token = generate_password_hash(reset_token)

                # Store hashed reset token in database
                execute_query(
                    "UPDATE users SET reset_pin = %s, reset_requested_at = NOW() WHERE id = %s",
                    (hashed_token, user_id),
                    fetch=False
                )

                # TODO: Send the reset token to user's email (omitted here)
                return jsonify({
                    'status': 'success',
                    'message': 'If the account exists, a reset PIN has been sent to the registered email.'
                })
            else:
                # Generic response to avoid username enumeration
                return jsonify({
                    'status': 'success',
                    'message': 'If the account exists, a reset PIN has been sent to the registered email.'
                })

        except Exception as e:
            print(f"Forgot password error: {str(e)}")
            return jsonify({'status': 'error', 'message': 'Failed to process password reset'}), 500

    return render_template('forgot_password.html')

# Reset password endpoint (patched)
@app.route('/reset-password', methods=['GET', 'POST'])
def reset_password():
    if request.method == 'POST':
        try:
            data = request.get_json() or {}
            username = data.get('username', '').strip()
            reset_pin_input = data.get('reset_pin', '').strip()
            new_password = data.get('new_password', '').strip()

            if not username or not reset_pin_input or not new_password:
                return jsonify({'status': 'error', 'message': 'All fields are required'}), 400

            if len(new_password) < 8:
                return jsonify({'status': 'error', 'message': 'Password must be at least 8 characters'}), 400

            # Parameterized query to prevent SQL injection
            user = execute_query(
                "SELECT id, reset_pin FROM users WHERE username = %s",
                (username,)
            )

            if not user:
                # Generic response to avoid username enumeration
                return jsonify({'status': 'error', 'message': 'Invalid username or reset PIN'}), 400

            user_id, stored_hashed_pin = user[0]

            if not stored_hashed_pin or not check_password_hash(stored_hashed_pin, reset_pin_input):
                # Generic error message prevents PIN enumeration and timing attacks
                return jsonify({'status': 'error', 'message': 'Invalid username or reset PIN'}), 400

            # Hash the new password
            hashed_password = generate_password_hash(new_password)

            # Update password and clear reset PIN
            execute_query(
                "UPDATE users SET password = %s, reset_pin = NULL, reset_requested_at = NULL WHERE id = %s",
                (hashed_password, user_id),
                fetch=False
            )

            return jsonify({'status': 'success', 'message': 'Password has been reset successfully'})

        except Exception as e:

            print(f"Reset password error: {str(e)}")
            return jsonify({'status': 'error', 'message': 'Failed to reset password'}), 500

    return render_template('reset_password.html')

# V1 API - Patched forgot-password endpoint
@app.route('/api/v1/forgot-password', methods=['POST'])
def api_v1_forgot_password():
    try:
        data = request.get_json() or {}
        username = data.get('username', '').strip()

        if not username:
            return jsonify({'status': 'error', 'message': 'Username is required'}), 400

        # Parameterized query to prevent SQL injection
        user = execute_query(
            "SELECT id FROM users WHERE username = %s",
            (username,)
        )

        if not user:
            # Generic response prevents username enumeration
            return jsonify({'status': 'success', 'message': 'If the username exists, a reset PIN has been sent'}), 200

        user_id = user[0][0]

        # Secure 6-digit reset PIN
        reset_pin = f"{secrets.randbelow(900000) + 100000}"  # 100000-999999

        # Store hashed PIN in DB
        hashed_pin = generate_password_hash(reset_pin)

        execute_query(
            "UPDATE users SET reset_pin = %s, reset_requested_at = %s WHERE id = %s",
            (hashed_pin, datetime.now(), user_id),
            fetch=False
        )

        # TODO: Send PIN via email/SMS securely
        # Do NOT include reset_pin in API response

        return jsonify({
            'status': 'success',
            'message': 'If the username exists, a reset PIN has been sent'
        })

    except Exception as e:
        print(f"API V1 forgot-password error: {str(e)}")
        return jsonify({'status': 'error', 'message': 'Failed to process request'}), 500

# Patched API for forgot-password (replaces V2 and V3)
@app.route('/api/forgot-password', methods=['POST'])
def api_forgot_password():
    try:
        data = request.get_json() or {}
        username = data.get('username', '').strip()

        if not username:
            return jsonify({'status': 'error', 'message': 'Username is required'}), 400

        # Parameterized query to prevent SQL injection
        user = execute_query(
            "SELECT id FROM users WHERE username = %s",
            (username,)
        )

        if user:
            user_id = user[0][0]

            # Secure 6-digit reset PIN
            reset_pin = f"{secrets.randbelow(900000) + 100000}"  # 100000-999999
            hashed_pin = generate_password_hash(reset_pin)

            execute_query(
                "UPDATE users SET reset_pin = %s, reset_requested_at = %s WHERE id = %s",
                (hashed_pin, datetime.now(), user_id),
                fetch=False
            )

            # TODO: Send PIN via email/SMS securely
            # Never expose the PIN in the API response

        # Always return generic response to prevent username enumeration
        return jsonify({
            'status': 'success',
            'message': 'If the username exists, a reset PIN has been sent'
        })

    except Exception as e:
        print(f"API forgot-password error: {str(e)}")
        return jsonify({'status': 'error', 'message': 'Failed to process request'}), 500
        
@app.route('/api/transactions', methods=['GET'])
@token_required
def api_transactions(current_user):
    account_number = request.args.get('account_number', '').strip()

    if not account_number:
        return jsonify({'error': 'Account number required'}), 400

    # Ensure the user only queries their own account
    if account_number != current_user.get('account_number'):
        return jsonify({'error': 'Unauthorized access to account'}), 403

    try:
        query = """
            SELECT id, from_account, to_account, amount, timestamp, transaction_type, description
            FROM transactions
            WHERE from_account = %s OR to_account = %s
            ORDER BY timestamp DESC
        """
        transactions = execute_query(query, (account_number, account_number))

        transaction_list = [{
            'id': t[0],
            'from_account': t[1],
            'to_account': t[2],
            'amount': float(t[3]),
            'timestamp': str(t[4]),
            'transaction_type': t[5],
            'description': t[6]
        } for t in transactions]

        return jsonify({'transactions': transaction_list, 'account_number': account_number})

    except Exception as e:
        print(f"Transaction fetch error: {str(e)}")
        return jsonify({'status': 'error', 'message': 'Failed to fetch transactions'}), 500


# -------------------------------
# Create virtual card
# -------------------------------
@app.route('/api/virtual-cards/create', methods=['POST'])
@token_required
def create_virtual_card(current_user):
    try:
        data = request.get_json() or {}
        card_limit = float(data.get('card_limit', 1000.0))
        if card_limit <= 0:
            return jsonify({'status': 'error', 'message': 'Invalid card limit'}), 400

        card_type = data.get('card_type', 'standard').strip().lower()
        if card_type not in ['standard', 'premium', 'gold']:
            card_type = 'standard'

        card_number = generate_card_number()
        cvv = generate_cvv()
        expiry_date = (datetime.now() + timedelta(days=365)).strftime('%m/%y')

        # Use parameterized query to prevent SQL injection
        query = """
            INSERT INTO virtual_cards 
            (user_id, card_number, cvv, expiry_date, card_limit, card_type)
            VALUES (%s, %s, %s, %s, %s, %s)
            RETURNING id
        """
        result = execute_query(query, (current_user['user_id'], card_number, cvv, expiry_date, card_limit, card_type))

        if result:
            return jsonify({
                'status': 'success',
                'message': 'Virtual card created successfully',
                'card_details': {
                    'card_number': card_number,
                    'expiry_date': expiry_date,
                    'limit': card_limit,
                    'type': card_type
                    # CVV not returned for security
                }
            })

        return jsonify({'status': 'error', 'message': 'Failed to create virtual card'}), 500

    except Exception as e:
        print(f"Create virtual card error: {str(e)}")
        return jsonify({'status': 'error', 'message': 'Failed to create virtual card'}), 500


# -------------------------------
# Get virtual cards
# -------------------------------
@app.route('/api/virtual-cards', methods=['GET'])
@token_required
def get_virtual_cards(current_user):
    try:
        # Pagination parameters
        page = max(int(request.args.get('page', 1)), 1)
        per_page = min(int(request.args.get('per_page', 10)), 50)
        offset = (page - 1) * per_page

        query = """
            SELECT id, card_number, expiry_date, card_limit, balance, is_frozen, is_active, created_at, last_used_at, card_type
            FROM virtual_cards
            WHERE user_id = %s
            ORDER BY created_at DESC
            LIMIT %s OFFSET %s
        """
        cards = execute_query(query, (current_user['user_id'], per_page, offset))

        return jsonify({
            'status': 'success',
            'cards': [{
                'id': c[0],
                'card_number': c[1],
                'expiry_date': c[2],
                'limit': float(c[3]),
                'balance': float(c[4]),
                'is_frozen': c[5],
                'is_active': c[6],
                'created_at': str(c[7]),
                'last_used_at': str(c[8]) if c[8] else None,
                'card_type': c[9]
                # CVV not exposed
            } for c in cards],
            'page': page,
            'per_page': per_page,
            'total_cards': len(cards)
        })

    except Exception as e:
        print(f"Fetch virtual cards error: {str(e)}")
        return jsonify({'status': 'error', 'message': 'Failed to fetch virtual cards'}), 500

@app.route('/api/transactions', methods=['GET'])
@token_required
def api_transactions(current_user):
    account_number = request.args.get('account_number', '').strip()

    if not account_number:
        return jsonify({'error': 'Account number required'}), 400

    try:
        transactions = execute_query(
            """
            SELECT id, from_account, to_account, amount, timestamp, transaction_type, description
            FROM transactions
            WHERE from_account = %s OR to_account = %s
            ORDER BY timestamp DESC
            """,
            (account_number, account_number)
        )

        return jsonify({
            'transactions': [
                {
                    'id': t[0],
                    'from_account': t[1],
                    'to_account': t[2],
                    'amount': float(t[3]),
                    'timestamp': str(t[4]),
                    'transaction_type': t[5],
                    'description': t[6]
                }
                for t in transactions
            ],
            'account_number': account_number
        })

    except Exception:
        return jsonify({'error': 'Failed to fetch transactions'}), 500


# -------------------------------
# Create virtual card (patched)
# -------------------------------
@app.route('/api/virtual-cards/create', methods=['POST'])
@token_required
def create_virtual_card(current_user):
    try:
        data = request.get_json() or {}
        card_limit = float(data.get('card_limit', 1000.0))
        if card_limit <= 0:
            return jsonify({'status': 'error', 'message': 'Invalid card limit'}), 400

        card_type = data.get('card_type', 'standard').strip().lower()
        if card_type not in ['standard', 'premium', 'gold']:
            card_type = 'standard'

        card_number = generate_card_number()
        cvv = generate_cvv()

        expiry_date = (datetime.now() + timedelta(days=365)).strftime('%m/%y')

        query = """
            INSERT INTO virtual_cards
            (user_id, card_number, cvv, expiry_date, card_limit, card_type)
            VALUES (%s, %s, %s, %s, %s, %s)
            RETURNING id
        """
        result = execute_query(query, (current_user['user_id'], card_number, cvv, expiry_date, card_limit, card_type))

        if result:

            return jsonify({
                'status': 'success',
                'message': 'Virtual card created successfully',
                'card_details': {
                    'card_number': card_number,

                    'expiry_date': expiry_date,
                    'limit': card_limit,
                    'type': card_type
                    # CVV not returned for security
                }
            })

        return jsonify({'status': 'error', 'message': 'Failed to create virtual card'}), 500

    except Exception as e:
        print(f"Create virtual card error: {str(e)}")
        return jsonify({'status': 'error', 'message': 'Failed to create virtual card'}), 500

@app.route('/api/virtual-cards', methods=['GET'])
@token_required
def get_virtual_cards(current_user):
    try:
        # Pagination parameters
        page = max(request.args.get('page', default=1, type=int), 1)
        per_page = min(request.args.get('per_page', default=10, type=int), 50)
        offset = (page - 1) * per_page

        query = """
            SELECT id, card_number, expiry_date, card_limit, balance, is_frozen, is_active, created_at, last_used_at, card_type
            FROM virtual_cards
            WHERE user_id = %s
            ORDER BY created_at DESC
            LIMIT %s OFFSET %s
        """
        cards = execute_query(query, (current_user['user_id'], per_page, offset))

        card_list = [{
            'id': card[0],
            'card_number': card[1],
            # CVV removed for security
            'expiry_date': card[2],
            'limit': float(card[3]),
            'balance': float(card[4]),
            'is_frozen': card[5],
            'is_active': card[6],
            'created_at': str(card[7]),
            'last_used_at': str(card[8]) if card[8] else None,
            'card_type': card[9]
        } for card in cards]

        return jsonify({
            'status': 'success',
            'cards': card_list,
            'page': page,
            'per_page': per_page
        })

    except Exception as e:
        print(f"Get virtual cards error: {str(e)}")
        return jsonify({'status': 'error', 'message': 'Failed to fetch virtual cards'}), 500


# -------------------------------
# Toggle freeze/unfreeze card (patched)
# -------------------------------
@app.route('/api/virtual-cards/<int:card_id>/toggle-freeze', methods=['POST'])
@token_required
def toggle_card_freeze(current_user, card_id):
    try:
        # Ensure the card belongs to the current user
        card = execute_query(
            "SELECT is_frozen FROM virtual_cards WHERE id = %s AND user_id = %s",
            (card_id, current_user['user_id'])
        )
        if not card:
            return jsonify({'status': 'error', 'message': 'Card not found or access denied'}), 404

        # Toggle freeze status safely
        new_status = not card[0][0]
        execute_query(
            "UPDATE virtual_cards SET is_frozen = %s WHERE id = %s",
            (new_status, card_id),
            fetch=False
        )

        return jsonify({
            'status': 'success',
            'message': f"Card {'frozen' if new_status else 'unfrozen'} successfully"
        })

    except Exception as e:
        print(f"Toggle card freeze error: {str(e)}")
        return jsonify({'status': 'error', 'message': 'Failed to toggle card freeze'}), 500

@app.route('/api/virtual-cards/<int:card_id>/transactions', methods=['GET'])
@token_required
def get_card_transactions(current_user, card_id):
    try:
        # Ensure the card belongs to the current user
        card = execute_query(
            "SELECT id, card_number FROM virtual_cards WHERE id = %s AND user_id = %s",
            (card_id, current_user['user_id'])
        )
        if not card:
            return jsonify({'status': 'error', 'message': 'Card not found or access denied'}), 404

        transactions = execute_query(
            """
            SELECT id, amount, merchant, type, status, timestamp, description
            FROM card_transactions
            WHERE card_id = %s
            ORDER BY timestamp DESC
            """,
            (card_id,)
        )

        transaction_list = [{
            'id': t[0],
            'amount': float(t[1]),
            'merchant': t[2],
            'type': t[3],
            'status': t[4],
            'timestamp': str(t[5]),
            'description': t[6],
            # Do not expose full card number for security; last 4 digits only
            'card_number_last4': card[0][1][-4:]
        } for t in transactions]

        return jsonify({'status': 'success', 'transactions': transaction_list})

    except Exception as e:
        print(f"Get card transactions error: {str(e)}")
        return jsonify({'status': 'error', 'message': 'Failed to fetch transactions'}), 500


# -------------------------------
# Update virtual card limit (patched)
# -------------------------------
@app.route('/api/virtual-cards/<int:card_id>/update-limit', methods=['POST'])
@token_required
def update_card_limit(current_user, card_id):
    try:
        data = request.get_json()
        if not data or 'card_limit' not in data:
            return jsonify({'status': 'error', 'message': 'card_limit is required'}), 400

        # Validate card limit
        try:
            card_limit = float(data['card_limit'])
            if card_limit < 0 or card_limit > 100000:  # example max limit
                return jsonify({'status': 'error', 'message': 'Invalid card limit'}), 400
        except ValueError:
            return jsonify({'status': 'error', 'message': 'Invalid card limit format'}), 400

        # Ensure the card belongs to the current user
        card = execute_query(
            "SELECT id, card_limit, balance, is_frozen, is_active, card_type FROM virtual_cards WHERE id = %s AND user_id = %s",
            (card_id, current_user['user_id'])
        )
        if not card:
            return jsonify({'status': 'error', 'message': 'Card not found or access denied'}), 404

        # Update only allowed field
        execute_query(
            "UPDATE virtual_cards SET card_limit = %s WHERE id = %s",
            (card_limit, card_id),
            fetch=False
        )

        return jsonify({
            'status': 'success',
            'message': 'Card limit updated successfully',
            'card_details': {
                'id': card_id,
                'card_limit': card_limit,
                'balance': float(card[0][2]),
                'is_frozen': card[0][3],
                'is_active': card[0][4],
                'card_type': card[0][5]
            }
        })

    except Exception as e:
        print(f"Update card limit error: {str(e)}")
        return jsonify({'status': 'error', 'message': 'Failed to update card limit'}), 500

@app.route('/api/bill-categories', methods=['GET'])
@token_required
def get_bill_categories(current_user):
    try:
        categories = execute_query(
            "SELECT id, name, description FROM bill_categories WHERE is_active = TRUE"
        )

        return jsonify({
            'status': 'success',
            'categories': [{
                'id': cat[0],
                'name': cat[1],
                'description': cat[2]
            } for cat in categories]
        })

    except Exception as e:
        print(f"Get bill categories error: {str(e)}")
        return jsonify({'status': 'error', 'message': 'Failed to fetch bill categories'}), 500


# -------------------------------
# Get billers by category (patched)
# -------------------------------
@app.route('/api/billers/by-category/<int:category_id>', methods=['GET'])
@token_required
def get_billers_by_category(current_user, category_id):
    try:
        # Parameterized query prevents SQL injection
        billers = execute_query(
            "SELECT id, name, description, minimum_amount, maximum_amount "
            "FROM billers WHERE category_id = %s AND is_active = TRUE",
            (category_id,)
        )

        return jsonify({
            'status': 'success',
            'billers': [{
                'id': b[0],
                'name': b[1],
                'description': b[2],
                'minimum_amount': float(b[3]),
                'maximum_amount': float(b[4]) if b[4] else None
                # Removed account_number from response for security
            } for b in billers]
        })

    except Exception as e:
        print(f"Get billers error: {str(e)}")
        return jsonify({'status': 'error', 'message': 'Failed to fetch billers'}), 500


# -------------------------------
# Create bill payment (patched)
# -------------------------------
@app.route('/api/bill-payments/create', methods=['POST'])
@token_required
def create_bill_payment(current_user):
    try:
        data = request.get_json()


        biller_id = data.get('biller_id')
        amount = float(data.get('amount', 0))
        payment_method = data.get('payment_method')
        card_id = data.get('card_id') if payment_method == 'virtual_card' else None

        # Input validation
        if amount <= 0:
            return jsonify({'status': 'error', 'message': 'Invalid amount'}), 400
        if payment_method not in ['virtual_card', 'balance']:
            return jsonify({'status': 'error', 'message': 'Invalid payment method'}), 400

        # Validate biller exists
        biller = execute_query(
            "SELECT id FROM billers WHERE id = %s AND is_active = TRUE",
            (biller_id,)
        )
        if not biller:
            return jsonify({'status': 'error', 'message': 'Invalid biller'}), 400

        if payment_method == 'virtual_card':
            # Ensure card belongs to user
            card = execute_query(
                "SELECT id, current_balance, card_limit, is_frozen "
                "FROM virtual_cards WHERE id = %s AND user_id = %s",
                (card_id, current_user['user_id'])
            )
            if not card:
                return jsonify({'status': 'error', 'message': 'Card not found or access denied'}), 404

            card = card[0]
            if card[3]:  # is_frozen
                return jsonify({'status': 'error', 'message': 'Card is frozen'}), 400
            if amount > float(card[1]):
                return jsonify({'status': 'error', 'message': 'Insufficient card balance'}), 400
        else:
            # Check user balance
            user_balance = float(execute_query(
                "SELECT balance FROM users WHERE id = %s",
                (current_user['user_id'],)
            )[0][0])
            if amount > user_balance:
                return jsonify({'status': 'error', 'message': 'Insufficient balance'}), 400

        # Generate secure reference number
        reference = f"BILL{secrets.token_hex(6)}"

        # Build queries for atomic transaction
        queries = []

        # Insert payment record
        payment_query = """
            INSERT INTO bill_payments 
            (user_id, biller_id, amount, payment_method, card_id, reference_number, description)
            VALUES (%s, %s, %s, %s, %s, %s, %s)

        """
        payment_values = (
            current_user['user_id'],
            biller_id,
            amount,
            payment_method,
            card_id,
            reference,
            data.get('description', 'Bill Payment')
        )
        queries.append((payment_query, payment_values))

        # Deduct amount
        if payment_method == 'virtual_card':
            queries.append((
                "UPDATE virtual_cards SET current_balance = current_balance - %s WHERE id = %s",
                (amount, card_id)
            ))
        else:
            queries.append((
                "UPDATE users SET balance = balance - %s WHERE id = %s",
                (amount, current_user['user_id'])
            ))

        # Execute all queries atomically
        execute_transaction(queries)

        return jsonify({
            'status': 'success',
            'message': 'Payment processed successfully',
            'payment_details': {
                'reference': reference,
                'amount': amount,
                'payment_method': payment_method,
                'timestamp': str(datetime.now())
            }
        })

    except Exception as e:
        print(f"Create bill payment error: {str(e)}")
        return jsonify({'status': 'error', 'message': 'Failed to process payment'}), 500


@app.route('/api/bill-payments/history', methods=['GET'])
@token_required
def get_payment_history(current_user):
    try:
        # Pagination
        page = int(request.args.get('page', 1))
        page_size = min(int(request.args.get('page_size', 20)), 100)
        offset = (page - 1) * page_size

        # Parameterized query to prevent SQL injection
        payments = execute_query(
            """
            SELECT bp.id, bp.amount, bp.payment_method, bp.reference_number, 
                   bp.status, bp.created_at, bp.processed_at, bp.description,
                   b.name AS biller_name, bc.name AS category_name
            FROM bill_payments bp
            JOIN billers b ON bp.biller_id = b.id
            JOIN bill_categories bc ON b.category_id = bc.id
            LEFT JOIN virtual_cards vc ON bp.card_id = vc.id
            WHERE bp.user_id = %s
            ORDER BY bp.created_at DESC
            LIMIT %s OFFSET %s
            """,
            (current_user['user_id'], page_size, offset)
        )

        return jsonify({
            'status': 'success',
            'page': page,
            'page_size': page_size,
            'payments': [{
                'id': p[0],
                'amount': float(p[1]),
                'payment_method': p[2],
                'reference': p[3],
                'status': p[4],
                'created_at': str(p[5]),
                'processed_at': str(p[6]) if p[6] else None,
                'description': p[7],
                'biller_name': p[8],
                'category_name': p[9]
                # Removed card_number to avoid sensitive data exposure
            } for p in payments]
        })

    except Exception as e:
        print(f"Payment history error: {str(e)}")
        return jsonify({'status': 'error', 'message': 'Failed to fetch payment history'}), 500


# -------------------------------
# Authenticated AI chat (patched)
# -------------------------------
@app.route('/api/ai/chat', methods=['POST'])
@ai_rate_limit
@token_required
def ai_chat_authenticated(current_user):

    try:
        data = request.get_json()
        user_message = data.get('message', '').strip()
        if not user_message:
            return jsonify({'status': 'error', 'message': 'Message is required'}), 400

        # Sanitize input to reduce prompt injection risks
        sanitized_message = user_message.replace("\n", " ").replace("\r", " ").strip()
        if len(sanitized_message) > 1000:
            return jsonify({'status': 'error', 'message': 'Message too long'}), 400

        # Minimal user context for AI
        user_context = {
            'user_id': current_user['user_id'],
            'username': current_user['username']
            # Removed account number, balance, is_admin to prevent sensitive data leaks
        }

        response = ai_agent.chat(sanitized_message, user_context)

        return jsonify({
            'status': 'success',
            'ai_response': response,
            'mode': 'authenticated',
            'user_context_included': True
        })

    except Exception as e:
        print(f"AI chat error: {str(e)}")
        return jsonify({'status': 'error', 'message': 'AI chat failed'}), 500


# -------------------------------
# Anonymous AI chat (patched)
# -------------------------------
@app.route('/api/ai/chat/anonymous', methods=['POST'])
@ai_rate_limit
def ai_chat_anonymous():

    try:
        data = request.get_json()
        user_message = data.get('message', '').strip()
        if not user_message:
            return jsonify({'status': 'error', 'message': 'Message is required'}), 400

        sanitized_message = user_message.replace("\n", " ").replace("\r", " ").strip()
        if len(sanitized_message) > 1000:
            return jsonify({'status': 'error', 'message': 'Message too long'}), 400

        response = ai_agent.chat(sanitized_message, None)

        return jsonify({
            'status': 'success',
            'ai_response': response,
            'mode': 'anonymous'
        })

    except Exception as e:
        print(f"Anonymous AI chat error: {str(e)}")
        return jsonify({'status': 'error', 'message': 'Anonymous AI chat failed'}), 500


# -------------------------------
# AI system info (patched)
# -------------------------------
@app.route('/api/ai/system-info', methods=['GET'])
@token_required  # Require authentication now
def ai_system_info():

    try:
        return jsonify({
            'status': 'success',
            'system_info': ai_agent.get_system_info(sanitize=True),
            'endpoints': {
                'authenticated_chat': '/api/ai/chat',
                'anonymous_chat': '/api/ai/chat/anonymous'
            }
        })
    except Exception as e:
        print(f"AI system info error: {str(e)}")
        return jsonify({'status': 'error', 'message': 'Failed to fetch system info'}), 500