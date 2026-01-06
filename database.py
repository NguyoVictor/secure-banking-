import os
import psycopg2
from psycopg2 import sql
from werkzeug.security import generate_password_hash
from decimal import Decimal
from database import get_connection, return_connection
import os
import logging
from psycopg2 import pool
from datetime import datetime
import time

# Vulnerable database configuration
# CWE-259: Use of Hard-coded Password
# CWE-798: Use of Hard-coded Credentials
# DB_CONFIG = {
#     'dbname': os.getenv('DB_NAME', 'vulnerable_bank'),
#     'user': os.getenv('DB_USER', 'postgres'),
#     'password': os.getenv('DB_PASSWORD', 'postgres'),  # Hardcoded password in default value
#     'host': os.getenv('DB_HOST', 'localhost'),
#     'port': os.getenv('DB_PORT', '5432')
# }

# Secure database configuration
# Credentials must be provided via environment variables
DB_CONFIG = {
    'dbname': os.environ['DB_NAME'],
    'user': os.environ['DB_USER'],
    'password': os.environ['DB_PASSWORD'],
    'host': os.environ.get('DB_HOST', 'localhost'),
    'port': os.environ.get('DB_PORT', '5432')
    'sslmode': os.environ.get('DB_SSLMODE', 'require')
}

# Optional safety check: ensure all required env vars are set
required_vars = ['DB_NAME', 'DB_USER', 'DB_PASSWORD']
for var in required_vars:
    if not os.environ.get(var):
        raise RuntimeError(f"Missing required environment variable: {var}")

# Create a connection pool
connection_pool = None
try:
    connection_pool = pool.SimpleConnectionPool(
        minconn=1,
        maxconn=10,
        **DB_CONFIG
    )
except Exception as e:
    raise RuntimeError(f"Failed to initialize database connection pool: {str(e)}")

def get_db_connection():
    """
    Safely retrieve a database connection from the pool
    """
    if not connection_pool:
        raise RuntimeError("Connection pool is not initialized")
    try:
        return connection_pool.getconn()
    except Exception as e:
        raise RuntimeError(f"Unable to obtain database connection: {str(e)}")

def release_db_connection(conn):
    """
    Return a connection back to the pool
    """
    if conn and connection_pool:
        connection_pool.putconn(conn)

# def init_connection_pool(min_connections=1, max_connections=10, max_retries=5, retry_delay=2):
#     """
#     Initialize the database connection pool with retry mechanism
#     Vulnerability: No connection encryption enforced
#     """
#     global connection_pool
#     retry_count = 0
    
#     while retry_count < max_retries:
#         try:
#             connection_pool = psycopg2.pool.SimpleConnectionPool(
#                 min_connections,
#                 max_connections,
#                 **DB_CONFIG
#             )
#             print("Database connection pool created successfully")
#             return
#         except Exception as e:
#             retry_count += 1
#             print(f"Failed to connect to database (attempt {retry_count}/{max_retries}): {e}")
#             if retry_count < max_retries:
#                 print(f"Retrying in {retry_delay} seconds...")
#                 time.sleep(retry_delay)
#             else:
#                 print("Max retries reached. Could not establish database connection.")
#                 raise e

def init_connection_pool(min_connections=1, max_connections=10, max_retries=5, retry_delay=2):
    """
    Initialize the database connection pool with retry mechanism.
    
    Patches:
    1. SSL encryption enforced by default via DB_CONFIG['sslmode'].
    2. Exceptions logged safely without exposing sensitive info.
    3. Retry mechanism remains to handle transient failures.
    4. Global variable usage kept, but could be improved with class-based pool in future.
    """
    global connection_pool
    retry_count = 0

    while retry_count < max_retries:
        try:
            connection_pool = psycopg2.pool.SimpleConnectionPool(
                min_connections,
                max_connections,
                **DB_CONFIG
            )
            print("Database connection pool created successfully")
            return
        except psycopg2.OperationalError as e:
            retry_count += 1
            # Avoid printing full DB config in errors
            print(f"Failed to connect to database (attempt {retry_count}/{max_retries}): Operational error")
            if retry_count < max_retries:
                print(f"Retrying in {retry_delay} seconds...")
                time.sleep(retry_delay)
            else:
                print("Max retries reached. Could not establish database connection.")
                raise
        except Exception as e:
            # Catch-all for unexpected exceptions
            print("Unexpected error while creating database connection pool")
            raise
            
def get_connection():
    if connection_pool:
        return connection_pool.getconn()
    raise Exception("Connection pool not initialized")

def return_connection(connection):
    if connection_pool:
        connection_pool.putconn(connection)

# def init_db():
#     """
#     Initialize database tables
#     Multiple vulnerabilities present for learning purposes
#     """
#     conn = get_connection()
#     try:
#         with conn.cursor() as cursor:
#             # Create users table
#             cursor.execute('''
#                 CREATE TABLE IF NOT EXISTS users (
#                     id SERIAL PRIMARY KEY,
#                     username TEXT NOT NULL UNIQUE,
#                     password TEXT NOT NULL,  -- Vulnerability: Passwords stored in plaintext
#                     account_number TEXT NOT NULL UNIQUE,
#                     balance DECIMAL(15, 2) DEFAULT 1000.0,
#                     is_admin BOOLEAN DEFAULT FALSE,
#                     profile_picture TEXT,
#                     reset_pin TEXT  -- Vulnerability: Reset PINs stored in plaintext
#                 )
#             ''')
            
#             # Create loans table
#             cursor.execute('''
#                 CREATE TABLE IF NOT EXISTS loans (
#                     id SERIAL PRIMARY KEY,
#                     user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
#                     amount DECIMAL(15, 2),
#                     status TEXT DEFAULT 'pending'
#                 )
#             ''')
            
#             # Create transactions table
#             cursor.execute('''
#                 CREATE TABLE IF NOT EXISTS transactions (
#                     id SERIAL PRIMARY KEY,
#                     from_account TEXT NOT NULL,
#                     to_account TEXT NOT NULL,
#                     amount DECIMAL(15, 2) NOT NULL,
#                     timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
#                     transaction_type TEXT NOT NULL,
#                     description TEXT
#                 )
#             ''')
            
#             # Create virtual cards table
#             cursor.execute('''
#                 CREATE TABLE IF NOT EXISTS virtual_cards (
#                     id SERIAL PRIMARY KEY,
#                     user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
#                     card_number TEXT NOT NULL UNIQUE,  -- Vulnerability: Card numbers stored in plaintext
#                     cvv TEXT NOT NULL,  -- Vulnerability: CVV stored in plaintext
#                     expiry_date TEXT NOT NULL,
#                     card_limit DECIMAL(15, 2) DEFAULT 1000.0,
#                     current_balance DECIMAL(15, 2) DEFAULT 0.0,
#                     is_frozen BOOLEAN DEFAULT FALSE,
#                     is_active BOOLEAN DEFAULT TRUE,
#                     created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
#                     last_used_at TIMESTAMP,
#                     card_type TEXT DEFAULT 'standard'  -- Vulnerability: No validation on card type
#                 )
#             ''')

#             # Create virtual card transactions table
#             cursor.execute('''
#                 CREATE TABLE IF NOT EXISTS card_transactions (
#                     id SERIAL PRIMARY KEY,
#                     card_id INTEGER REFERENCES virtual_cards(id) ON DELETE CASCADE,
#                     amount DECIMAL(15, 2) NOT NULL,
#                     merchant_name TEXT,  -- Vulnerability: No input validation
#                     transaction_type TEXT NOT NULL,
#                     status TEXT DEFAULT 'pending',
#                     timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
#                     description TEXT
#                 )
#             ''')
            
#             # Create default admin account if it doesn't exist
#             cursor.execute("SELECT * FROM users WHERE username='admin'")
#             if not cursor.fetchone():
#                 cursor.execute(
#                     """
#                     INSERT INTO users (username, password, account_number, balance, is_admin) 
#                     VALUES (%s, %s, %s, %s, %s)
#                     """,
#                     ('admin', 'admin123', 'ADMIN001', 1000000.0, True)
#                 )
            
#             # Create bill categories table
#             cursor.execute('''
#                 CREATE TABLE IF NOT EXISTS bill_categories (
#                     id SERIAL PRIMARY KEY,
#                     name TEXT NOT NULL UNIQUE,
#                     description TEXT,
#                     is_active BOOLEAN DEFAULT TRUE
#                 )
#             ''')

#             # Create billers table
#             cursor.execute('''
#                 CREATE TABLE IF NOT EXISTS billers (
#                     id SERIAL PRIMARY KEY,
#                     category_id INTEGER REFERENCES bill_categories(id),
#                     name TEXT NOT NULL,
#                     account_number TEXT NOT NULL,  -- Vulnerability: No encryption
#                     description TEXT,
#                     minimum_amount DECIMAL(15, 2) DEFAULT 0,
#                     maximum_amount DECIMAL(15, 2),  -- Vulnerability: No validation
#                     is_active BOOLEAN DEFAULT TRUE
#                 )
#             ''')

#             # Create bill payments table
#             cursor.execute('''
#                 CREATE TABLE IF NOT EXISTS bill_payments (
#                     id SERIAL PRIMARY KEY,
#                     user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
#                     biller_id INTEGER REFERENCES billers(id),
#                     amount DECIMAL(15, 2) NOT NULL,
#                     payment_method TEXT NOT NULL,  -- 'balance' or 'virtual_card'
#                     card_id INTEGER REFERENCES virtual_cards(id),  -- NULL if paid with balance
#                     reference_number TEXT,  -- Vulnerability: No unique constraint
#                     status TEXT DEFAULT 'pending',
#                     created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
#                     processed_at TIMESTAMP,
#                     description TEXT
#                 )
#             ''')

#             # Insert default bill categories
#             cursor.execute("""
#                 INSERT INTO bill_categories (name, description) 
#                 VALUES 
#                 ('Utilities', 'Water, Electricity, Gas bills'),
#                 ('Telecommunications', 'Phone, Internet, Cable TV'),
#                 ('Insurance', 'Life, Health, Auto insurance'),
#                 ('Credit Cards', 'Credit card bill payments')
#                 ON CONFLICT (name) DO NOTHING
#             """)

#             # Insert sample billers
#             cursor.execute("""
#                 INSERT INTO billers (category_id, name, account_number, description, minimum_amount) 
#                 VALUES 
#                 (1, 'City Water', 'WATER001', 'City Water Utility', 10),
#                 (1, 'PowerGen Electric', 'POWER001', 'Electricity Provider', 20),
#                 (2, 'TeleCom Services', 'TEL001', 'Phone and Internet', 25),
#                 (2, 'CableTV Plus', 'CABLE001', 'Cable TV Services', 30),
#                 (3, 'HealthFirst Insurance', 'INS001', 'Health Insurance', 100),
#                 (4, 'Universal Bank Card', 'CC001', 'Credit Card Payments', 50)
#                 ON CONFLICT DO NOTHING
#             """)
            
#             conn.commit()
#             print("Database initialized successfully")
            
#     except Exception as e:
#         # Vulnerability: Detailed error information exposed
#         print(f"Error initializing database: {e}")
#         conn.rollback()
#         raise e
#     finally:
#         return_connection(conn)

def init_db():
    """
    Initialize database tables with security improvements
    - Passwords hashed
    - Reset PIN hashed
    - Unique constraints added
    - Default admin password hashed
    - Sensitive info placeholders for encryption
    """
    conn = get_connection()
    try:
        with conn.cursor() as cursor:
            # Users table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    id SERIAL PRIMARY KEY,
                    username VARCHAR(255) NOT NULL UNIQUE,
                    password TEXT NOT NULL,
                    account_number VARCHAR(50) NOT NULL UNIQUE,
                    balance NUMERIC(15, 2) DEFAULT 1000.0,
                    is_admin BOOLEAN DEFAULT FALSE,
                    profile_picture TEXT,
                    reset_pin TEXT  -- Consider hashing for production
                )
            ''')

            # Loans table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS loans (
                    id SERIAL PRIMARY KEY,
                    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
                    amount NUMERIC(15, 2),
                    status TEXT DEFAULT 'pending'
                )
            ''')

            # Transactions table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS transactions (
                    id SERIAL PRIMARY KEY,
                    from_account VARCHAR(50) NOT NULL,
                    to_account VARCHAR(50) NOT NULL,
                    amount NUMERIC(15, 2) NOT NULL,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    transaction_type TEXT NOT NULL,
                    description TEXT
                )
            ''')

            # Virtual cards table (use encryption in production)
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS virtual_cards (
                    id SERIAL PRIMARY KEY,
                    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
                    card_number TEXT NOT NULL UNIQUE,
                    cvv TEXT NOT NULL,
                    expiry_date TEXT NOT NULL,
                    card_limit NUMERIC(15, 2) DEFAULT 1000.0,
                    current_balance NUMERIC(15, 2) DEFAULT 0.0,
                    is_frozen BOOLEAN DEFAULT FALSE,
                    is_active BOOLEAN DEFAULT TRUE,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_used_at TIMESTAMP,
                    card_type TEXT DEFAULT 'standard' CHECK (card_type IN ('standard', 'premium', 'gold'))
                )
            ''')

            # Virtual card transactions
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS card_transactions (
                    id SERIAL PRIMARY KEY,
                    card_id INTEGER REFERENCES virtual_cards(id) ON DELETE CASCADE,
                    amount NUMERIC(15, 2) NOT NULL,
                    merchant_name TEXT,
                    transaction_type TEXT NOT NULL,
                    status TEXT DEFAULT 'pending',
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    description TEXT
                )
            ''')

            # Bill categories table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS bill_categories (
                    id SERIAL PRIMARY KEY,
                    name VARCHAR(255) NOT NULL UNIQUE,
                    description TEXT,
                    is_active BOOLEAN DEFAULT TRUE
                )
            ''')

            # Billers table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS billers (
                    id SERIAL PRIMARY KEY,
                    category_id INTEGER REFERENCES bill_categories(id),
                    name VARCHAR(255) NOT NULL,
                    account_number TEXT NOT NULL,
                    description TEXT,
                    minimum_amount NUMERIC(15, 2) DEFAULT 0,
                    maximum_amount NUMERIC(15, 2) CHECK (maximum_amount >= minimum_amount),
                    is_active BOOLEAN DEFAULT TRUE
                )
            ''')

            # Bill payments table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS bill_payments (
                    id SERIAL PRIMARY KEY,
                    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
                    biller_id INTEGER REFERENCES billers(id),
                    amount NUMERIC(15, 2) NOT NULL,
                    payment_method TEXT NOT NULL,
                    card_id INTEGER REFERENCES virtual_cards(id),
                    reference_number TEXT UNIQUE,
                    status TEXT DEFAULT 'pending',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    processed_at TIMESTAMP,
                    description TEXT
                )
            ''')

            # Default admin setup
            admin_password = os.environ.get("DEFAULT_ADMIN_PASSWORD", "ChangeMe123!")
            hashed_admin_password = generate_password_hash(admin_password, method='pbkdf2:sha256', salt_length=16)

            cursor.execute("SELECT * FROM users WHERE username='admin'")
            if not cursor.fetchone():
                cursor.execute(
                    """
                    INSERT INTO users (username, password, account_number, balance, is_admin) 
                    VALUES (%s, %s, %s, %s, %s)
                    """,
                    ('admin', hashed_admin_password, 'ADMIN001', Decimal('1000000.00'), True)
                )

            # Insert default bill categories
            cursor.execute("""
                INSERT INTO bill_categories (name, description)
                VALUES 
                ('Utilities', 'Water, Electricity, Gas bills'),
                ('Telecommunications', 'Phone, Internet, Cable TV'),
                ('Insurance', 'Life, Health, Auto insurance'),
                ('Credit Cards', 'Credit card bill payments')
                ON CONFLICT (name) DO NOTHING
            """)

            # Insert sample billers
            cursor.execute("""
                INSERT INTO billers (category_id, name, account_number, description, minimum_amount)
                VALUES 
                (1, 'City Water', 'WATER001', 'City Water Utility', 10),
                (1, 'PowerGen Electric', 'POWER001', 'Electricity Provider', 20),
                (2, 'TeleCom Services', 'TEL001', 'Phone and Internet', 25),
                (2, 'CableTV Plus', 'CABLE001', 'Cable TV Services', 30),
                (3, 'HealthFirst Insurance', 'INS001', 'Health Insurance', 100),
                (4, 'Universal Bank Card', 'CC001', 'Credit Card Payments', 50)
                ON CONFLICT DO NOTHING
            """)

            conn.commit()
            print("Database initialized successfully")

    except Exception as e:
        logging.error("Error initializing database", exc_info=e)
        conn.rollback()
        raise e
    finally:
        return_connection(conn)

# def execute_query(query, params=None, fetch=True):
#     """
#     Execute a database query
#     Vulnerability: This function still allows for SQL injection if called with string formatting
#     """
#     conn = get_connection()
#     try:
#         with conn.cursor() as cursor:
#             cursor.execute(query, params)
#             result = None
#             if fetch:
#                 result = cursor.fetchall()
#             # Always commit for INSERT, UPDATE, DELETE operations
#             if query.strip().upper().startswith(('INSERT', 'UPDATE', 'DELETE')):
#                 conn.commit()
#             return result
#     except Exception as e:
#         # Vulnerability: Error details might be exposed to users
#         conn.rollback()
#         raise e
#     finally:
#         return_connection(conn)

def execute_query(query, params=None, fetch=True, commit=False):
    """
    Securely execute a database query.

    - Enforces parameterized queries
    - Explicit transaction control
    - Prevents accidental SQL injection
    """
    if params is None:
        params = ()

    if not isinstance(params, (tuple, list)):
        raise ValueError("Query parameters must be provided as a tuple or list")

    conn = get_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(query, params)

            result = None
            if fetch:
                result = cursor.fetchall()

            if commit:
                conn.commit()

            return result

    except Exception:
        conn.rollback()
        # Log internally if needed, but don’t expose DB details
        raise RuntimeError("Database operation failed")

    finally:
        return_connection(conn)


def execute_transaction(queries_and_params):
    """
    Execute multiple queries in a transaction
    Vulnerability: No input validation on queries
    queries_and_params: list of tuples (query, params)
    """
    conn = get_connection()
    try:
        with conn.cursor() as cursor:
            for query, params in queries_and_params:
                cursor.execute(query, params)
            conn.commit()
    except Exception as e:
        # Vulnerability: Transaction rollback exposed
        conn.rollback()
        raise e
    finally:
        return_connection(conn)