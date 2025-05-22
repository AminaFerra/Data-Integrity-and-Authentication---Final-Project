import os
import io
import base64
import hashlib
import hmac
from datetime import datetime, timedelta
from flask import (
    Flask, Blueprint, render_template, request, redirect, url_for,
    flash, session, current_app, send_file, g, has_request_context
)
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager, UserMixin, login_user, logout_user,
    login_required, current_user
)
from werkzeug.security import generate_password_hash, check_password_hash
import re
from authlib.integrations.flask_client import OAuth
from dotenv import load_dotenv
import pyotp
import qrcode
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from cryptography.hazmat.primitives import hashes as crypto_hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding as crypto_padding
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature
import re
from email_validator import validate_email, EmailNotValidError
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import numpy as np
from cryptography.fernet import Fernet

#Password Policies
def validate_password(password):
    """
    Validate that the password meets the following requirements:
    - At least 12 characters long
    - Contains at least one uppercase letter
    - Contains at least one lowercase letter
    - Contains at least one digit
    - Contains at least one special character
    """
    if len(password) < 12:
        return False
    if not re.search(r"[A-Z]", password):
        return False
    if not re.search(r"[a-z]", password):
        return False
    if not re.search(r"\d", password):
        return False
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return False
    return True

load_dotenv()

# Initialize Blueprints
auth_bp = Blueprint('auth', __name__, template_folder='templates')
documents_bp = Blueprint('documents', __name__, template_folder='templates')
rbac_bp = Blueprint('rbac', __name__, template_folder='templates')
security_bp = Blueprint('security', __name__, template_folder='templates')

# Validate critical environment variables
required_env_vars = ['SECRET_KEY', 'ENCRYPTION_KEY', 'HMAC_KEY']
for var in required_env_vars:
    if not os.environ.get(var):
        raise EnvironmentError(f"Missing required environment variable: {var}")

# Validate encryption and HMAC key lengths
if len(os.environ.get('ENCRYPTION_KEY').encode('utf-8')) < 32:
    raise ValueError("ENCRYPTION_KEY must be at least 32 bytes long")
if len(os.environ.get('HMAC_KEY').encode('utf-8')) < 32:
    raise ValueError("HMAC_KEY must be at least 32 bytes long")

#.env config.
class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY')
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL', 'sqlite:///instance/securedocs.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SESSION_COOKIE_SECURE = os.environ.get('SESSION_COOKIE_SECURE', 'True').lower() == 'true'
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    PERMANENT_SESSION_LIFETIME = timedelta(minutes=15)
    UPLOAD_FOLDER = 'Uploads'
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024
    ENCRYPTION_KEY = os.environ.get('ENCRYPTION_KEY')
    HMAC_KEY = os.environ.get('HMAC_KEY').encode('utf-8')
    ENCRYPTION_KEY_BYTES = ENCRYPTION_KEY.encode('utf-8')[:32].ljust(32, b'\0')
    OAUTH_CREDENTIALS = {
        'github': {
            'id': os.environ.get('GITHUB_CLIENT_ID', ''),
            'secret': os.environ.get('GITHUB_CLIENT_SECRET', '')
        },
        'auth0': {
            'id': os.environ.get('AUTH0_CLIENT_ID', ''),
            'secret': os.environ.get('AUTH0_CLIENT_SECRET', ''),
            'domain': os.environ.get('AUTH0_DOMAIN', 'dev-kc42cum1xnzzqav7.us.auth0.com')
        }
    }
    SERVER_NAME = os.environ.get('SERVER_NAME', 'localhost:5000')
    USE_SSL_DEV = os.environ.get('USE_SSL_DEV', 'False').lower() == 'true'

app = Flask(__name__)
app.config.from_object(Config)

# Ensure instance folder exists
os.makedirs(os.path.join(app.instance_path), exist_ok=True)

# Update SQLite database URI to use absolute path
app.config['SQLALCHEMY_DATABASE_URI'] = f"sqlite:///{os.path.join(app.instance_path, 'securedocs.db')}"
print(f"Database will be created at: {app.config['SQLALCHEMY_DATABASE_URI']}")

# Initialize Fernet cipher for all encryption/decryption purposes
cipher_suite = None  # Ensure 'cipher_suite' is always defined
try:
    encryption_key_str = app.config.get('ENCRYPTION_KEY')
    if not encryption_key_str:
        raise ValueError("ENCRYPTION_KEY is not set or is empty in the application configuration.")

    key_bytes_for_fernet = encryption_key_str.encode('utf-8')
    try:
        decoded_key_for_validation = base64.urlsafe_b64decode(key_bytes_for_fernet)
    except (base64.binascii.Error, TypeError) as e:
        raise ValueError(f"ENCRYPTION_KEY ('{encryption_key_str[:10]}...') is not valid URL-safe base64: {e}")

    if len(decoded_key_for_validation) != 32:
        raise ValueError(
            f"Decoded ENCRYPTION_KEY must be 32 bytes long, but got {len(decoded_key_for_validation)} bytes. "
            f"Ensure ENCRYPTION_KEY in .env is a URL-safe base64 encoding of 32 random bytes "
            f"(e.g., output of Fernet.generate_key())."
        )
    cipher_suite = Fernet(key_bytes_for_fernet)
    app.logger.info("Fernet cipher suite initialized successfully for encryption.")
except ValueError as e:
    app.logger.error(f"CRITICAL: Fernet cipher_suite initialization failed due to invalid ENCRYPTION_KEY: {e}. Encryption/decryption will not work.")
except KeyError as e:
    app.logger.error(f"CRITICAL: Fernet cipher_suite initialization failed: ENCRYPTION_KEY not found in app.config ({e}). Encryption/decryption will not work.")
except Exception as e:
    app.logger.error(f"CRITICAL: Unexpected error initializing Fernet cipher_suite: {type(e)} - {e}. Encryption/decryption will not work.")

# Initialize SQLAlchemy and LoginManager after app configuration
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'auth.login'
login_manager.login_message = "Please log in to access this page."
login_manager.login_message_category = "info"
oauth = OAuth(app)

#Database Tables
class User(UserMixin, db.Model):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=True)
    role = db.Column(db.String(20), default='user', nullable=False)
    twofa_secret = db.Column(db.String(32), nullable=True)
    documents = db.relationship('Document', backref='owner', lazy=True, cascade="all, delete-orphan")
    audit_logs = db.relationship('AuditLog', backref='user_account', lazy=True, cascade="all, delete-orphan")
    doctor_visits = db.relationship('DoctorVisit', backref='owner', lazy=True, cascade="all, delete-orphan")
    diagnoses = db.relationship('Diagnosis', backref='owner', lazy=True, cascade="all, delete-orphan")
    prescriptions = db.relationship('Prescription', backref='owner', lazy=True, cascade="all, delete-orphan")
    todo_items = db.relationship('TodoItem', backref='owner', lazy=True, cascade="all, delete-orphan")
    mood_entries = db.relationship('MoodEntry', backref='owner', lazy=True, cascade="all, delete-orphan")
    public_key_pem = db.Column(db.Text, nullable=True) # Stores the user's public key in PEM format
    encrypted_private_key_pem = db.Column(db.Text, nullable=True) # Stores the user's encrypted private key in PEM format

class Document(db.Model):
    __tablename__ = 'document'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    filename = db.Column(db.String(255), nullable=False)
    file_path = db.Column(db.String(512), nullable=False)
    hash = db.Column(db.String(64), nullable=False)
    hmac = db.Column(db.String(64), nullable=False)
    signature = db.Column(db.Text, nullable=True)
    upload_date = db.Column(db.DateTime, default=db.func.current_timestamp())

class AuditLog(db.Model):
    __tablename__ = 'audit_log'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='SET NULL'), nullable=True)
    action = db.Column(db.String(255), nullable=False)
    timestamp = db.Column(db.DateTime, default=db.func.current_timestamp())
    details = db.Column(db.Text, nullable=True)

class DoctorVisit(db.Model):
    __tablename__ = 'doctor_visit'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    visit_date = db.Column(db.DateTime, nullable=False)
    doctor_name = db.Column(db.String(255), nullable=False)
    notes = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=db.func.current_timestamp())

class Diagnosis(db.Model):
    __tablename__ = 'diagnosis'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    visit_id = db.Column(db.Integer, db.ForeignKey('doctor_visit.id'), nullable=True)
    condition = db.Column(db.String(255), nullable=False)
    diagnosis_date = db.Column(db.DateTime, nullable=False)
    details = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=db.func.current_timestamp())

class Prescription(db.Model):
    __tablename__ = 'prescription'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    visit_id = db.Column(db.Integer, db.ForeignKey('doctor_visit.id'), nullable=True)
    medication = db.Column(db.String(255), nullable=False)
    dosage = db.Column(db.String(100), nullable=True)
    prescribed_date = db.Column(db.DateTime, nullable=False)
    instructions = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=db.func.current_timestamp())

class TodoItem(db.Model):
    __tablename__ = 'todo_item'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    task = db.Column(db.String(255), nullable=False)
    completed = db.Column(db.Boolean, default=False, nullable=False)
    created_at = db.Column(db.DateTime, default=db.func.current_timestamp())
    due_date = db.Column(db.DateTime, nullable=True)

class MoodEntry(db.Model):
    __tablename__ = 'mood_entry'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    mood = db.Column(db.String(50), nullable=False)
    mood_score = db.Column(db.Integer, nullable=False)
    entry_date = db.Column(db.DateTime, nullable=False)
    notes = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=db.func.current_timestamp())

def get_roles():
    return ['user', 'admin', 'doctor']

def get_user_by_id(user_id):
    return User.query.get(int(user_id))

def log_action(action, user_id=None, details=None):
    effective_user_id = user_id or (g.user_id if has_request_context() and hasattr(g, 'user_id') else None)
    audit_log = AuditLog(user_id=effective_user_id, action=action, details=details)
    db.session.add(audit_log)
    try:
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        print(f"Error committing audit log: {str(e)}")

def setup_2fa_secret_and_qr():
    secret = pyotp.random_base32()
    user_email_for_qr = current_user.email if has_request_context() and current_user.is_authenticated else "SecureDocsUser"
    totp = pyotp.TOTP(secret)
    uri = totp.provisioning_uri(name=user_email_for_qr, issuer_name="SecureDocsApp")
    qr = qrcode.QRCode(version=4, error_correction=qrcode.constants.ERROR_CORRECT_M, box_size=10, border=4)
    qr.add_data(uri)
    qr.make(fit=True)
    img = qr.make_image(fill_color='black', back_color='white')
    buffered = io.BytesIO()
    img.save(buffered, format="PNG")
    img_str = base64.b64encode(buffered.getvalue()).decode('utf-8')
    return secret, f"data:image/png;base64,{img_str}"

def verify_2fa_code(secret, code):
    if not secret or not code:
        log_action(action="2FA verification failed: Missing secret or code", details="Secret or code is empty")
        return False
    try:
        code = ''.join(c for c in code if c.isdigit())
        totp = pyotp.TOTP(secret)
        is_valid = totp.verify(code, valid_window=1)
        if not is_valid:
            log_action(action="2FA verification failed: Invalid code", details=f"Code: {code}, Server time: {datetime.utcnow()}")
        return is_valid
    except Exception as e:
        log_action(action="2FA verification error", details=str(e))
        return False

def encrypt_file_data(data_bytes):
    try:
        key = app.config['ENCRYPTION_KEY_BYTES']
        cipher = AES.new(key, AES.MODE_EAX)
        ciphertext, tag = cipher.encrypt_and_digest(data_bytes)
        return cipher.nonce + tag + ciphertext
    except Exception as e:
        log_action(action=f"Encryption failed: {str(e)}")
        return None

def decrypt_file_data(encrypted_blob_with_nonce_and_tag):
    try:
        key = app.config['ENCRYPTION_KEY_BYTES']
        nonce, tag, ciphertext = encrypted_blob_with_nonce_and_tag[:16], encrypted_blob_with_nonce_and_tag[16:32], encrypted_blob_with_nonce_and_tag[32:]
        cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
        decrypted_data = cipher.decrypt_and_verify(ciphertext, tag)
        return decrypted_data
    except ValueError as e:
        log_action(action=f"Decryption or MAC verification failed: {str(e)}")
        return None
    except Exception as e:
        log_action(action=f"Decryption error: {str(e)}")
        return None

def generate_file_hash(data):
    return hashlib.sha256(data).hexdigest()

def generate_file_hmac(data):
    return hmac.new(app.config['HMAC_KEY'], data, hashlib.sha256).hexdigest()

def generate_user_key_pair():
    """Generates a new RSA private/public key pair."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')
    return private_key, public_key_pem

def encrypt_private_key(private_key_obj, fernet_cipher):
    """Serializes a private key to PEM and encrypts it using Fernet."""
    if not fernet_cipher:
        raise ValueError("Fernet cipher is not initialized. Cannot encrypt private key.")
    private_key_pem_bytes = private_key_obj.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption() # PEM itself is not encrypted here
    )
    encrypted_pem = fernet_cipher.encrypt(private_key_pem_bytes)
    return encrypted_pem.decode('utf-8') # Store as string

def decrypt_private_key(encrypted_private_key_pem_str, fernet_cipher):
    """Decrypts a Fernet-encrypted private key PEM and loads it."""
    if not fernet_cipher:
        raise ValueError("Fernet cipher is not initialized. Cannot decrypt private key.")
    decrypted_pem_bytes = fernet_cipher.decrypt(encrypted_private_key_pem_str.encode('utf-8'))
    private_key = serialization.load_pem_private_key(
        decrypted_pem_bytes,
        password=None, # No password for the PEM itself at this stage
        backend=default_backend()
    )
    return private_key

def sign_document_data(user, data_to_sign):
    """Signs data using the user's private key. Generates keys if not present."""
    if not cipher_suite:
        raise EnvironmentError("Encryption/Decryption system (Fernet) is not properly initialized. Cannot proceed with signing.")

    private_key_to_use = None
    if user.encrypted_private_key_pem and user.public_key_pem:
        try:
            private_key_to_use = decrypt_private_key(user.encrypted_private_key_pem, cipher_suite)
        except Exception as e:
            # Log this error, could be key corruption or change in ENCRYPTION_KEY
            log_action(action=f"Failed to decrypt private key for user {user.id}: {e}", user_id=user.id, level='ERROR')
            # Fall through to generate new keys, or handle as a more critical error
            # For now, let's attempt to regenerate to keep system usable, but this needs monitoring.
            flash("Error accessing your existing signature key. A new key pair will be generated. If this persists, contact support.", "warning")
            user.encrypted_private_key_pem = None # Clear potentially corrupted key
            user.public_key_pem = None
            # db.session.commit() # Commit the clearing if desired immediately

    if not private_key_to_use:
        # Generate new keys for the user
        new_private_key, new_public_key_pem = generate_user_key_pair()
        user.public_key_pem = new_public_key_pem
        user.encrypted_private_key_pem = encrypt_private_key(new_private_key, cipher_suite)
        db.session.add(user) # Ensure user is in session if they are new or detached
        try:
            db.session.commit()
            log_action(action=f"Generated new RSA key pair for user {user.id}", user_id=user.id)
            private_key_to_use = new_private_key
        except Exception as e:
            db.session.rollback()
            log_action(action=f"Failed to save new RSA key pair for user {user.id}: {e}", user_id=user.id, level='ERROR')
            raise RuntimeError(f"Could not generate or save signature keys for user {user.id}: {e}")

    signature = private_key_to_use.sign(
        data_to_sign,
        crypto_padding.PSS(
            mgf=crypto_padding.MGF1(crypto_hashes.SHA256()),
            salt_length=crypto_padding.PSS.MAX_LENGTH
        ),
        crypto_hashes.SHA256()
    )
    return signature.hex()

def verify_document_signature(user_public_key_pem_str, signature_hex, data_to_verify):
    """Verifies a signature using a given public key PEM string."""
    if not user_public_key_pem_str:
        # This case should ideally be handled before calling, e.g. if user has no public key
        log_action(action="Attempted to verify signature but user_public_key_pem_str was missing.", level='WARNING')
        return False
    try:
        public_key = serialization.load_pem_public_key(
            user_public_key_pem_str.encode('utf-8'),
            backend=default_backend()
        )
        signature_bytes = bytes.fromhex(signature_hex)
        public_key.verify(
            signature_bytes,
            data_to_verify,
            crypto_padding.PSS(
                mgf=crypto_padding.MGF1(crypto_hashes.SHA256()),
                salt_length=crypto_padding.PSS.MAX_LENGTH
            ),
            crypto_hashes.SHA256()
        )
        return True
    except InvalidSignature:
        log_action(action="Signature verification failed: InvalidSignature.", level='INFO')
        return False
    except Exception as e:
        # Log other errors, e.g., malformed key, etc.
        log_action(action=f"Error during signature verification: {e}", level='ERROR')
        return False

def verify_document_integrity(file_path, stored_hash, stored_hmac):
    try:
        with open(file_path, 'rb') as f:
            data = f.read()
        current_hash = generate_file_hash(data)
        current_hmac = generate_file_hmac(data)
        if current_hash != stored_hash:
            log_action(action="Integrity check failed: Hash mismatch")
            return False
        if not hmac.compare_digest(current_hmac.encode('utf-8'), stored_hmac.encode('utf-8')):
            log_action(action="Integrity check failed: HMAC mismatch")
            return False
        return True
    except Exception as e:
        log_action(action=f"Error verifying document integrity: {str(e)}")
        return False

def generate_wellness_chart(user_id):
    mood_entries = MoodEntry.query.filter_by(user_id=user_id).order_by(MoodEntry.entry_date.asc()).all()
    if not mood_entries:
        return None
    dates = [entry.entry_date for entry in mood_entries]
    scores = [entry.mood_score for entry in mood_entries]
    plt.figure(figsize=(8, 4))
    plt.plot(dates, scores, marker='o', linestyle='-', color='b', label='Mood Score')
    plt.title('Wellness Chart: Mood Over Time')
    plt.xlabel('Date')
    plt.ylabel('Mood Score (1-5)')
    plt.grid(True)
    plt.legend()
    plt.tight_layout()
    buffer = io.BytesIO()
    plt.savefig(buffer, format='png')
    plt.close()
    buffer.seek(0)
    img_str = base64.b64encode(buffer.getvalue()).decode('utf-8')
    return f"data:image/png;base64,{img_str}"

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# OAuth setup with validation
if app.config['OAUTH_CREDENTIALS']['github']['id'] and app.config['OAUTH_CREDENTIALS']['github']['secret']:
    oauth.register(
        name='github',
        client_id=app.config['OAUTH_CREDENTIALS']['github']['id'],
        client_secret=app.config['OAUTH_CREDENTIALS']['github']['secret'],
        access_token_url='https://github.com/login/oauth/access_token',
        authorize_url='https://github.com/login/oauth/authorize',
        api_base_url='https://api.github.com/',
        client_kwargs={'scope': 'user:email read:user'},
    )

if app.config['OAUTH_CREDENTIALS']['auth0']['id'] and app.config['OAUTH_CREDENTIALS']['auth0']['secret']:
    oauth.register(
        name='auth0',
        client_id=app.config['OAUTH_CREDENTIALS']['auth0']['id'],
        client_secret=app.config['OAUTH_CREDENTIALS']['auth0']['secret'],
        api_base_url=f"https://{app.config['OAUTH_CREDENTIALS']['auth0']['domain']}/",
        access_token_url=f"https://{app.config['OAUTH_CREDENTIALS']['auth0']['domain']}/oauth/token",
        authorize_url=f"https://{app.config['OAUTH_CREDENTIALS']['auth0']['domain']}/authorize",
        client_kwargs={'scope': 'openid profile email'},
        server_metadata_url=f"https://{app.config['OAUTH_CREDENTIALS']['auth0']['domain']}/.well-known/openid-configuration"
    )


@auth_bp.route('/signup', methods=['GET', 'POST'])
def signup():
    if current_user.is_authenticated:
        return redirect(url_for('documents.dashboard'))
    
    if request.method == 'GET':
        return render_template('signup.html')
    
    # Get form data
    email = request.form.get('email')
    password = request.form.get('password')
    confirm_password = request.form.get('confirm_password')
    
    # Validate required fields
    if not all([email, password, confirm_password]):
        flash('All Fields are required', 'error')
        return render_template('signup.html')
    
    # Check if passwords match
    if password != confirm_password:
        flash('Passwords do not Match', 'error')
        return render_template('signup.html')
    
    # Validate email format
    try:
        # Validate and normalize email
        valid = validate_email(email)
        email = valid.email
    except EmailNotValidError as e:
        flash(f'Email is not valid: {str(e)}', 'error')
        return render_template('signup.html')
    
    # Check if email already exists
    if User.query.filter_by(email=email).first():
        flash('اThis Email is already Used', 'warning')
        return redirect(url_for('auth.signup'))
    
    # Validate password strength
    if not validate_password(password):
        flash('The password does not match the policies', 'error')
        return render_template('signup.html')
    
    # Create new user
    hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
    new_user = User(email=email, password=hashed_password, role='user')
    
    # Generate and store RSA key pair for the user
    try:
        private_key, public_key_pem = generate_user_key_pair()
        new_user.public_key_pem = public_key_pem
        
        # Encrypt and store the private key
        new_user.encrypted_private_key_pem = encrypt_private_key(private_key, cipher_suite)
        
        db.session.add(new_user)
        db.session.commit()
        
        log_action(action=f"User signed up: {email}", user_id=new_user.id)
        flash('Account is created successfully, you can now login.', 'success')
        return redirect(url_for('auth.login'))
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Error during user registration: {str(e)}")
        flash('Something went Wrong while creating the account, please try again.', 'error')
        return render_template('signup.html')

@auth_bp.route('/disable_2fa', methods=['GET', 'POST'])
@login_required
def disable_2fa():
    if not current_user.twofa_secret:
        flash('Two-Factor Authentication is not enabled for your account.', 'info')
        return redirect(url_for('documents.dashboard'))
    if request.method == 'POST':
        current_user.twofa_secret = None
        db.session.commit()
        log_action(action="2FA disabled", user_id=current_user.id)
        flash('Two-Factor Authentication has been disabled successfully.', 'success')
        return redirect(url_for('documents.dashboard'))
    return render_template('disable_2fa.html', current_page='disable_2fa')

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('documents.dashboard') if current_user.role in ['user', 'admin'] else url_for('documents.doctor_dashboard'))
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        remember = request.form.get('remember') == 'on'
        user = User.query.filter_by(email=email).first()
        if not user:
            flash('No account found with that email.', 'error')
            log_action(action=f"Failed login attempt: No user found for email {email}")
            return render_template('login.html')
        if not user.password:
            flash('This account does not have a password set. Please use GitHub/Auth0 login or reset your password.', 'error')
            log_action(action=f"Failed login attempt: No password set for email {email}")
            return render_template('login.html')
        if not check_password_hash(user.password, password):
            flash('Incorrect password. Please try again.', 'error')
            log_action(action=f"Failed login attempt: Incorrect password for email {email}")
            return render_template('login.html')
        if user.twofa_secret:
            session.clear()
            session['user_id_for_2fa_verify'] = user.id
            session['remember_me'] = remember
            log_action(action=f"User login attempt (2FA required): {email}", user_id=user.id)
            return redirect(url_for('auth.verify_2fa_on_login'))
        login_user(user, remember=remember)
        g.user_id = user.id
        session['session_start_time'] = datetime.utcnow().timestamp()
        flash('For enhanced security, we recommend setting up Two-Factor Authentication.', 'info')
        return redirect(url_for('documents.dashboard') if user.role in ['user', 'admin'] else url_for('documents.doctor_dashboard'))
    return render_template('login.html')

@auth_bp.route('/logout', methods=['POST'])
@login_required
def logout():
    user_id_for_log = current_user.id
    user_email_for_log = current_user.email
    logout_user()
    session.clear()
    log_action(
        action="User logged out via button",
        user_id=user_id_for_log,
        details=f"User {user_email_for_log} (ID: {user_id_for_log}) logged out by clicking the logout button."
    )
    flash('You have been logged out successfully.', 'info')
    return redirect(url_for('auth.login'))

def verify_2fa_code(secret, code):
    if not secret or not code:
        log_action(action="2FA verification failed: Missing secret or code", details="Secret or code is empty")
        return False
    try:
        code = ''.join(c for c in code if c.isdigit())
        totp = pyotp.TOTP(secret, interval=30)
        is_valid = totp.verify(code, valid_window=0)  # Strictly validate current time window
        if not is_valid:
            log_action(action="2FA verification failed: Invalid code", details=f"Code: {code}, Server time: {datetime.utcnow()}")
        return is_valid
    except Exception as e:
        log_action(action="2FA verification error", details=str(e))
        return False

@auth_bp.route('/verify_2fa_on_login', methods=['GET', 'POST'])
def verify_2fa_on_login():
    user_id = session.get('user_id_for_2fa_verify')
    if not user_id:
        flash("Invalid verification session. Please log in again.", "error")
        session.clear()
        return redirect(url_for('auth.login'))
    
    user = User.query.get(user_id)
    if not user or not user.twofa_secret:
        flash("2FA not enabled or user not found.", "error")
        session.clear()
        return redirect(url_for('auth.login'))
    
    if request.method == 'POST':
        code = request.form.get('code')
        if not code or not code.isdigit():
            flash("Please enter a valid 2FA code.", "error")
            log_action(action="Invalid 2FA input", user_id=user.id)
        elif verify_2fa_code(user.twofa_secret, code):
            try:
                session.pop('user_id_for_2fa_verify', None)
                remember = session.pop('remember_me', False)
                login_user(user, remember=remember)
                session['session_start_time'] = datetime.utcnow().timestamp()
                g.user_id = user.id
                log_action(action="User logged in (2FA verified)", user_id=user.id)
                flash('Successfully verified and logged in!', 'success')
                return redirect(url_for('documents.dashboard') if user.role in ['user', 'admin'] else url_for('documents.doctor_dashboard'))
            except Exception as e:
                flash(f"Error during login after 2FA verification: {str(e)}", "error")
                log_action(action=f"Error after 2FA verification: {str(e)}", user_id=user.id)
                return redirect(url_for('auth.login'))
        else:
            # Check if the code is expired by testing it against adjacent time windows
            totp = pyotp.TOTP(user.twofa_secret, interval=30)
            if totp.verify(code, valid_window=1):  # Check if code is valid in adjacent time windows
                flash('The 2FA code has expired. Please use the latest code from your authenticator app.', 'error')
                log_action(action="2FA verification failed: Expired code", user_id=user.id)
            else:
                flash('Invalid 2FA code. Please try again.', 'error')
                log_action(action="2FA verification failed: Invalid code", user_id=user.id)
    return render_template('verify_2fa.html', current_page='verify_2fa')

@auth_bp.route('/login/auth0/')
def auth0_login():
    if not app.config['OAUTH_CREDENTIALS']['auth0']['id']:
        flash('Auth0 login is not configured.', 'error')
        return redirect(url_for('auth.login'))
    try:
        redirect_uri = url_for('auth.auth0_callback', _external=True)
        log_action(action=f"Initiating Auth0 login with redirect URI: {redirect_uri}")
        return oauth.auth0.authorize_redirect(redirect_uri)
    except Exception as e:
        log_action(action=f"Auth0 OAuth initiation error: {str(e)}")
        flash(f'Failed to initiate Auth0 login: {str(e)}', 'error')
        return redirect(url_for('auth.login'))

@auth_bp.route('/login/auth0/callback')
def auth0_callback():
    try:
        token = oauth.auth0.authorize_access_token()
        if not token:
            log_action(action="Auth0 OAuth failed: No token received")
            flash('Failed to authorize with Auth0: No token received.', 'error')
            return redirect(url_for('auth.login'))
        resp = oauth.auth0.get('userinfo', token=token)
        resp.raise_for_status()
        user_info = resp.json()
        email = user_info.get('email')
        if not email:
            log_action(action="Auth0 OAuth failed: No email found")
            flash('No email found from Auth0. Please ensure your Auth0 account has a verified email.', 'error')
            return redirect(url_for('auth.login'))
        user = User.query.filter_by(email=email).first()
        if not user:
            user = User(email=email, role='user')
            db.session.add(user)
            db.session.commit()
            log_action(action=f"New user signed up via Auth0: {email}", user_id=user.id)
            flash('Your account has been successfully created via Auth0!', 'success')
        else:
            log_action(action=f"User logged in via Auth0: {email}", user_id=user.id)
            flash('Logged in successfully via Auth0!', 'success')
        login_user(user)
        g.user_id = user.id
        session['session_start_time'] = datetime.utcnow().timestamp()
        return redirect(url_for('documents.dashboard') if user.role in ['user', 'admin'] else url_for('documents.doctor_dashboard'))
    except Exception as e:
        log_action(action=f"Auth0 OAuth callback error: {str(e)}")
        flash(f'An error occurred during Auth0 authentication: {str(e)}', 'error')
        return redirect(url_for('auth.login'))

@auth_bp.route('/login/github/')
def github_login():
    if not app.config['OAUTH_CREDENTIALS']['github']['id']:
        flash('GitHub login is not configured.', 'error')
        return redirect(url_for('auth.login'))
    try:
        redirect_uri = url_for('auth.github_callback', _external=True)
        return oauth.github.authorize_redirect(redirect_uri)
    except Exception as e:
        log_action(action=f"GitHub OAuth initiation error: {str(e)}")
        flash(f'Failed to initiate GitHub login: {str(e)}', 'error')
        return redirect(url_for('auth.login'))

@auth_bp.route('/login/github/callback')
def github_callback():
    try:
        token = oauth.github.authorize_access_token()
        if not token:
            log_action(action="GitHub OAuth failed: No token received")
            flash('Failed to authorize with GitHub: No token received.', 'error')
            return redirect(url_for('auth.login'))
        resp = oauth.github.get('user', token=token)
        resp.raise_for_status()
        user_info = resp.json()
        email = user_info.get('email')
        if not email:
            email_resp = oauth.github.get('user/emails', token=token)
            email_resp.raise_for_status()
            emails_data = email_resp.json()
            primary_email_obj = next((e for e in emails_data if e.get('primary') and e.get('verified')), None)
            if primary_email_obj:
                email = primary_email_obj['email']
            else:
                verified_email_obj = next((e for e in emails_data if e.get('verified')), None)
                if verified_email_obj:
                    email = verified_email_obj['email']
                else:
                    log_action(action="GitHub OAuth failed: No verified email found")
                    flash('No verified email found from GitHub. Please ensure you have a primary, verified email on your GitHub account.', 'error')
                    return redirect(url_for('auth.login'))
        user = User.query.filter_by(email=email).first()
        if not user:
            user = User(email=email, role='user')
            db.session.add(user)
            db.session.commit()
            log_action(action=f"New user signed up via GitHub: {email}", user_id=user.id)
            flash('Your account has been successfully created via GitHub!', 'success')
        else:
            log_action(action=f"User logged in via GitHub: {email}", user_id=user.id)
            flash('Logged in successfully via GitHub!', 'success')
        login_user(user)
        g.user_id = user.id
        session['session_start_time'] = datetime.utcnow().timestamp()
        return redirect(url_for('documents.dashboard') if user.role in ['user', 'admin'] else url_for('documents.doctor_dashboard'))
    except Exception as e:
        log_action(action=f"GitHub OAuth callback error: {str(e)}")
        flash(f'An error occurred during GitHub authentication: {str(e)}', 'error')
        return redirect(url_for('auth.login'))

@auth_bp.route('/setup_2fa', methods=['GET', 'POST'])
@login_required
def setup_2fa():
    skip_2fa = request.args.get('skip') == '1'
    if skip_2fa:
        flash("Two-Factor Authentication setup skipped. You can enable it later from your profile.", "info")
        return redirect(url_for('documents.dashboard') if current_user.role in ['user', 'admin'] else url_for('documents.doctor_dashboard'))
    user = User.query.get(session.get('user_id_for_2fa_setup', current_user.id))
    if not user:
        flash("User not found.", "error")
        session.clear()
        return redirect(url_for('auth.login'))
    if request.method == 'POST':
        code = request.form.get('code')
        temp_secret = session.get(f'temp_2fa_secret_{user.id}')
        if not temp_secret:
            flash("2FA setup session expired. Please try again.", "error")
            session.clear()
            return redirect(url_for('auth.setup_2fa'))
        if verify_2fa_code(temp_secret, code):
            user.twofa_secret = temp_secret
            db.session.commit()
            session.pop(f'temp_2fa_secret_{user.id}', None)
            session.pop('user_id_for_2fa_setup', None)
            log_action(action="2FA enabled", user_id=user.id)
            flash('Two-Factor Authentication enabled successfully!', 'success')
            return redirect(url_for('documents.dashboard') if user.role in ['user', 'admin'] else url_for('documents.doctor_dashboard'))
        flash('Invalid 2FA code. Please try again. Make sure you enter the current code shown in your authenticator app.', 'error')
        log_action(action="2FA setup failed (invalid code)", user_id=user.id)
        uri = pyotp.totp.TOTP(temp_secret).provisioning_uri(name=user.email, issuer_name="SecureDocsApp")
        qr = qrcode.QRCode(version=1, error_correction=qrcode.constants.ERROR_CORRECT_L, box_size=10, border=4)
        qr.add_data(uri)
        qr.make(fit=True)
        img = qr.make_image(fill_color='black', back_color='white')
        buffered = io.BytesIO()
        img.save(buffered, format="PNG")
        qr_code_img = base64.b64encode(buffered.getvalue()).decode('utf-8')
        secret_for_display = ' '.join([temp_secret[i:i+4] for i in range(0, len(temp_secret), 4)])
        return render_template('setup_2fa.html', 
                              qr_code=f"data:image/png;base64,{qr_code_img}", 
                              secret_key=secret_for_display,
                              for_setup=True, 
                              current_page='setup_2fa')
    secret, qr_code_img = setup_2fa_secret_and_qr()
    session[f'temp_2fa_secret_{user.id}'] = secret
    log_action(action="Initiated 2FA setup", user_id=user.id)
    secret_for_display = ' '.join([secret[i:i+4] for i in range(0, len(secret), 4)])
    return render_template('setup_2fa.html', 
                          qr_code=qr_code_img, 
                          secret_key=secret_for_display,
                          for_setup=True, 
                          current_page='setup_2fa')



@documents_bp.route('/dashboard')
@login_required
def dashboard():
    if current_user.role == 'doctor':
        return redirect(url_for('documents.doctor_dashboard'))
    try:
        document_count = Document.query.filter_by(user_id=current_user.id).count()
        if current_user.role == 'admin':
            doctor_visits = DoctorVisit.query.order_by(DoctorVisit.visit_date.desc()).limit(5).all()
            diagnoses = Diagnosis.query.order_by(Diagnosis.diagnosis_date.desc()).limit(5).all()
            prescriptions = Prescription.query.order_by(Prescription.prescribed_date.desc()).limit(5).all()
            todo_items = TodoItem.query.order_by(TodoItem.created_at.desc()).limit(5).all()
            mood_entries = MoodEntry.query.order_by(MoodEntry.entry_date.desc()).limit(5).all()
            wellness_chart = None
        else:
            doctor_visits = DoctorVisit.query.filter_by(user_id=current_user.id).order_by(DoctorVisit.visit_date.desc()).limit(5).all()
            diagnoses = Diagnosis.query.filter_by(user_id=current_user.id).order_by(Diagnosis.diagnosis_date.desc()).limit(5).all()
            prescriptions = Prescription.query.filter_by(user_id=current_user.id).order_by(Prescription.prescribed_date.desc()).limit(5).all()
            todo_items = TodoItem.query.filter_by(user_id=current_user.id).order_by(TodoItem.created_at.desc()).limit(5).all()
            mood_entries = MoodEntry.query.filter_by(user_id=current_user.id).order_by(MoodEntry.entry_date.desc()).limit(5).all()
            wellness_chart = generate_wellness_chart(current_user.id)
    except Exception as e:
        flash(f"Error loading dashboard data: {str(e)}", "error")
        log_action(action=f"Error loading dashboard: {str(e)}", user_id=current_user.id)
        document_count = 0
        doctor_visits = diagnoses = prescriptions = todo_items = mood_entries = []
        wellness_chart = None
    return render_template('dashboard.html', 
                          document_count=document_count, 
                          doctor_visits=doctor_visits, 
                          diagnoses=diagnoses, 
                          prescriptions=prescriptions, 
                          todo_items=todo_items, 
                          mood_entries=mood_entries, 
                          wellness_chart=wellness_chart, 
                          current_page='dashboard')

@documents_bp.route('/doctor_dashboard')
@login_required
def doctor_dashboard():
    if current_user.role != 'doctor':
        flash('Access denied: Doctors only', 'danger')
        log_action(action="Unauthorized access attempt to doctor dashboard", user_id=current_user.id)
        return redirect(url_for('documents.dashboard'))
    try:
        users = User.query.filter_by(role='user').all()
        doctor_visits = DoctorVisit.query.order_by(DoctorVisit.visit_date.desc()).limit(5).all()
        mood_entries = MoodEntry.query.order_by(MoodEntry.entry_date.desc()).limit(5).all()
    except Exception as e:
        flash(f"Error loading doctor dashboard data: {str(e)}", "error")
        log_action(action=f"Error loading doctor dashboard: {str(e)}", user_id=current_user.id)
        users = doctor_visits = mood_entries = []
    return render_template('doctor_dashboard.html',
                          users=users,
                          doctor_visits=doctor_visits,
                          mood_entries=mood_entries,
                          current_page='doctor_dashboard')

@documents_bp.route('/upload', methods=['GET', 'POST'])
@login_required
def upload():
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file part selected.', 'warning')
            return redirect(request.url)
        file = request.files['file']
        if file.filename == '':
            flash('No file selected for uploading.', 'warning')
            return redirect(request.url)
        if file:
            original_filename = file.filename
            allowed_extensions = {'.pdf', '.docx', '.txt'}
            if not any(original_filename.lower().endswith(ext) for ext in allowed_extensions):
                flash('Unsupported file type. Allowed files: PDF, DOCX, TXT.', 'error')
                return redirect(request.url)
            file_data = file.read()
            if len(file_data) == 0:
                flash('The selected file is empty.', 'warning')
                return redirect(request.url)
            if len(file_data) > app.config['MAX_CONTENT_LENGTH']:
                flash(f"File size exceeds the maximum limit of {app.config['MAX_CONTENT_LENGTH'] // (1024*1024)}MB.", "error")
                return redirect(request.url)
            try:
                encrypted_blob = encrypt_file_data(file_data)
                if encrypted_blob is None:
                    flash('File encryption failed.', 'error')
                    return redirect(request.url)
                signature_hex = sign_document_data(current_user, encrypted_blob)
                doc_hash = generate_file_hash(encrypted_blob)
                doc_hmac = generate_file_hmac(encrypted_blob)
                timestamp = datetime.utcnow().strftime('%Y%m%d%H%M%S%f')
                encrypted_filename = f"document_{current_user.id}_{timestamp}.enc"
                encrypted_file_path = os.path.join(app.config['UPLOAD_FOLDER'], encrypted_filename)
                with open(encrypted_file_path, 'wb') as f:
                    f.write(encrypted_blob)
                document = Document(
                    user_id=current_user.id,
                    filename=original_filename,
                    file_path=encrypted_file_path,
                    hash=doc_hash,
                    hmac=doc_hmac,
                    signature=signature_hex
                )
                db.session.add(document)
                db.session.commit()
                log_action(action=f"Uploaded file: {original_filename}", user_id=current_user.id, details=f"Document ID: {document.id}, Saved as: {encrypted_filename}")
                flash('File uploaded and encrypted successfully!', 'success')
                return redirect(url_for('documents.list_documents'))
            except Exception as e:
                log_action(action=f"Error uploading file {original_filename}: {str(e)}", user_id=current_user.id)
                flash(f'An error occurred while processing the file: {str(e)}', 'error')
                return redirect(request.url)
    return render_template('upload.html', current_page='upload')

@documents_bp.route('/list')
@login_required
def list_documents():
    page = request.args.get('page', 1, type=int)
    per_page = 10
    pagination = Document.query.filter_by(user_id=current_user.id).order_by(Document.upload_date.desc()).paginate(page=page, per_page=per_page) if current_user.role != 'admin' else Document.query.order_by(Document.upload_date.desc()).paginate(page=page, per_page=per_page)
    documents_on_page = pagination.items
    return render_template('documents.html', documents=documents_on_page, pagination=pagination, current_page='list_documents')

@documents_bp.route('/download/<int:document_id>')
@login_required
def download_document(document_id):
    document = Document.query.get_or_404(document_id)
    if document.owner.id != current_user.id and current_user.role != 'admin':
        flash('You do not have permission to download this file.', 'danger')
        log_action(action=f"Unauthorized download attempt: DocID {document_id}", user_id=current_user.id)
        return redirect(url_for('documents.list_documents'))
    if not os.path.exists(document.file_path):
        flash('File not found on the server.', 'error')
        log_action(action=f"File not found for DocID {document_id}: {document.file_path}", user_id=current_user.id)
        return redirect(url_for('documents.list_documents'))
    if not verify_document_integrity(document.file_path, document.hash, document.hmac):
        flash('File integrity check failed (hash or HMAC mismatch). The file might be corrupted or tampered with.', 'error')
        log_action(action=f"Integrity check failed for DocID {document_id} (encrypted data)", user_id=current_user.id)
        return redirect(url_for('documents.list_documents'))

    # Read the encrypted file content first
    try:
        with open(document.file_path, 'rb') as f:
            encrypted_data = f.read() # Read file content into encrypted_data
    except IOError as e:
        flash(f'Error reading file: {e}', 'error')
        log_action(action=f"IOError reading file for DocID {document_id}: {document.file_path}", user_id=current_user.id)
        return redirect(url_for('documents.list_documents'))

    # Now verify the signature using the read data
    if document.signature and document.owner.public_key_pem:
        try:
            if not verify_document_signature(document.owner.public_key_pem, document.signature, encrypted_data):
                flash('File signature verification failed. The file might be corrupted or tampered with.', 'error')
                log_action(action=f"Signature verification failed for DocID {document_id}", user_id=current_user.id)
                return redirect(url_for('documents.list_documents'))
        except InvalidSignature: # Catching specific InvalidSignature exception
            flash('File signature is invalid. The file may have been tampered with or the key is incorrect.', 'error')
            log_action(action=f"InvalidSignature exception for DocID {document_id}", user_id=current_user.id)
            return redirect(url_for('documents.list_documents'))
        except Exception as e: # Catch other potential errors during verification
            flash(f'An unexpected error occurred during signature verification: {str(e)}', 'error')
            log_action(action=f"Unexpected error during signature verification for DocID {document_id}: {str(e)}", user_id=current_user.id)
            return redirect(url_for('documents.list_documents'))
    elif document.signature or document.owner.public_key_pem: # Case where one is present but not both
        flash('Signature or public key is partially missing. Cannot reliably verify signature.', 'warning')
        log_action(action=f"Signature or public key partially missing for DocID {document_id}. Download proceeded without full verification.", user_id=current_user.id)
        # Depending on security policy, you might choose to prevent download here
    else: # Case where neither signature nor public key is present
        log_action(action=f"Signature and public key missing for DocID {document_id}, skipping signature verification.", user_id=current_user.id)
        # flash('This document does not have a signature to verify.', 'info')

    # Decrypt the data
    decrypted_data = decrypt_file_data(encrypted_data)
    if decrypted_data is None:
        flash('Failed to decrypt the file. It might be corrupted or the encryption key has changed.', 'error')
        log_action(action=f"Decryption failed for DocID {document_id}", user_id=current_user.id)
        return redirect(url_for('documents.list_documents'))
    flash('Signature verification successful. The document is downloaded.')
    log_action(action=f"Downloaded file: {document.filename}", user_id=current_user.id, details=f"Document ID: {document_id}")
    return send_file(
        io.BytesIO(decrypted_data),
        download_name=document.filename,
        as_attachment=True,
        mimetype='application/octet-stream'
    )

@documents_bp.route('/edit_name/<int:document_id>', methods=['GET', 'POST'])
@login_required
def edit_document_name(document_id):
    document = Document.query.get_or_404(document_id)
    if current_user.role != 'admin':
        flash('You do not have permission to edit document names.', 'danger')
        log_action(action=f"Unauthorized document name edit attempt: DocID {document_id}", user_id=current_user.id)
        return redirect(url_for('documents.list_documents'))
    if request.method == 'POST':
        new_filename = request.form.get('filename')
        if not new_filename or len(new_filename) < 1:
            flash('Document name cannot be empty.', 'error')
            return render_template('edit_document_name.html', document=document, current_page='edit_document_name')
        old_filename = document.filename
        document.filename = new_filename
        db.session.commit()
        log_action(
            action=f"Admin edited document name",
            user_id=current_user.id,
            details=f"Document ID: {document_id}, Old name: {old_filename}, New name: {new_filename}"
        )
        flash(f'Document name updated successfully from "{old_filename}" to "{new_filename}".', 'success')
        return redirect(url_for('documents.list_documents'))
    return render_template('edit_document_name.html', document=document, current_page='edit_document_name')

@documents_bp.route('/delete/<int:document_id>', methods=['POST'])
@login_required
def delete_document(document_id):
    document = Document.query.get_or_404(document_id)
    if document.owner.id != current_user.id and current_user.role != 'admin':
        flash('You do not have permission to delete this file.', 'danger')
        log_action(action=f"Unauthorized delete attempt: DocID {document_id}", user_id=current_user.id)
        return redirect(url_for('documents.list_documents'))
    try:
        filename_for_log = document.filename
        file_path = document.file_path
        if os.path.exists(file_path):
            os.remove(file_path)
            log_action(action=f"Deleted file from disk: {file_path}", user_id=current_user.id)
        db.session.delete(document)
        db.session.commit()
        log_action(action=f"Deleted file: {filename_for_log}", user_id=current_user.id, details=f"Document ID: {document_id}")
        flash(f'File "{filename_for_log}" deleted successfully.', 'success')
    except Exception as e:
        db.session.rollback()
        log_action(action=f"Error deleting file (DocID {document_id}): {str(e)}", user_id=current_user.id)
        flash(f'An error occurred while deleting the file: {str(e)}', 'error')
    return redirect(url_for('documents.list_documents'))

@documents_bp.route('/verify-integrity/<int:document_id>')
@login_required
def verify_integrity(document_id):
    document = Document.query.get_or_404(document_id)
    if document.owner.id != current_user.id and current_user.role != 'admin':
        flash('You do not have permission to verify this file.', 'danger')
        log_action(action=f"Unauthorized integrity verification attempt: DocID {document_id}", user_id=current_user.id)
        return redirect(url_for('documents.list_documents'))
    try:
        if not os.path.exists(document.file_path):
            flash('File not found on the server.', 'error')
            log_action(action=f"File not found for integrity check: DocID {document_id}", user_id=current_user.id)
            return redirect(url_for('documents.list_documents'))
        integrity_result = verify_document_integrity(document.file_path, document.hash, document.hmac)
        if integrity_result:
            flash('Document integrity verified successfully! The file has not been tampered with.', 'success')
            log_action(action=f"Document integrity verified: DocID {document_id}", user_id=current_user.id, details="Integrity check passed")
        else:
            flash('WARNING: Document integrity check failed! The file may have been tampered with or corrupted.', 'danger')
            log_action(action=f"Document integrity check failed: DocID {document_id}", user_id=current_user.id, details="Hash or HMAC mismatch detected")
    except Exception as e:
        flash(f'An error occurred during integrity verification: {str(e)}', 'error')
        log_action(action=f"Error during document integrity verification: {str(e)}", user_id=current_user.id, details=f"Document ID: {document_id}")
    return redirect(url_for('documents.list_documents'))

@documents_bp.route('/doctor_visits', methods=['GET', 'POST'])
@login_required
def manage_doctor_visits():
    if request.method == 'POST':
        if current_user.role != 'user':
            flash('Only users can add doctor visits.', 'error')
            return redirect(url_for('documents.manage_doctor_visits'))
        visit_date = request.form.get('visit_date')
        doctor_name = request.form.get('doctor_name')
        notes = request.form.get('notes')
        if not all([visit_date, doctor_name]):
            flash('Visit date and doctor name are required.', 'error')
            return redirect(url_for('documents.manage_doctor_visits'))
        try:
            visit_date = datetime.strptime(visit_date, '%Y-%m-%d')
            new_visit = DoctorVisit(
                user_id=current_user.id,
                visit_date=visit_date,
                doctor_name=doctor_name,
                notes=notes
            )
            db.session.add(new_visit)
            db.session.commit()
            log_action(action=f"Added doctor visit: {doctor_name} on {visit_date}", user_id=current_user.id)
            flash('Doctor visit added successfully!', 'success')
            return redirect(url_for('documents.dashboard'))
        except Exception as e:
            db.session.rollback()
            log_action(action=f"Error adding doctor visit: {str(e)}", user_id=current_user.id)
            flash(f'Error adding doctor visit: {str(e)}', 'error')
            return redirect(url_for('documents.manage_doctor_visits'))
    visits = DoctorVisit.query.order_by(DoctorVisit.visit_date.desc()).all() if current_user.role in ['admin', 'doctor'] else DoctorVisit.query.filter_by(user_id=current_user.id).order_by(DoctorVisit.visit_date.desc()).all()
    return render_template('doctor_visits.html', visits=visits, current_page='doctor_visits')

@documents_bp.route('/diagnoses', methods=['GET', 'POST'])
@login_required
def manage_diagnoses():
    if request.method == 'POST':
        if current_user.role != 'doctor':
            flash('Only doctors can add diagnoses.', 'error')
            return redirect(url_for('documents.manage_diagnoses'))
        user_id = request.form.get('user_id')
        condition = request.form.get('condition')
        diagnosis_date = request.form.get('diagnosis_date')
        visit_id = request.form.get('visit_id')
        details = request.form.get('details')
        if not all([user_id, condition, diagnosis_date]):
            flash('User, condition, and diagnosis date are required.', 'error')
            return redirect(url_for('documents.manage_diagnoses'))
        try:
            user = User.query.get(user_id)
            if not user or user.role != 'user':
                flash('Invalid user selected.', 'error')
                return redirect(url_for('documents.manage_diagnoses'))
            diagnosis_date = datetime.strptime(diagnosis_date, '%Y-%m-%d')
            visit_id = int(visit_id) if visit_id else None
            if visit_id:
                visit = DoctorVisit.query.get(visit_id)
                if not visit or visit.user_id != int(user_id):
                    flash('Invalid doctor visit selected.', 'error')
                    return redirect(url_for('documents.manage_diagnoses'))
            new_diagnosis = Diagnosis(
                user_id=user_id,
                visit_id=visit_id,
                condition=condition,
                diagnosis_date=diagnosis_date,
                details=details
            )
            db.session.add(new_diagnosis)
            db.session.commit()
            log_action(action=f"Added diagnosis: {condition} on {diagnosis_date} for user {user.email}", user_id=current_user.id)
            flash('Diagnosis added successfully!', 'success')
            return redirect(url_for('documents.doctor_dashboard') if current_user.role == 'doctor' else url_for('documents.dashboard'))
        except Exception as e:
            db.session.rollback()
            log_action(action=f"Error adding diagnosis: {str(e)}", user_id=current_user.id)
            flash(f'Error adding diagnosis: {str(e)}', 'error')
            return redirect(url_for('documents.manage_diagnoses'))
    if current_user.role in ['admin', 'doctor']:
        diagnoses = Diagnosis.query.order_by(Diagnosis.diagnosis_date.desc()).all()
        visits = DoctorVisit.query.all()
        users = User.query.filter_by(role='user').all()
    else:
        diagnoses = Diagnosis.query.filter_by(user_id=current_user.id).order_by(Diagnosis.diagnosis_date.desc()).all()
        visits = DoctorVisit.query.filter_by(user_id=current_user.id).all()
        users = []
    return render_template('diagnoses.html', diagnoses=diagnoses, visits=visits, users=users, current_page='diagnoses')

@documents_bp.route('/prescriptions', methods=['GET', 'POST'])
@login_required
def manage_prescriptions():
    if request.method == 'POST':
        if current_user.role != 'doctor':
            flash('Only doctors can add prescriptions.', 'error')
            return redirect(url_for('documents.manage_prescriptions'))
        user_id = request.form.get('user_id')
        medication = request.form.get('medication')
        dosage = request.form.get('dosage')
        prescribed_date = request.form.get('prescribed_date')
        visit_id = request.form.get('visit_id')
        instructions = request.form.get('instructions')
        if not all([user_id, medication, prescribed_date]):
            flash('User, medication, and prescribed date are required.', 'error')
            return redirect(url_for('documents.manage_prescriptions'))
        try:
            user = User.query.get(user_id)
            if not user or user.role != 'user':
                flash('Invalid user selected.', 'error')
                return redirect(url_for('documents.manage_prescriptions'))
            prescribed_date = datetime.strptime(prescribed_date, '%Y-%m-%d')
            visit_id = int(visit_id) if visit_id else None
            if visit_id:
                visit = DoctorVisit.query.get(visit_id)
                if not visit or visit.user_id != int(user_id):
                    flash('Invalid doctor visit selected.', 'error')
                    return redirect(url_for('documents.manage_prescriptions'))
            new_prescription = Prescription(
                user_id=user_id,
                visit_id=visit_id,
                medication=medication,
                dosage=dosage,
                prescribed_date=prescribed_date,
                instructions=instructions
            )
            db.session.add(new_prescription)
            db.session.commit()
            log_action(action=f"Added prescription: {medication} on {prescribed_date} for user {user.email}", user_id=current_user.id)
            flash('Prescription added successfully!', 'success')
            return redirect(url_for('documents.doctor_dashboard') if current_user.role == 'doctor' else url_for('documents.dashboard'))
        except Exception as e:
            db.session.rollback()
            log_action(action=f"Error adding prescription: {str(e)}", user_id=current_user.id)
            flash(f'Error adding prescription: {str(e)}', 'error')
            return redirect(url_for('documents.manage_prescriptions'))
    if current_user.role in ['admin', 'doctor']:
        prescriptions = Prescription.query.order_by(Prescription.prescribed_date.desc()).all()
        visits = DoctorVisit.query.all()
        users = User.query.filter_by(role='user').all()
    else:
        prescriptions = Prescription.query.filter_by(user_id=current_user.id).order_by(Prescription.prescribed_date.desc()).all()
        visits = DoctorVisit.query.filter_by(user_id=current_user.id).all()
        users = []
    return render_template('prescriptions.html', prescriptions=prescriptions, visits=visits, users=users, current_page='prescriptions')

@documents_bp.route('/todo', methods=['GET', 'POST'])
@login_required
def manage_todo():
    if request.method == 'POST':
        if current_user.role != 'user':
            flash('Only users can add to-do items.', 'error')
            return redirect(url_for('documents.manage_todo'))
        task = request.form.get('task')
        due_date = request.form.get('due_date')
        completed = request.form.get('completed') == 'on'
        if not task:
            flash('Task description is required.', 'error')
            return redirect(url_for('documents.manage_todo'))
        try:
            due_date = datetime.strptime(due_date, '%Y-%m-%d') if due_date else None
            new_todo = TodoItem(
                user_id=current_user.id,
                task=task,
                due_date=due_date,
                completed=completed
            )
            db.session.add(new_todo)
            db.session.commit()
            log_action(action=f"Added todo item: {task}", user_id=current_user.id)
            flash('To-do item added successfully!', 'success')
            return redirect(url_for('documents.dashboard'))
        except Exception as e:
            db.session.rollback()
            log_action(action=f"Error adding todo item: {str(e)}", user_id=current_user.id)
            flash(f'Error adding to-do item: {str(e)}', 'error')
            return redirect(url_for('documents.manage_todo'))
    todos = TodoItem.query.order_by(TodoItem.created_at.desc()).all() if current_user.role == 'admin' else TodoItem.query.filter_by(user_id=current_user.id).order_by(TodoItem.created_at.desc()).all()
    return render_template('todo.html', todos=todos, current_page='todo')

@documents_bp.route('/todo/toggle/<int:todo_id>', methods=['POST'])
@login_required
def toggle_todo(todo_id):
    if current_user.role != 'user':
        flash('Only users can modify to-do items.', 'error')
        return redirect(url_for('documents.manage_todo'))
    todo = TodoItem.query.get_or_404(todo_id)
    if todo.user_id != current_user.id:
        flash('You do not have permission to modify this to-do item.', 'danger')
        log_action(action=f"Unauthorized todo toggle attempt: TodoID {todo_id}", user_id=current_user.id)
        return redirect(url_for('documents.manage_todo'))
    try:
        todo.completed = not todo.completed
        db.session.commit()
        status = "completed" if todo.completed else "pending"
        log_action(action=f"Todo item {status}: {todo.task}", user_id=current_user.id, details=f"Todo ID: {todo_id}")
        flash(f'To-do item marked as {status}.', 'success')
    except Exception as e:
        db.session.rollback()
        log_action(action=f"Error toggling todo item {todo_id}: {str(e)}", user_id=current_user.id)
        flash(f'Error updating to-do item: {str(e)}', 'error')
    return redirect(url_for('documents.manage_todo'))

@documents_bp.route('/mood', methods=['GET', 'POST'])
@login_required
def manage_mood():
    mood_options = [
        {'emoji': '😊', 'label': 'Happy', 'score': 5},
        {'emoji': '🙂', 'label': 'Good', 'score': 4},
        {'emoji': '😐', 'label': 'Neutral', 'score': 3},
        {'emoji': '😔', 'label': 'Sad', 'score': 2},
        {'emoji': '😢', 'label': 'Very Sad', 'score': 1}
    ]
    if request.method == 'POST':
        if current_user.role != 'user':
            flash('Only users can add mood entries.', 'error')
            return redirect(url_for('documents.manage_mood'))
        mood = request.form.get('mood')
        entry_date = request.form.get('entry_date')
        notes = request.form.get('notes')
        if not all([mood, entry_date]):
            flash('Mood and entry date are required.', 'error')
            return redirect(url_for('documents.manage_mood'))
        try:
            entry_date = datetime.strptime(entry_date, '%Y-%m-%d')
            selected_mood = next((m for m in mood_options if m['label'] == mood), None)
            if not selected_mood:
                flash('Invalid mood selected.', 'error')
                return redirect(url_for('documents.manage_mood'))
            new_mood = MoodEntry(
                user_id=current_user.id,
                mood=selected_mood['label'],
                mood_score=selected_mood['score'],
                entry_date=entry_date,
                notes=notes
            )
            db.session.add(new_mood)
            db.session.commit()
            log_action(action=f"Added mood entry: {mood} on {entry_date}", user_id=current_user.id)
            flash('Mood entry added successfully!', 'success')
            return redirect(url_for('documents.dashboard'))
        except Exception as e:
            db.session.rollback()
            log_action(action=f"Error adding mood entry: {str(e)}", user_id=current_user.id)
            flash(f'Error adding mood entry: {str(e)}', 'error')
            return redirect(url_for('documents.manage_mood'))
    moods = MoodEntry.query.order_by(MoodEntry.entry_date.desc()).all() if current_user.role in ['admin', 'doctor'] else MoodEntry.query.filter_by(user_id=current_user.id).order_by(MoodEntry.entry_date.desc()).all()
    return render_template('mood.html', moods=moods, mood_options=mood_options, current_page='mood')



@rbac_bp.route('/users')
@login_required
def list_users():
    if current_user.role != 'admin':
        flash('You do not have permission to access this page.', 'danger')
        return redirect(url_for('documents.dashboard'))
    page = request.args.get('page', 1, type=int)
    per_page = 10
    search_query = request.args.get('search', '')
    query = User.query
    if search_query:
        query = query.filter(User.email.ilike(f'%{search_query}%'))
    user_pagination = query.order_by(User.email).paginate(page=page, per_page=per_page)
    all_users = user_pagination.items
    return render_template('admin/users.html', users=all_users, pagination=user_pagination, current_page='list_users', search_query=search_query)

@rbac_bp.route('/user/edit/<int:user_id>', methods=['GET', 'POST'])
@login_required
def edit_user(user_id):
    if current_user.role != 'admin':
        flash('You do not have permission to edit users.', 'danger')
        return redirect(url_for('documents.dashboard'))
    user_to_edit = User.query.get_or_404(user_id)
    if request.method == 'POST':
        new_role = request.form.get('role')
        if new_role not in get_roles():
            flash('Invalid role selected.', 'error')
        else:
            if user_to_edit.id == current_user.id and user_to_edit.role == 'admin' and new_role != 'admin':
                flash('You cannot remove your own admin role.', 'warning')
            else:
                old_role = user_to_edit.role
                user_to_edit.role = new_role
                db.session.commit()
                log_action(action=f"User role changed for {user_to_edit.email} from {old_role} to {new_role}", user_id=current_user.id)
                flash(f'User role for {user_to_edit.email} updated successfully.', 'success')
                return redirect(url_for('rbac.list_users'))
    return render_template('admin/edit_user.html', user_to_edit=user_to_edit, roles=get_roles(), current_page='edit_user')

@rbac_bp.route('/user/delete/<int:user_id>', methods=['POST'])
@login_required
def delete_user(user_id):
    if current_user.role != 'admin':
        flash('You do not have permission to delete users.', 'danger')
        return redirect(url_for('documents.dashboard'))
    user_to_delete = User.query.get_or_404(user_id)
    if user_to_delete.id == current_user.id:
        flash('You cannot delete your own account.', 'error')
        return redirect(url_for('rbac.list_users'))
    try:
        email_deleted_log = user_to_delete.email
        db.session.delete(user_to_delete)
        db.session.commit()
        log_action(action=f"User deleted: {email_deleted_log}", user_id=current_user.id)
        flash(f'User {email_deleted_log} deleted successfully.', 'success')
    except Exception as e:
        db.session.rollback()
        log_action(action=f"Error deleting user {user_to_delete.email}: {str(e)}", user_id=current_user.id)
        flash(f'An error occurred while deleting the user: {str(e)}', 'error')
    return redirect(url_for('rbac.list_users'))

@rbac_bp.route('/user/add', methods=['GET', 'POST'])
@login_required
def add_user():
    if current_user.role != 'admin':
        flash('Access denied: Admins only', 'danger')
        return redirect(url_for('documents.dashboard'))
    if request.method == 'POST':
        email = request.form.get('email')
        role = request.form.get('role')
        if not all([email, role]):
            flash('All fields are required', 'error')
            return redirect(url_for('rbac.add_user'))
        if role not in get_roles():
            flash('Invalid role selected', 'error')
            return redirect(url_for('rbac.add_user'))
        if not validate_email(email):
            flash('Invalid email address', 'error')
            return redirect(url_for('rbac.add_user'))
        if User.query.filter_by(email=email).first():
            flash('Email already exists', 'warning')
            return redirect(url_for('rbac.add_user'))
        temp_password = os.urandom(8).hex()
        new_user = User(
            email=email,
            password=generate_password_hash(temp_password, method='pbkdf2:sha256'),
            role=role
        )
        db.session.add(new_user)
        db.session.commit()
        log_action(
            action=f"Admin created user: {email}",
            user_id=current_user.id,
            details=f"Role: {role}, Temp password: {temp_password}"
        )
        flash(f'User {email} created successfully! Temporary password: {temp_password}', 'success')
        return redirect(url_for('rbac.list_users'))
    return render_template('admin/add_user.html', current_page='add_user')

@rbac_bp.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    if request.method == 'POST':
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        confirm_new_password = request.form.get('confirm_new_password')
        if new_password:
            if not current_user.password:
                flash("You cannot change your password as your account was created via OAuth and does not have a local password. You can set one if you wish.", "info")
            elif not current_password or not check_password_hash(current_user.password, current_password):
                flash('Your current password is incorrect.', 'error')
            elif new_password != confirm_new_password:
                flash('The new passwords do not match.', 'error')
            elif not validate_password(new_password):
                flash('The new password must be at least 12 characters long and include uppercase, lowercase, numbers, and special characters.', 'error')
            else:
                current_user.password = generate_password_hash(new_password, method='pbkdf2:sha256')
                db.session.commit()
                log_action(action="User changed password", user_id=current_user.id)
                flash('Your password has been updated successfully.', 'success')
                return redirect(url_for('rbac.profile'))
        else:
            if not any(request.form.values()):
                flash('No changes were submitted.', 'info')
    return render_template('profile.html', current_page='profile')



@security_bp.route('/audit_logs')
@login_required
def audit_logs_list():
    if current_user.role != 'admin':
        flash('You do not have permission to access this page.', 'danger')
        return redirect(url_for('documents.dashboard'))
    page = request.args.get('page', 1, type=int)
    per_page = 15
    search_query = request.args.get('search', '')
    query = AuditLog.query
    if search_query:
        query = query.join(User, AuditLog.user_id == User.id, isouter=True).filter(
            db.or_(
                AuditLog.action.ilike(f'%{search_query}%'),
                User.email.ilike(f'%{search_query}%'),
                AuditLog.details.ilike(f'%{search_query}%')
            )
        )
    log_pagination = query.order_by(AuditLog.timestamp.desc()).paginate(page=page, per_page=per_page)
    logs = log_pagination.items
    return render_template('admin/audit_logs.html', logs=logs, pagination=log_pagination, current_page='audit_logs', search_query=search_query)

app.config['SESSION_PERMANENT'] = False
app.config['SESSION_USE_SIGNER'] = True

@app.before_request
def before_request():
    if current_user.is_authenticated:
        g.user_id = current_user.id
        session_start = session.get('session_start_time')
        if session_start:
            session_duration = datetime.utcnow().timestamp() - session_start
            if session_duration > 900:  # 15 minutes
                user_id_for_log = current_user.id
                user_email_for_log = current_user.email
                logout_user()
                session.clear()
                log_action(
                    action="User auto-logged out due to session timeout",
                    user_id=user_id_for_log,
                    details=f"User {user_email_for_log} (ID: {user_id_for_log}) was logged out after 15-minute session timeout."
                )
                flash('Your session has expired after 15 minutes. Please log in again.', 'info')
                return redirect(url_for('auth.login'))
        # Check if admin is using default password
        if current_user.role == 'admin' and current_user.email == 'admin@example.com':
            if check_password_hash(current_user.password, os.environ.get('DEFAULT_ADMIN_PASSWORD', 'AdminSecure123!')):
                flash('You are using the default admin password. Please change it immediately for security.', 'warning')

@app.teardown_request
def teardown_request(exception=None):
    if hasattr(g, 'user_id') and g.user_id is not None:
        if not current_user.is_authenticated:
            user = User.query.get(g.user_id)
            if user:
                log_action(
                    action="User session ended",
                    user_id=g.user_id,
                    details=f"User {user.email} (ID: {g.user_id}) left the website."
                )
        delattr(g, 'user_id')

app.register_blueprint(auth_bp, url_prefix='/auth')
app.register_blueprint(documents_bp, url_prefix='/documents')
app.register_blueprint(rbac_bp, url_prefix='/admin/rbac')
app.register_blueprint(security_bp, url_prefix='/admin/security')

@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('documents.dashboard') if current_user.role in ['user', 'admin'] else url_for('documents.doctor_dashboard'))
    return redirect(url_for('auth.login'))

@app.errorhandler(404)
def not_found_error(error):
    log_action(action=f"404 Not Found: {request.url}", user_id=current_user.id if current_user.is_authenticated else None)
    flash('The page you were looking for could not be found. You have been redirected to the homepage.', 'info')
    if current_user.is_authenticated:
        return redirect(url_for('documents.dashboard') if current_user.role in ['user', 'admin'] else url_for('documents.doctor_dashboard'))
    return redirect(url_for('auth.login'))

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    log_action(action=f"500 Internal Server Error: {request.url} - Error: {str(error)}", user_id=current_user.id if current_user.is_authenticated else None)
    return render_template('errors/500.html'), 500

@app.errorhandler(403)
def forbidden_error(error):
    log_action(action=f"403 Forbidden: {request.url}", user_id=current_user.id if current_user.is_authenticated else None)
    return render_template('errors/403.html'), 403

@app.errorhandler(401)
def unauthorized_access(error):
    log_action(action=f"401 Unauthorized (handler): {request.url}", user_id=current_user.id if current_user.is_authenticated else None)
    flash("You need to be logged in to access this page.", "warning")
    return redirect(url_for('auth.login'))

@app.context_processor
def inject_global_vars():
    is_admin_user = current_user.is_authenticated and current_user.role == 'admin'
    is_doctor_user = current_user.is_authenticated and current_user.role == 'doctor'
    return dict(is_admin_user=is_admin_user, is_doctor_user=is_doctor_user)

# Create database tables if they don't exist and default admin user
with app.app_context():
    db.create_all()
    print("Database tables created or already exist.")
    
    # Create a default admin user if one doesn't exist
    ADMIN_EMAIL = app.config.get('ADMIN_EMAIL', 'admin@example.com')
    ADMIN_PASSWORD = app.config.get('ADMIN_PASSWORD', 'AdminSecure123!') # Ensure this is strong
    
    if not User.query.filter_by(email=ADMIN_EMAIL).first():
        hashed_password = generate_password_hash(ADMIN_PASSWORD, method='pbkdf2:sha256')
        admin_user = User(
            email=ADMIN_EMAIL,
            password=hashed_password,
            role='admin',
            # Assuming 'name' is not a required field or has a default
            # If 'name' or other fields are mandatory and don't have defaults:
            # name='Default Admin Name' # Example
        )
        db.session.add(admin_user)
        try:
            db.session.commit()
            print(f"Default admin user '{ADMIN_EMAIL}' created successfully.")
        except Exception as e:
            db.session.rollback()
            print(f"Failed to create default admin user '{ADMIN_EMAIL}': {e}")

if __name__ == '__main__':
    flask_debug = os.environ.get('FLASK_DEBUG', 'False').lower() in ('true', '1', 't')
    run_host = os.environ.get('HOST', '0.0.0.0')
    run_port = int(os.environ.get('PORT', 5000))
    if app.config['USE_SSL_DEV'] and flask_debug:
        import ssl
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certfile='localhost.crt', keyfile='localhost.key') 
        app.run(debug=flask_debug, host=run_host, port=run_port, ssl_context=context)
    else:
        app.run(debug=flask_debug, host=run_host, port=run_port)