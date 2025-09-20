from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail, Message
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import re
import secrets
import uuid
import os
from functools import wraps
from werkzeug.utils import secure_filename
from PIL import Image
import threading
import asyncio
from aiosmtpd.controller import Controller
import time
import socket
from flask_dance.contrib.google import make_google_blueprint, google
from flask_dance.consumer import oauth_authorized, oauth_error
from flask_dance.consumer.storage.sqla import SQLAlchemyStorage, OAuthConsumerMixin
from sqlalchemy.orm.exc import NoResultFound
import requests
from flask_login import current_user, LoginManager, login_user, UserMixin, logout_user
import folium
from flask_cors import CORS
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity, create_refresh_token
import logging
from logging.handlers import RotatingFileHandler

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)

# Configuration
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', secrets.token_hex(32))
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///banking.db').replace('postgres://', 'postgresql://')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif', 'webp'}
app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024  # 5MB max

# JWT Configuration
app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY', secrets.token_hex(32))
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=24)
app.config['JWT_REFRESH_TOKEN_EXPIRES'] = timedelta(days=30)

# Email Configuration
app.config['MAIL_SERVER'] = os.environ.get('MAIL_SERVER', 'smtp.gmail.com')
app.config['MAIL_PORT'] = int(os.environ.get('MAIL_PORT', 587))
app.config['MAIL_USE_TLS'] = os.environ.get('MAIL_USE_TLS', 'True').lower() == 'true'
app.config['MAIL_USE_SSL'] = os.environ.get('MAIL_USE_SSL', 'False').lower() == 'true'
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME', '')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD', '')
app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('MAIL_DEFAULT_SENDER', 'noreply@ghanabank.com')

# Google OAuth Configuration
app.config['GOOGLE_OAUTH_CLIENT_ID'] = os.environ.get('GOOGLE_OAUTH_CLIENT_ID')
app.config['GOOGLE_OAUTH_CLIENT_SECRET'] = os.environ.get('GOOGLE_OAUTH_CLIENT_SECRET')

# CORS Configuration
CORS(app, origins=[
    "http://localhost:5000",
    "http://127.0.0.1:5000",
    "http://localhost",
    "http://10.0.2.2:5000",
    "https://*.onrender.com",
    "http://localhost:8081",
    "http://127.0.0.1:8081",
], supports_credentials=True)

# Ensure upload folder exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Initialize extensions
db = SQLAlchemy(app)
mail = Mail(app)
jwt = JWTManager(app)

# Setup login manager
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Database Models
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    full_name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    phone = db.Column(db.String(20), unique=True, nullable=True)
    date_of_birth = db.Column(db.Date, nullable=True)
    gps_address = db.Column(db.String(20), nullable=True)
    ghana_card_id = db.Column(db.String(20), unique=True, nullable=True)
    password_hash = db.Column(db.String(255), nullable=True)
    checking_account = db.Column(db.String(20), nullable=True)
    savings_account = db.Column(db.String(20), nullable=True)
    checking_balance = db.Column(db.Float, default=0.00)
    savings_balance = db.Column(db.Float, default=0.00)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_verified = db.Column(db.Boolean, default=False)
    reset_token = db.Column(db.String(100), nullable=True)
    reset_token_expiry = db.Column(db.DateTime, nullable=True)
    profile_image = db.Column(db.String(100), nullable=True)
    google_id = db.Column(db.String(100), unique=True, nullable=True)
    refresh_token = db.Column(db.String(255), nullable=True)
    
    wallet_fundings = db.relationship('WalletFunding', backref='user', lazy=True)
    oauth_tokens = db.relationship('OAuth', back_populates='user', lazy=True)
    transactions = db.relationship('Transaction', backref='user', lazy=True)
    bill_payments = db.relationship('BillPayment', backref='user', lazy=True)
    budgets = db.relationship('Budget', backref='user', lazy=True)
    external_accounts = db.relationship('ExternalBankAccount', backref='user', lazy=True)
    external_transactions = db.relationship('ExternalTransaction', backref='user', lazy=True)

class OAuth(OAuthConsumerMixin, db.Model):
    provider_user_id = db.Column(db.String(256), unique=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    user = db.relationship('User', back_populates='oauth_tokens')

class Transaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    transaction_type = db.Column(db.String(50), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    description = db.Column(db.String(200), nullable=False)
    account_type = db.Column(db.String(20), nullable=False)
    balance_after = db.Column(db.Float, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    reference_id = db.Column(db.String(50), nullable=True)
    category = db.Column(db.String(50), nullable=True)

class BillPayment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    bill_type = db.Column(db.String(50), nullable=False)
    provider = db.Column(db.String(100), nullable=False)
    account_number = db.Column(db.String(50), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    payment_method = db.Column(db.String(20), nullable=False)
    status = db.Column(db.String(20), default='pending')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    reference_id = db.Column(db.String(50), nullable=True)

class WalletFunding(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    account_type = db.Column(db.String(20), nullable=False)
    reference_id = db.Column(db.String(50), unique=True, nullable=False)
    status = db.Column(db.String(20), default='pending')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Budget(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    category = db.Column(db.String(50), nullable=False)
    budget_amount = db.Column(db.Float, nullable=False)
    spent = db.Column(db.Float, default=0.0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    __table_args__ = (db.UniqueConstraint('user_id', 'category', name='_user_category_uc'),)

class ExternalBankAccount(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    bank_name = db.Column(db.String(100), nullable=False)
    account_name = db.Column(db.String(100), nullable=False)
    account_number = db.Column(db.String(50), nullable=False)
    bank_code = db.Column(db.String(20), nullable=True)
    is_verified = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class ExternalTransaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    bank_account_id = db.Column(db.Integer, db.ForeignKey('external_bank_account.id'), nullable=True)
    transaction_type = db.Column(db.String(20), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    description = db.Column(db.String(200), nullable=False)
    status = db.Column(db.String(20), default='pending')
    reference_id = db.Column(db.String(50), unique=True, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

# Create Google OAuth blueprint
google_blueprint = make_google_blueprint(
    client_id=app.config["GOOGLE_OAUTH_CLIENT_ID"],
    client_secret=app.config["GOOGLE_OAUTH_CLIENT_SECRET"],
    scope=["profile", "email"],
    redirect_to="google_callback",
    storage=SQLAlchemyStorage(OAuth, db.session, user=current_user)
)
app.register_blueprint(google_blueprint, url_prefix="/google_login")

# Bank and Mobile Money Providers
BANKS = {
    'ecobank': {'name': 'Ecobank Ghana', 'color': '#008C5A'},
    'gtbank': {'name': 'GTBank Ghana', 'color': '#043D75'},
    'absa': {'name': 'Absa Bank Ghana', 'color': '#E4002B'},
    'calbank': {'name': 'CAL Bank', 'color': '#0033A0'},
    'fidelity': {'name': 'Fidelity Bank Ghana', 'color': '#8CC63F'},
    'stanbic': {'name': 'Stanbic Bank Ghana', 'color': '#0065A4'},
    'republic': {'name': 'Republic Bank Ghana', 'color': '#E21836'},
    'zenith': {'name': 'Zenith Bank Ghana', 'color': '#002B45'},
    'access': {'name': 'Access Bank Ghana', 'color': '#E41E26'},
    'adb': {'name': 'Agricultural Development Bank', 'color': '#008752'},
}

MOBILE_MONEY = {
    'mtn': {'name': 'MTN Mobile Money', 'color': '#FFCC00'},
    'vodafone': {'name': 'Vodafone Cash', 'color': '#E60000'},
    'airteltigo': {'name': 'AirtelTigo Money', 'color': '#E10070'},
}

BILL_TYPES = {
    'utilities': 'Utilities',
    'mobile': 'Mobile',
    'school': 'School Fees',
    'tv': 'TV Subscription',
    'internet': 'Internet'
}

# Utility Functions
def validate_ghana_card(card_id):
    if not card_id:
        return True
    pattern = r'^GHA-\d{9}-\d{1}$'
    return re.match(pattern, card_id) is not None

def validate_gps_address(address):
    if not address:
        return True
    pattern = r'^[A-Z]{2}-\d{4}-\d{4}$'
    return re.match(pattern, address) is not None

def validate_phone(phone):
    if not phone:
        return True
    pattern = r'^0[2345][0-9]{8}$'
    return re.match(pattern, phone) is not None

def validate_password(password):
    if not password:
        return False, "Password is required"
    
    if len(password) < 8:
        return False, "Password must be at least 8 characters long"
    
    if not re.search(r'[A-Z]', password):
        return False, "Password must contain at least one uppercase letter"
    
    if not re.search(r'[a-z]', password):
        return False, "Password must contain at least one lowercase letter"
    
    if not re.search(r'[0-9]', password):
        return False, "Password must contain at least one number"
    
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        return False, "Password must contain at least one special character"
    
    return True, "Password is valid"

def generate_account_number():
    return f"GB{secrets.randbelow(900000) + 100000}"

def generate_reference_id(prefix="TXN"):
    return f"{prefix}{secrets.token_hex(8).upper()}"

def create_transaction(user_id, transaction_type, amount, description, account_type, balance_after, category=None):
    transaction = Transaction(
        user_id=user_id,
        transaction_type=transaction_type,
        amount=amount,
        description=description,
        account_type=account_type,
        balance_after=balance_after,
        reference_id=generate_reference_id(),
        category=category
    )
    db.session.add(transaction)
    return transaction

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

def save_profile_image(file, user_id):
    if file and allowed_file(file.filename):
        filename = secure_filename(f"{user_id}_{int(datetime.now().timestamp())}.webp")
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        
        try:
            img = Image.open(file.stream)
            img.thumbnail((200, 200))
            
            if img.mode in ('RGBA', 'LA'):
                background = Image.new('RGB', img.size, (255, 255, 255))
                background.paste(img, mask=img.split()[-1])
                img = background
            
            img.save(filepath, 'WEBP', quality=80)
            return filename
        except Exception as e:
            logger.error(f"Error processing image: {e}")
            return None
    return None

def send_email(to, subject, template, **kwargs):
    try:
        if not app.config['MAIL_USERNAME'] or not app.config['MAIL_PASSWORD']:
            logger.warning("Email not configured. Skipping email send.")
            return True
            
        msg = Message(subject, recipients=[to])
        msg.html = render_template(template, **kwargs)
        mail.send(msg)
        logger.info(f"Email sent to {to}")
        return True
    except Exception as e:
        logger.error(f"Email sending failed: {e}")
        return False

# JWT callbacks
@jwt.expired_token_loader
def expired_token_callback(jwt_header, jwt_payload):
    return jsonify({'success': False, 'message': 'Token has expired'}), 401

@jwt.invalid_token_loader
def invalid_token_callback(error):
    return jsonify({'success': False, 'message': 'Invalid token'}), 401

@jwt.unauthorized_loader
def missing_token_callback(error):
    return jsonify({'success': False, 'message': 'Authentication required'}), 401

# Google OAuth Handlers
@oauth_authorized.connect_via(google_blueprint)
def google_logged_in(blueprint, token):
    if not token:
        return False
    
    try:
        resp = blueprint.session.get("https://www.googleapis.com/oauth2/v1/userinfo")
        if not resp.ok:
            return False
        
        google_info = resp.json()
        google_id = str(google_info["id"])
        email = google_info["email"]
        full_name = google_info.get("name", email.split("@")[0])
        
        # Find or create user
        user = User.query.filter_by(email=email).first()
        if not user:
            user = User(
                full_name=full_name,
                email=email,
                google_id=google_id,
                checking_account=generate_account_number(),
                savings_account=generate_account_number(),
                is_verified=True
            )
            db.session.add(user)
            db.session.commit()
        
        # Find or create OAuth token
        oauth = OAuth.query.filter_by(provider=blueprint.name, provider_user_id=google_id).first()
        if not oauth:
            oauth = OAuth(
                provider=blueprint.name,
                provider_user_id=google_id,
                token=token,
                user_id=user.id
            )
            db.session.add(oauth)
        else:
            oauth.token = token
        
        db.session.commit()
        login_user(user)
        
        return False
    except Exception as e:
        logger.error(f"Google OAuth error: {e}")
        return False

@oauth_error.connect_via(google_blueprint)
def google_error(blueprint, error, error_description=None, error_uri=None):
    logger.error(f"OAuth error: {error}, {error_description}")

# API Routes
@app.route('/api/health', methods=['GET'])
def api_health():
    return jsonify({'success': True, 'message': 'Server is healthy', 'timestamp': datetime.utcnow().isoformat()})

@app.route('/api/auth/register', methods=['POST'])
def api_register():
    try:
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'message': 'No data provided'}), 400
        
        # Validate required fields
        required_fields = ['full_name', 'email', 'password', 'confirm_password']
        for field in required_fields:
            if not data.get(field):
                return jsonify({'success': False, 'message': f'{field.replace("_", " ").title()} is required'}), 400
        
        if data['password'] != data['confirm_password']:
            return jsonify({'success': False, 'message': 'Passwords do not match'}), 400
        
        is_valid, message = validate_password(data['password'])
        if not is_valid:
            return jsonify({'success': False, 'message': message}), 400
        
        if not validate_email(data['email']):
            return jsonify({'success': False, 'message': 'Invalid email format'}), 400
        
        if User.query.filter_by(email=data['email']).first():
            return jsonify({'success': False, 'message': 'Email already registered'}), 400
        
        if data.get('phone') and User.query.filter_by(phone=data['phone']).first():
            return jsonify({'success': False, 'message': 'Phone number already registered'}), 400
        
        if data.get('ghana_card_id') and not validate_ghana_card(data['ghana_card_id']):
            return jsonify({'success': False, 'message': 'Invalid Ghana Card format'}), 400
        
        if data.get('gps_address') and not validate_gps_address(data['gps_address']):
            return jsonify({'success': False, 'message': 'Invalid GPS address format'}), 400
        
        if data.get('phone') and not validate_phone(data['phone']):
            return jsonify({'success': False, 'message': 'Invalid phone number format'}), 400
        
        # Create user
        user = User(
            full_name=data['full_name'],
            email=data['email'],
            phone=data.get('phone'),
            date_of_birth=datetime.strptime(data['date_of_birth'], '%Y-%m-%d').date() if data.get('date_of_birth') else None,
            gps_address=data.get('gps_address'),
            ghana_card_id=data.get('ghana_card_id'),
            password_hash=generate_password_hash(data['password']),
            checking_account=generate_account_number(),
            savings_account=generate_account_number(),
            is_verified=True
        )
        
        db.session.add(user)
        db.session.commit()
        
        # Create welcome transaction
        create_transaction(
            user.id,
            'credit',
            100.00,  # Welcome bonus
            'Welcome bonus',
            'checking',
            100.00,
            'bonus'
        )
        user.checking_balance = 100.00
        db.session.commit()
        
        # Generate tokens
        access_token = create_access_token(identity=user.id)
        refresh_token = create_refresh_token(identity=user.id)
        
        user.refresh_token = refresh_token
        db.session.commit()
        
        # Send welcome email
        send_email(
            user.email,
            'Welcome to Ghana Bank',
            'emails/welcome.html',
            user=user
        )
        
        return jsonify({
            'success': True,
            'message': 'Registration successful',
            'data': {
                'user': user_to_dict(user),
                'tokens': {
                    'access_token': access_token,
                    'refresh_token': refresh_token
                }
            }
        }), 201
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Registration error: {e}")
        return jsonify({'success': False, 'message': 'Registration failed'}), 500

@app.route('/api/auth/login', methods=['POST'])
def api_login():
    try:
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'message': 'No data provided'}), 400
        
        email_or_phone = data.get('email_or_phone')
        password = data.get('password')
        
        if not email_or_phone or not password:
            return jsonify({'success': False, 'message': 'Email/phone and password are required'}), 400
        
        user = User.query.filter(
            (User.email == email_or_phone) | (User.phone == email_or_phone)
        ).first()
        
        if not user or not user.password_hash or not check_password_hash(user.password_hash, password):
            return jsonify({'success': False, 'message': 'Invalid credentials'}), 401
        
        # Generate tokens
        access_token = create_access_token(identity=user.id)
        refresh_token = create_refresh_token(identity=user.id)
        
        user.refresh_token = refresh_token
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'Login successful',
            'data': {
                'user': user_to_dict(user),
                'tokens': {
                    'access_token': access_token,
                    'refresh_token': refresh_token
                }
            }
        })
        
    except Exception as e:
        logger.error(f"Login error: {e}")
        return jsonify({'success': False, 'message': 'Login failed'}), 500

@app.route('/api/auth/refresh', methods=['POST'])
@jwt_required(refresh=True)
def api_refresh():
    try:
        user_id = get_jwt_identity()
        user = User.query.get(user_id)
        
        if not user:
            return jsonify({'success': False, 'message': 'User not found'}), 404
        
        new_access_token = create_access_token(identity=user.id)
        
        return jsonify({
            'success': True,
            'message': 'Token refreshed',
            'data': {
                'access_token': new_access_token
            }
        })
        
    except Exception as e:
        logger.error(f"Token refresh error: {e}")
        return jsonify({'success': False, 'message': 'Token refresh failed'}), 500

@app.route('/api/auth/logout', methods=['POST'])
@jwt_required()
def api_logout():
    try:
        user_id = get_jwt_identity()
        user = User.query.get(user_id)
        
        if user:
            user.refresh_token = None
            db.session.commit()
        
        return jsonify({'success': True, 'message': 'Logout successful'})
        
    except Exception as e:
        logger.error(f"Logout error: {e}")
        return jsonify({'success': False, 'message': 'Logout failed'}), 500

@app.route('/api/auth/forgot-password', methods=['POST'])
def api_forgot_password():
    try:
        data = request.get_json()
        email = data.get('email')
        
        if not email:
            return jsonify({'success': False, 'message': 'Email is required'}), 400
        
        user = User.query.filter_by(email=email).first()
        if user:
            reset_token = secrets.token_urlsafe(32)
            user.reset_token = reset_token
            user.reset_token_expiry = datetime.utcnow() + timedelta(hours=1)
            db.session.commit()
            
            reset_link = f"{request.host_url}reset-password/{reset_token}"
            send_email(
                user.email,
                'Password Reset Request',
                'emails/password_reset.html',
                user=user,
                reset_link=reset_link
            )
        
        return jsonify({'success': True, 'message': 'If an account with that email exists, a reset link has been sent'})
        
    except Exception as e:
        logger.error(f"Forgot password error: {e}")
        return jsonify({'success': False, 'message': 'Password reset failed'}), 500

@app.route('/api/auth/reset-password', methods=['POST'])
def api_reset_password():
    try:
        data = request.get_json()
        token = data.get('token')
        password = data.get('password')
        confirm_password = data.get('confirm_password')
        
        if not token or not password or not confirm_password:
            return jsonify({'success': False, 'message': 'All fields are required'}), 400
        
        if password != confirm_password:
            return jsonify({'success': False, 'message': 'Passwords do not match'}), 400
        
        is_valid, message = validate_password(password)
        if not is_valid:
            return jsonify({'success': False, 'message': message}), 400
        
        user = User.query.filter_by(reset_token=token).first()
        if not user or user.reset_token_expiry < datetime.utcnow():
            return jsonify({'success': False, 'message': 'Invalid or expired reset token'}), 400
        
        user.password_hash = generate_password_hash(password)
        user.reset_token = None
        user.reset_token_expiry = None
        db.session.commit()
        
        return jsonify({'success': True, 'message': 'Password reset successful'})
        
    except Exception as e:
        logger.error(f"Reset password error: {e}")
        return jsonify({'success': False, 'message': 'Password reset failed'}), 500

@app.route('/api/user/profile', methods=['GET'])
@jwt_required()
def api_get_profile():
    try:
        user_id = get_jwt_identity()
        user = User.query.get(user_id)
        
        if not user:
            return jsonify({'success': False, 'message': 'User not found'}), 404
        
        return jsonify({
            'success': True,
            'data': {
                'user': user_to_dict(user)
            }
        })
        
    except Exception as e:
        logger.error(f"Get profile error: {e}")
        return jsonify({'success': False, 'message': 'Failed to fetch profile'}), 500

@app.route('/api/user/profile', methods=['PUT'])
@jwt_required()
def api_update_profile():
    try:
        user_id = get_jwt_identity()
        user = User.query.get(user_id)
        
        if not user:
            return jsonify({'success': False, 'message': 'User not found'}), 404
        
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'message': 'No data provided'}), 400
        
        # Update fields
        if 'full_name' in data:
            user.full_name = data['full_name']
        
        if 'phone' in data and data['phone'] != user.phone:
            if User.query.filter(User.phone == data['phone'], User.id != user.id).first():
                return jsonify({'success': False, 'message': 'Phone number already in use'}), 400
            if not validate_phone(data['phone']):
                return jsonify({'success': False, 'message': 'Invalid phone number format'}), 400
            user.phone = data['phone']
        
        if 'gps_address' in data and data['gps_address'] != user.gps_address:
            if not validate_gps_address(data['gps_address']):
                return jsonify({'success': False, 'message': 'Invalid GPS address format'}), 400
            user.gps_address = data['gps_address']
        
        if 'ghana_card_id' in data and data['ghana_card_id'] != user.ghana_card_id:
            if User.query.filter(User.ghana_card_id == data['ghana_card_id'], User.id != user.id).first():
                return jsonify({'success': False, 'message': 'Ghana Card ID already in use'}), 400
            if not validate_ghana_card(data['ghana_card_id']):
                return jsonify({'success': False, 'message': 'Invalid Ghana Card format'}), 400
            user.ghana_card_id = data['ghana_card_id']
        
        if 'date_of_birth' in data:
            try:
                user.date_of_birth = datetime.strptime(data['date_of_birth'], '%Y-%m-%d').date()
            except ValueError:
                return jsonify({'success': False, 'message': 'Invalid date format'}), 400
        
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'Profile updated successfully',
            'data': {
                'user': user_to_dict(user)
            }
        })
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Update profile error: {e}")
        return jsonify({'success': False, 'message': 'Failed to update profile'}), 500

@app.route('/api/user/change-password', methods=['POST'])
@jwt_required()
def api_change_password():
    try:
        user_id = get_jwt_identity()
        user = User.query.get(user_id)
        
        if not user:
            return jsonify({'success': False, 'message': 'User not found'}), 404
        
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'message': 'No data provided'}), 400
        
        current_password = data.get('current_password')
        new_password = data.get('new_password')
        confirm_password = data.get('confirm_password')
        
        if not current_password or not new_password or not confirm_password:
            return jsonify({'success': False, 'message': 'All fields are required'}), 400
        
        if new_password != confirm_password:
            return jsonify({'success': False, 'message': 'New passwords do not match'}), 400
        
        if not check_password_hash(user.password_hash, current_password):
            return jsonify({'success': False, 'message': 'Current password is incorrect'}), 400
        
        is_valid, message = validate_password(new_password)
        if not is_valid:
            return jsonify({'success': False, 'message': message}), 400
        
        user.password_hash = generate_password_hash(new_password)
        db.session.commit()
        
        return jsonify({'success': True, 'message': 'Password changed successfully'})
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Change password error: {e}")
        return jsonify({'success': False, 'message': 'Failed to change password'}), 500

@app.route('/api/user/upload-profile-image', methods=['POST'])
@jwt_required()
def api_upload_profile_image():
    try:
        user_id = get_jwt_identity()
        user = User.query.get(user_id)
        
        if not user:
            return jsonify({'success': False, 'message': 'User not found'}), 404
        
        if 'profile_image' not in request.files:
            return jsonify({'success': False, 'message': 'No file provided'}), 400
        
        file = request.files['profile_image']
        if file.filename == '':
            return jsonify({'success': False, 'message': 'No file selected'}), 400
        
        filename = save_profile_image(file, user.id)
        if not filename:
            return jsonify({'success': False, 'message': 'Invalid file type'}), 400
        
        # Delete old image if exists
        if user.profile_image:
            try:
                old_path = os.path.join(app.config['UPLOAD_FOLDER'], user.profile_image)
                if os.path.exists(old_path):
                    os.remove(old_path)
            except OSError as e:
                logger.error(f"Error deleting old profile image: {e}")
        
        user.profile_image = filename
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'Profile image updated successfully',
            'data': {
                'profile_image': filename,
                'profile_image_url': url_for('uploaded_file', filename=filename, _external=True)
            }
        })
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Upload profile image error: {e}")
        return jsonify({'success': False, 'message': 'Failed to upload profile image'}), 500

@app.route('/api/accounts/balance', methods=['GET'])
@jwt_required()
def api_get_balance():
    try:
        user_id = get_jwt_identity()
        user = User.query.get(user_id)
        
        if not user:
            return jsonify({'success': False, 'message': 'User not found'}), 404
        
        return jsonify({
            'success': True,
            'data': {
                'checking_balance': user.checking_balance,
                'savings_balance': user.savings_balance,
                'total_balance': user.checking_balance + user.savings_balance
            }
        })
        
    except Exception as e:
        logger.error(f"Get balance error: {e}")
        return jsonify({'success': False, 'message': 'Failed to fetch balance'}), 500

@app.route('/api/transactions', methods=['GET'])
@jwt_required()
def api_get_transactions():
    try:
        user_id = get_jwt_identity()
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 20, type=int)
        account_type = request.args.get('account_type')
        category = request.args.get('category')
        
        query = Transaction.query.filter_by(user_id=user_id)
        
        if account_type and account_type in ['checking', 'savings']:
            query = query.filter_by(account_type=account_type)
        
        if category:
            query = query.filter_by(category=category)
        
        transactions = query.order_by(Transaction.created_at.desc()).paginate(
            page=page, per_page=per_page, error_out=False
        )
        
        return jsonify({
            'success': True,
            'data': {
                'transactions': [transaction_to_dict(txn) for txn in transactions.items],
                'pagination': {
                    'page': transactions.page,
                    'per_page': transactions.per_page,
                    'total': transactions.total,
                    'pages': transactions.pages
                }
            }
        })
        
    except Exception as e:
        logger.error(f"Get transactions error: {e}")
        return jsonify({'success': False, 'message': 'Failed to fetch transactions'}), 500

@app.route('/api/transactions/<int:transaction_id>', methods=['GET'])
@jwt_required()
def api_get_transaction(transaction_id):
    try:
        user_id = get_jwt_identity()
        transaction = Transaction.query.filter_by(id=transaction_id, user_id=user_id).first()
        
        if not transaction:
            return jsonify({'success': False, 'message': 'Transaction not found'}), 404
        
        return jsonify({
            'success': True,
            'data': {
                'transaction': transaction_to_dict(transaction)
            }
        })
        
    except Exception as e:
        logger.error(f"Get transaction error: {e}")
        return jsonify({'success': False, 'message': 'Failed to fetch transaction'}), 500

@app.route('/api/transfer/internal', methods=['POST'])
@jwt_required()
def api_internal_transfer():
    try:
        user_id = get_jwt_identity()
        user = User.query.get(user_id)
        
        if not user:
            return jsonify({'success': False, 'message': 'User not found'}), 404
        
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'message': 'No data provided'}), 400
        
        recipient_account = data.get('recipient_account')
        amount = float(data.get('amount', 0))
        from_account = data.get('from_account', 'checking')
        description = data.get('description', 'Internal transfer')
        
        if not recipient_account or amount <= 0 or from_account not in ['checking', 'savings']:
            return jsonify({'success': False, 'message': 'Invalid parameters'}), 400
        
        # Check if transferring to own account
        if (from_account == 'checking' and recipient_account == user.checking_account) or \
           (from_account == 'savings' and recipient_account == user.savings_account):
            return jsonify({'success': False, 'message': 'Cannot transfer to the same account'}), 400
        
        # Find recipient
        recipient = User.query.filter(
            (User.checking_account == recipient_account) | (User.savings_account == recipient_account)
        ).first()
        
        if not recipient:
            return jsonify({'success': False, 'message': 'Recipient account not found'}), 404
        
        # Check sender balance
        sender_balance = user.checking_balance if from_account == 'checking' else user.savings_balance
        if sender_balance < amount:
            return jsonify({'success': False, 'message': 'Insufficient funds'}), 400
        
        # Determine recipient account type
        recipient_account_type = 'checking' if recipient_account == recipient.checking_account else 'savings'
        recipient_balance = recipient.checking_balance if recipient_account_type == 'checking' else recipient.savings_balance
        
        # Update balances
        if from_account == 'checking':
            user.checking_balance -= amount
        else:
            user.savings_balance -= amount
        
        if recipient_account_type == 'checking':
            recipient.checking_balance += amount
        else:
            recipient.savings_balance += amount
        
        # Create transactions
        sender_txn = create_transaction(
            user.id,
            'debit',
            amount,
            f"Transfer to {recipient.full_name} - {description}",
            from_account,
            user.checking_balance if from_account == 'checking' else user.savings_balance,
            'transfer'
        )
        
        recipient_txn = create_transaction(
            recipient.id,
            'credit',
            amount,
            f"Transfer from {user.full_name} - {description}",
            recipient_account_type,
            recipient.checking_balance if recipient_account_type == 'checking' else recipient.savings_balance,
            'transfer'
        )
        
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'Transfer successful',
            'data': {
                'transaction_id': sender_txn.id,
                'reference_id': sender_txn.reference_id,
                'new_balance': user.checking_balance if from_account == 'checking' else user.savings_balance
            }
        })
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Internal transfer error: {e}")
        return jsonify({'success': False, 'message': 'Transfer failed'}), 500

@app.route('/api/transfer/external', methods=['POST'])
@jwt_required()
def api_external_transfer():
    try:
        user_id = get_jwt_identity()
        user = User.query.get(user_id)
        
        if not user:
            return jsonify({'success': False, 'message': 'User not found'}), 404
        
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'message': 'No data provided'}), 400
        
        bank_name = data.get('bank_name')
        account_number = data.get('account_number')
        account_name = data.get('account_name')
        amount = float(data.get('amount', 0))
        from_account = data.get('from_account', 'checking')
        description = data.get('description', 'External transfer')
        
        if not all([bank_name, account_number, account_name]) or amount <= 0:
            return jsonify({'success': False, 'message': 'Invalid parameters'}), 400
        
        # Check sender balance
        sender_balance = user.checking_balance if from_account == 'checking' else user.savings_balance
        if sender_balance < amount:
            return jsonify({'success': False, 'message': 'Insufficient funds'}), 400
        
        # Update sender balance
        if from_account == 'checking':
            user.checking_balance -= amount
        else:
            user.savings_balance -= amount
        
        # Create transaction
        transaction = create_transaction(
            user.id,
            'debit',
            amount,
            f"Transfer to {account_name} ({bank_name}) - {description}",
            from_account,
            user.checking_balance if from_account == 'checking' else user.savings_balance,
            'external_transfer'
        )
        
        # Create external transaction record
        external_txn = ExternalTransaction(
            user_id=user.id,
            transaction_type='debit',
            amount=amount,
            description=f"Transfer to {account_name} ({bank_name})",
            status='completed',
            reference_id=generate_reference_id('EXT')
        )
        db.session.add(external_txn)
        
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'External transfer initiated successfully',
            'data': {
                'transaction_id': transaction.id,
                'reference_id': transaction.reference_id,
                'new_balance': user.checking_balance if from_account == 'checking' else user.savings_balance
            }
        })
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"External transfer error: {e}")
        return jsonify({'success': False, 'message': 'Transfer failed'}), 500

@app.route('/api/bills/pay', methods=['POST'])
@jwt_required()
def api_pay_bill():
    try:
        user_id = get_jwt_identity()
        user = User.query.get(user_id)
        
        if not user:
            return jsonify({'success': False, 'message': 'User not found'}), 404
        
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'message': 'No data provided'}), 400
        
        bill_type = data.get('bill_type')
        provider = data.get('provider')
        account_number = data.get('account_number')
        amount = float(data.get('amount', 0))
        payment_method = data.get('payment_method', 'checking')
        
        if not all([bill_type, provider, account_number]) or amount <= 0:
            return jsonify({'success': False, 'message': 'Invalid parameters'}), 400
        
        if payment_method not in ['checking', 'savings']:
            return jsonify({'success': False, 'message': 'Invalid payment method'}), 400
        
        # Check balance
        balance = user.checking_balance if payment_method == 'checking' else user.savings_balance
        if balance < amount:
            return jsonify({'success': False, 'message': 'Insufficient funds'}), 400
        
        # Update balance
        if payment_method == 'checking':
            user.checking_balance -= amount
        else:
            user.savings_balance -= amount
        
        # Create transaction
        transaction = create_transaction(
            user.id,
            'debit',
            amount,
            f"Bill payment to {provider} ({bill_type})",
            payment_method,
            user.checking_balance if payment_method == 'checking' else user.savings_balance,
            'bill_payment'
        )
        
        # Create bill payment record
        bill_payment = BillPayment(
            user_id=user.id,
            bill_type=bill_type,
            provider=provider,
            account_number=account_number,
            amount=amount,
            payment_method=payment_method,
            status='completed',
            reference_id=generate_reference_id('BILL')
        )
        db.session.add(bill_payment)
        
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'Bill payment successful',
            'data': {
                'transaction_id': transaction.id,
                'reference_id': transaction.reference_id,
                'bill_reference': bill_payment.reference_id,
                'new_balance': user.checking_balance if payment_method == 'checking' else user.savings_balance
            }
        })
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Bill payment error: {e}")
        return jsonify({'success': False, 'message': 'Bill payment failed'}), 500

@app.route('/api/wallet/fund', methods=['POST'])
@jwt_required()
def api_fund_wallet():
    try:
        user_id = get_jwt_identity()
        user = User.query.get(user_id)
        
        if not user:
            return jsonify({'success': False, 'message': 'User not found'}), 404
        
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'message': 'No data provided'}), 400
        
        amount = float(data.get('amount', 0))
        account_type = data.get('account_type', 'checking')
        
        if amount <= 0:
            return jsonify({'success': False, 'message': 'Invalid amount'}), 400
        
        if account_type not in ['checking', 'savings']:
            return jsonify({'success': False, 'message': 'Invalid account type'}), 400
        
        # Update balance
        if account_type == 'checking':
            user.checking_balance += amount
            new_balance = user.checking_balance
        else:
            user.savings_balance += amount
            new_balance = user.savings_balance
        
        # Create transaction
        transaction = create_transaction(
            user.id,
            'credit',
            amount,
            'Wallet funding',
            account_type,
            new_balance,
            'funding'
        )
        
        # Create wallet funding record
        wallet_funding = WalletFunding(
            user_id=user.id,
            amount=amount,
            account_type=account_type,
            reference_id=generate_reference_id('FUND'),
            status='completed'
        )
        db.session.add(wallet_funding)
        
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'Wallet funded successfully',
            'data': {
                'transaction_id': transaction.id,
                'reference_id': transaction.reference_id,
                'new_balance': new_balance
            }
        })
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Wallet funding error: {e}")
        return jsonify({'success': False, 'message': 'Wallet funding failed'}), 500

@app.route('/api/budgets', methods=['GET'])
@jwt_required()
def api_get_budgets():
    try:
        user_id = get_jwt_identity()
        budgets = Budget.query.filter_by(user_id=user_id).all()
        
        budget_data = []
        for budget in budgets:
            budget_data.append({
                'id': budget.id,
                'category': budget.category,
                'budget_amount': budget.budget_amount,
                'spent': budget.spent,
                'remaining': budget.budget_amount - budget.spent,
                'percentage': (budget.spent / budget.budget_amount * 100) if budget.budget_amount > 0 else 0,
                'created_at': budget.created_at.isoformat(),
                'updated_at': budget.updated_at.isoformat()
            })
        
        return jsonify({
            'success': True,
            'data': {
                'budgets': budget_data
            }
        })
        
    except Exception as e:
        logger.error(f"Get budgets error: {e}")
        return jsonify({'success': False, 'message': 'Failed to fetch budgets'}), 500

@app.route('/api/budgets', methods=['POST'])
@jwt_required()
def api_create_budget():
    try:
        user_id = get_jwt_identity()
        data = request.get_json()
        
        if not data:
            return jsonify({'success': False, 'message': 'No data provided'}), 400
        
        category = data.get('category')
        budget_amount = float(data.get('budget_amount', 0))
        
        if not category or budget_amount <= 0:
            return jsonify({'success': False, 'message': 'Invalid parameters'}), 400
        
        # Check if budget already exists
        existing_budget = Budget.query.filter_by(user_id=user_id, category=category).first()
        if existing_budget:
            return jsonify({'success': False, 'message': 'Budget for this category already exists'}), 400
        
        # Create new budget
        budget = Budget(
            user_id=user_id,
            category=category,
            budget_amount=budget_amount
        )
        db.session.add(budget)
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'Budget created successfully',
            'data': {
                'budget': {
                    'id': budget.id,
                    'category': budget.category,
                    'budget_amount': budget.budget_amount,
                    'spent': budget.spent,
                    'remaining': budget.budget_amount - budget.spent
                }
            }
        }), 201
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Create budget error: {e}")
        return jsonify({'success': False, 'message': 'Failed to create budget'}), 500

@app.route('/api/budgets/<int:budget_id>', methods=['PUT'])
@jwt_required()
def api_update_budget(budget_id):
    try:
        user_id = get_jwt_identity()
        budget = Budget.query.filter_by(id=budget_id, user_id=user_id).first()
        
        if not budget:
            return jsonify({'success': False, 'message': 'Budget not found'}), 404
        
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'message': 'No data provided'}), 400
        
        if 'budget_amount' in data:
            new_amount = float(data['budget_amount'])
            if new_amount <= 0:
                return jsonify({'success': False, 'message': 'Invalid budget amount'}), 400
            budget.budget_amount = new_amount
        
        if 'spent' in data:
            new_spent = float(data['spent'])
            if new_spent < 0:
                return jsonify({'success': False, 'message': 'Invalid spent amount'}), 400
            budget.spent = new_spent
        
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'Budget updated successfully',
            'data': {
                'budget': {
                    'id': budget.id,
                    'category': budget.category,
                    'budget_amount': budget.budget_amount,
                    'spent': budget.spent,
                    'remaining': budget.budget_amount - budget.spent
                }
            }
        })
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Update budget error: {e}")
        return jsonify({'success': False, 'message': 'Failed to update budget'}), 500

@app.route('/api/budgets/<int:budget_id>', methods=['DELETE'])
@jwt_required()
def api_delete_budget(budget_id):
    try:
        user_id = get_jwt_identity()
        budget = Budget.query.filter_by(id=budget_id, user_id=user_id).first()
        
        if not budget:
            return jsonify({'success': False, 'message': 'Budget not found'}), 404
        
        db.session.delete(budget)
        db.session.commit()
        
        return jsonify({'success': True, 'message': 'Budget deleted successfully'})
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Delete budget error: {e}")
        return jsonify({'success': False, 'message': 'Failed to delete budget'}), 500

@app.route('/api/banks/list', methods=['GET'])
@jwt_required()
def api_get_banks():
    try:
        banks_list = [{'code': code, 'name': info['name'], 'color': info['color']} for code, info in BANKS.items()]
        mobile_money_list = [{'code': code, 'name': info['name'], 'color': info['color']} for code, info in MOBILE_MONEY.items()]
        
        return jsonify({
            'success': True,
            'data': {
                'banks': banks_list,
                'mobile_money': mobile_money_list,
                'bill_types': [{'code': code, 'name': name} for code, name in BILL_TYPES.items()]
            }
        })
        
    except Exception as e:
        logger.error(f"Get banks error: {e}")
        return jsonify({'success': False, 'message': 'Failed to fetch banks list'}), 500

@app.route('/api/external-accounts', methods=['GET'])
@jwt_required()
def api_get_external_accounts():
    try:
        user_id = get_jwt_identity()
        accounts = ExternalBankAccount.query.filter_by(user_id=user_id).all()
        
        accounts_data = [{
            'id': acc.id,
            'bank_name': acc.bank_name,
            'account_name': acc.account_name,
            'account_number': acc.account_number,
            'is_verified': acc.is_verified,
            'created_at': acc.created_at.isoformat()
        } for acc in accounts]
        
        return jsonify({
            'success': True,
            'data': {
                'accounts': accounts_data
            }
        })
        
    except Exception as e:
        logger.error(f"Get external accounts error: {e}")
        return jsonify({'success': False, 'message': 'Failed to fetch external accounts'}), 500

@app.route('/api/external-accounts', methods=['POST'])
@jwt_required()
def api_add_external_account():
    try:
        user_id = get_jwt_identity()
        data = request.get_json()
        
        if not data:
            return jsonify({'success': False, 'message': 'No data provided'}), 400
        
        bank_name = data.get('bank_name')
        account_name = data.get('account_name')
        account_number = data.get('account_number')
        bank_code = data.get('bank_code')
        
        if not all([bank_name, account_name, account_number]):
            return jsonify({'success': False, 'message': 'Missing required fields'}), 400
        
        # Check if account already exists
        existing_account = ExternalBankAccount.query.filter_by(
            user_id=user_id, account_number=account_number
        ).first()
        
        if existing_account:
            return jsonify({'success': False, 'message': 'Account already linked'}), 400
        
        # Create new external account
        account = ExternalBankAccount(
            user_id=user_id,
            bank_name=bank_name,
            account_name=account_name,
            account_number=account_number,
            bank_code=bank_code
        )
        db.session.add(account)
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'External account added successfully',
            'data': {
                'account': {
                    'id': account.id,
                    'bank_name': account.bank_name,
                    'account_name': account.account_name,
                    'account_number': account.account_number,
                    'is_verified': account.is_verified
                }
            }
        }), 201
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Add external account error: {e}")
        return jsonify({'success': False, 'message': 'Failed to add external account'}), 500

@app.route('/api/external-accounts/<int:account_id>', methods=['DELETE'])
@jwt_required()
def api_delete_external_account(account_id):
    try:
        user_id = get_jwt_identity()
        account = ExternalBankAccount.query.filter_by(id=account_id, user_id=user_id).first()
        
        if not account:
            return jsonify({'success': False, 'message': 'Account not found'}), 404
        
        db.session.delete(account)
        db.session.commit()
        
        return jsonify({'success': True, 'message': 'External account deleted successfully'})
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Delete external account error: {e}")
        return jsonify({'success': False, 'message': 'Failed to delete external account'}), 500

# Helper functions
def user_to_dict(user):
    return {
        'id': user.id,
        'full_name': user.full_name,
        'email': user.email,
        'phone': user.phone,
        'date_of_birth': user.date_of_birth.isoformat() if user.date_of_birth else None,
        'gps_address': user.gps_address,
        'ghana_card_id': user.ghana_card_id,
        'checking_account': user.checking_account,
        'savings_account': user.savings_account,
        'checking_balance': user.checking_balance,
        'savings_balance': user.savings_balance,
        'profile_image': user.profile_image,
        'profile_image_url': url_for('uploaded_file', filename=user.profile_image, _external=True) if user.profile_image else None,
        'is_verified': user.is_verified,
        'created_at': user.created_at.isoformat()
    }

def transaction_to_dict(transaction):
    return {
        'id': transaction.id,
        'type': transaction.transaction_type,
        'amount': transaction.amount,
        'description': transaction.description,
        'account_type': transaction.account_type,
        'balance_after': transaction.balance_after,
        'reference_id': transaction.reference_id,
        'category': transaction.category,
        'created_at': transaction.created_at.isoformat()
    }

def validate_email(email):
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

# Web routes (kept for backward compatibility)
@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/')
def index():
    return jsonify({'success': True, 'message': 'Ghana Bank API', 'version': '1.0.0'})

@app.route('/login', methods=['GET', 'POST'])
def login():
    return jsonify({'success': False, 'message': 'Use API endpoints for authentication'}), 404

@app.route('/google/callback')
def google_callback():
    return jsonify({'success': False, 'message': 'Use API endpoints for authentication'}), 404

# Error handlers
@app.errorhandler(404)
def not_found(error):
    return jsonify({'success': False, 'message': 'Endpoint not found'}), 404

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    return jsonify({'success': False, 'message': 'Internal server error'}), 500

@app.errorhandler(413)
def too_large(error):
    return jsonify({'success': False, 'message': 'File too large'}), 413

@app.errorhandler(400)
def bad_request(error):
    return jsonify({'success': False, 'message': 'Bad request'}), 400

@app.errorhandler(401)
def unauthorized(error):
    return jsonify({'success': False, 'message': 'Unauthorized'}), 401

@app.errorhandler(403)
def forbidden(error):
    return jsonify({'success': False, 'message': 'Forbidden'}), 403

# Health check endpoint for Render
@app.route('/health')
def health_check():
    try:
        # Test database connection
        db.session.execute('SELECT 1')
        return jsonify({'status': 'healthy', 'database': 'connected'}), 200
    except Exception as e:
        return jsonify({'status': 'unhealthy', 'database': 'disconnected', 'error': str(e)}), 500

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    
    # Configure production logging
    if not app.debug:
        file_handler = RotatingFileHandler('error.log', maxBytes=10240, backupCount=10)
        file_handler.setFormatter(logging.Formatter(
            '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
        ))
        file_handler.setLevel(logging.INFO)
        app.logger.addHandler(file_handler)
        app.logger.setLevel(logging.INFO)
        app.logger.info('Ghana Bank startup')
    
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=os.environ.get('FLASK_DEBUG', 'False').lower() == 'true')
