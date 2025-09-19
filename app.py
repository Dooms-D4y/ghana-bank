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
from flask_login import current_user, LoginManager, login_user, UserMixin
import folium
from flask_cors import CORS
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity

app = Flask(__name__)

# Configuration
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', secrets.token_hex(16))
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///banking.db').replace('postgres://', 'postgresql://')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif'}
app.config['MAX_CONTENT_LENGTH'] = 2 * 1024 * 1024  # 2MB max

# JWT Configuration
app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY', secrets.token_hex(32))
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=24)

# Email Configuration
app.config['MAIL_SERVER'] = os.environ.get('MAIL_SERVER', 'smtp.gmail.com')
app.config['MAIL_PORT'] = int(os.environ.get('MAIL_PORT', 587))
app.config['MAIL_USE_TLS'] = os.environ.get('MAIL_USE_TLS', 'True').lower() == 'true'
app.config['MAIL_USE_SSL'] = os.environ.get('MAIL_USE_SSL', 'False').lower() == 'true'
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('MAIL_DEFAULT_SENDER', 'noreply@ghanabank.com')

# Google OAuth Configuration
app.config['GOOGLE_OAUTH_CLIENT_ID'] = os.environ.get('GOOGLE_OAUTH_CLIENT_ID', 'DUMMY_CLIENT_ID_REPLACE_ME')
app.config['GOOGLE_OAUTH_CLIENT_SECRET'] = os.environ.get('GOOGLE_OAUTH_CLIENT_SECRET', 'DUMMY_CLIENT_SECRET_REPLACE_ME')

# CORS Configuration for Flutter app
CORS(app, origins=[
    "http://localhost:5000",
    "http://127.0.0.1:5000",
    "https://your-flutter-app.com",  # Replace with your Flutter app domain
    "http://localhost",  # For Android emulator
    "http://10.0.2.2:5000",  # For Android emulator
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
    
    # Relationship to wallet fundings
    wallet_fundings = db.relationship('WalletFunding', backref='user', lazy=True)
    # Relationship to OAuth tokens, corrected to use back_populates
    oauth_tokens = db.relationship('OAuth', back_populates='user', lazy=True)

# OAuth model
class OAuth(OAuthConsumerMixin, db.Model):
    provider_user_id = db.Column(db.String(256), unique=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    # Corrected to use back_populates
    user = db.relationship('User', back_populates='oauth_tokens')

class Transaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    transaction_type = db.Column(db.String(50), nullable=False)  # debit, credit, transfer
    amount = db.Column(db.Float, nullable=False)
    description = db.Column(db.String(200), nullable=False)
    account_type = db.Column(db.String(20), nullable=False)  # checking, savings
    balance_after = db.Column(db.Float, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    reference_id = db.Column(db.String(50), nullable=True)

class BillPayment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    bill_type = db.Column(db.String(50), nullable=False)  # utilities, mobile, school
    provider = db.Column(db.String(100), nullable=False)
    account_number = db.Column(db.String(50), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    payment_method = db.Column(db.String(20), nullable=False)  # checking, savings, mobile_money
    status = db.Column(db.String(20), default='pending')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    reference_id = db.Column(db.String(50), nullable=True)

class WalletFunding(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    account_type = db.Column(db.String(20), nullable=False)  # checking, savings
    reference_id = db.Column(db.String(50), unique=True, nullable=False)
    status = db.Column(db.String(20), default='pending')  # pending, completed
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

# Budget Model
class Budget(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    category = db.Column(db.String(50), nullable=False)
    budget_amount = db.Column(db.Float, nullable=False)
    spent = db.Column(db.Float, default=0.0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    __table_args__ = (db.UniqueConstraint('user_id', 'category', name='_user_category_uc'),)

# External Bank Account Model
class ExternalBankAccount(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    bank_code = db.Column(db.String(20), nullable=False)
    account_name = db.Column(db.String(100), nullable=False)
    account_number = db.Column(db.String(50), nullable=False)
    is_verified = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

# External Transaction Model
class ExternalTransaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    bank_account_id = db.Column(db.Integer, db.ForeignKey('external_bank_account.id'), nullable=True)
    transaction_type = db.Column(db.String(20), nullable=False)  # credit, debit
    amount = db.Column(db.Float, nullable=False)
    description = db.Column(db.String(200), nullable=False)
    status = db.Column(db.String(20), default='pending')  # pending, completed, failed
    reference_id = db.Column(db.String(50), unique=True, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

# Create Google OAuth blueprint with SQLAlchemy storage
google_blueprint = make_google_blueprint(
    client_id=app.config["GOOGLE_OAUTH_CLIENT_ID"],
    client_secret=app.config["GOOGLE_OAUTH_CLIENT_SECRET"],
    scope=[
        "https://www.googleapis.com/auth/userinfo.profile",
        "https://www.googleapis.com/auth/userinfo.email",
        "openid"
    ],
    redirect_to="dashboard",
    authorized_url="/authorized",
    storage=SQLAlchemyStorage(OAuth, db.session, user=current_user)
)
app.register_blueprint(google_blueprint, url_prefix="/google_login")

# Bank and Mobile Money Providers Configuration
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
    'mtn': {'name': 'MTN Mobile Money', 'color': '#FFCC00', 'prefix': '024, 054, 055, 059'},
    'vodafone': {'name': 'Vodafone Cash', 'color': '#E60000', 'prefix': '020, 050'},
    'airteltigo': {'name': 'AirtelTigo Money', 'color': '#E10070', 'prefix': '027, 057, 026, 056'},
}

# Utility Functions
def validate_ghana_card(card_id):
    """Validate Ghana Card ID format: GHA-XXXXXXXXX-X"""
    pattern = r'^GHA-\d{9}-\d{1}$'
    return re.match(pattern, card_id) is not None

def validate_gps_address(address):
    """Validate Ghana Post GPS address format"""
    pattern = r'^[A-Z]{2}-\d{4}-\d{4}$'
    return re.match(pattern, address) is not None

def validate_password(password):
    """Validate password requirements"""
    if not password:
        return True, "No password required for Google users"
    
    if len(password) < 8:
        return False, "Password must be at least 8 characters long"
    
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        return False, "Password must contain at least one special character"
    
    if re.search(r'\d{3,}', password):
        return False, "Password cannot contain phone numbers"
    
    return True, "Password is valid"

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({'error': 'Authentication required'}), 401
        return f(*args, **kwargs)
    return decorated_function

def send_email(to, subject, template, **kwargs):
    """Send email using Flask-Mail"""
    try:
        msg = Message(subject, recipients=[to])
        msg.html = render_template(template, **kwargs)
        mail.send(msg)
        return True
    except Exception as e:
        print(f"Email sending failed: {e}")
        return False

def generate_account_number():
    """Generate a random 4-digit account number suffix"""
    return f"...{secrets.randbelow(9000) + 1000}"

def create_transaction(user_id, transaction_type, amount, description, account_type, balance_after):
    """Create a new transaction record"""
    transaction = Transaction(
        user_id=user_id,
        transaction_type=transaction_type,
        amount=amount,
        description=description,
        account_type=account_type,
        balance_after=balance_after,
        reference_id=f"TXN{secrets.token_hex(8).upper()}"
    )
    db.session.add(transaction)
    db.session.commit()
    return transaction

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

def save_profile_image(file, user_id):
    if file and allowed_file(file.filename):
        filename = secure_filename(f"{user_id}_{int(datetime.now().timestamp())}.webp")
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        
        # Convert to WEBP and resize
        try:
            img = Image.open(file.stream)
            # Resize to 200x200 maintaining aspect ratio
            img.thumbnail((200, 200))
            # Save as WEBP
            img.save(filepath, 'WEBP')
            return filename
        except Exception as e:
            print(f"Error processing image: {e}")
            return None
    return None

# Google OAuth Handlers
@oauth_authorized.connect_via(google_blueprint)
def google_logged_in(blueprint, token):
    if not token:
        flash("Failed to log in with Google.", "error")
        return False
    
    resp = blueprint.session.get("/oauth2/v1/userinfo")
    if not resp.ok:
        flash("Failed to fetch user info from Google.", "error")
        return False
    
    google_info = resp.json()
    google_id = str(google_info["id"])
    email = google_info["email"]
    full_name = google_info.get("name", email.split("@")[0])
    
    # Find this OAuth token in the database, or create it
    query = OAuth.query.filter_by(
        provider=blueprint.name,
        provider_user_id=google_id,
    )
    try:
        oauth = query.one()
    except NoResultFound:
        oauth = OAuth(
            provider=blueprint.name,
            provider_user_id=google_id,
            token=token,
        )

    if oauth.user:
        # If this OAuth token already has an associated local account,
        # log in that local user account.
        login_user(oauth.user)
        session['user_id'] = oauth.user.id
        session['user_name'] = oauth.user.full_name
        session['profile_image'] = oauth.user.profile_image
        flash("Successfully signed in with Google.", "success")
    else:
        # Find existing user by email
        user = User.query.filter_by(email=email).first()
        
        if not user:
            # Create a new local user account for this user
            user = User(
                full_name=full_name,
                email=email,
                google_id=google_id,
                password_hash=None,
                checking_account=generate_account_number(),
                savings_account=generate_account_number(),
                is_verified=True
            )
            db.session.add(user)
            db.session.commit()
            
            # Send welcome email
            send_email(
                user.email,
                'Welcome to Ghana Bank',
                'emails/welcome_google.html',
                user=user
            )
            
            flash('Google registration successful! Please complete your profile.', 'success')
        else:
            flash('Google login successful!', 'success')
        
        # Associate the new local user account with the OAuth token
        oauth.user = user
        db.session.add(oauth)
        db.session.commit()
        
        # Log in the new local user account
        login_user(user)
        session['user_id'] = user.id
        session['user_name'] = user.full_name
        session['profile_image'] = user.profile_image
    
    # Disable Flask-Dance's default behavior for saving the OAuth token
    return False

@oauth_error.connect_via(google_blueprint)
def google_error(blueprint, error, error_description=None, error_uri=None):
    msg = (
        f"OAuth error from {blueprint.name}! "
        f"error={error} description={error_description} uri={error_uri}"
    )
    flash(msg, "error")

# API Routes for Flutter App
@app.route('/api/login', methods=['POST'])
def api_login():
    try:
        data = request.get_json()
        email_or_phone = data.get('email_or_phone')
        password = data.get('password')
        
        # Find user by email or phone
        user = User.query.filter(
            (User.email == email_or_phone) | (User.phone == email_or_phone)
        ).first()
        
        if user and user.password_hash and check_password_hash(user.password_hash, password):
            # Create JWT token
            access_token = create_access_token(identity=user.id)
            
            return jsonify({
                'success': True,
                'user': {
                    'id': user.id,
                    'full_name': user.full_name,
                    'email': user.email,
                    'phone': user.phone,
                    'checking_balance': user.checking_balance,
                    'savings_balance': user.savings_balance,
                    'profile_image': user.profile_image,
                    'checking_account': user.checking_account,
                    'savings_account': user.savings_account
                },
                'access_token': access_token
            })
        else:
            return jsonify({'success': False, 'message': 'Invalid credentials'}), 401
            
    except Exception as e:
        return jsonify({'success': False, 'message': f'Server error: {str(e)}'}), 500

@app.route('/api/register', methods=['POST'])
def api_register():
    try:
        data = request.get_json()
        
        # Validate required fields
        required_fields = ['full_name', 'email', 'password', 'confirm_password']
        for field in required_fields:
            if not data.get(field):
                return jsonify({'success': False, 'message': f'{field.replace("_", " ").title()} is required'}), 400
        
        # Validate password match
        if data['password'] != data['confirm_password']:
            return jsonify({'success': False, 'message': 'Passwords do not match'}), 400
        
        # Validate password strength
        is_valid, message = validate_password(data['password'])
        if not is_valid:
            return jsonify({'success': False, 'message': message}), 400
        
        # Check if user already exists
        if User.query.filter_by(email=data['email']).first():
            return jsonify({'success': False, 'message': 'Email already registered'}), 400
        
        # Create new user
        user = User(
            full_name=data['full_name'],
            email=data['email'],
            phone=data.get('phone'),
            date_of_birth=datetime.strptime(data['date_of_birth'], '%Y-%m-%d').date() if data.get('date_of_birth') else None,
            gps_address=data.get('gps_address'),
            ghana_card_id=data.get('ghana_card_id'),
            password_hash=generate_password_hash(data['password']),
            checking_account=generate_account_number(),
            savings_account=generate_account_number()
        )
        
        db.session.add(user)
        db.session.commit()
        
        # Create JWT token
        access_token = create_access_token(identity=user.id)
        
        return jsonify({
            'success': True,
            'message': 'Registration successful',
            'user': {
                'id': user.id,
                'full_name': user.full_name,
                'email': user.email,
                'phone': user.phone,
                'checking_balance': user.checking_balance,
                'savings_balance': user.savings_balance,
                'checking_account': user.checking_account,
                'savings_account': user.savings_account
            },
            'access_token': access_token
        })
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': f'Registration failed: {str(e)}'}), 500

@app.route('/api/user', methods=['GET'])
@jwt_required()
def api_get_user():
    try:
        user_id = get_jwt_identity()
        user = User.query.get(user_id)
        
        if not user:
            return jsonify({'success': False, 'message': 'User not found'}), 404
            
        return jsonify({
            'success': True,
            'user': {
                'id': user.id,
                'full_name': user.full_name,
                'email': user.email,
                'phone': user.phone,
                'checking_balance': user.checking_balance,
                'savings_balance': user.savings_balance,
                'profile_image': user.profile_image,
                'checking_account': user.checking_account,
                'savings_account': user.savings_account,
                'gps_address': user.gps_address,
                'ghana_card_id': user.ghana_card_id,
                'date_of_birth': user.date_of_birth.isoformat() if user.date_of_birth else None
            }
        })
        
    except Exception as e:
        return jsonify({'success': False, 'message': f'Error fetching user: {str(e)}'}), 500

@app.route('/api/transactions', methods=['GET'])
@jwt_required()
def api_transactions():
    try:
        user_id = get_jwt_identity()
        transactions = Transaction.query.filter_by(user_id=user_id).order_by(Transaction.created_at.desc()).all()
        
        return jsonify({
            'success': True,
            'transactions': [{
                'id': txn.id,
                'type': txn.transaction_type,
                'amount': txn.amount,
                'description': txn.description,
                'account_type': txn.account_type,
                'balance_after': txn.balance_after,
                'date': txn.created_at.isoformat(),
                'reference_id': txn.reference_id
            } for txn in transactions]
        })
        
    except Exception as e:
        return jsonify({'success': False, 'message': f'Error fetching transactions: {str(e)}'}), 500

@app.route('/api/transfer', methods=['POST'])
@jwt_required()
def api_transfer():
    try:
        user_id = get_jwt_identity()
        data = request.get_json()
        
        recipient_account = data.get('recipient_account')
        amount = float(data.get('amount'))
        from_account = data.get('from_account')
        description = data.get('description', 'Internal transfer')
        
        # Validate amount
        if amount <= 0:
            return jsonify({'success': False, 'message': 'Amount must be greater than zero'}), 400
        
        # Find recipient
        recipient_user = User.query.filter(
            (User.checking_account == recipient_account) | (User.savings_account == recipient_account)
        ).first()
        
        if not recipient_user:
            return jsonify({'success': False, 'message': 'Recipient account not found'}), 404
        
        # Get sender user
        user = User.query.get(user_id)
        
        # Check sender balance
        if from_account == 'checking':
            if user.checking_balance < amount:
                return jsonify({'success': False, 'message': 'Insufficient funds in checking account'}), 400
            user.checking_balance -= amount
        else:
            if user.savings_balance < amount:
                return jsonify({'success': False, 'message': 'Insufficient funds in savings account'}), 400
            user.savings_balance -= amount

        # Deposit into recipient's account
        if recipient_user.checking_account == recipient_account:
            recipient_user.checking_balance += amount
            recipient_account_type = 'checking'
        else:
            recipient_user.savings_balance += amount
            recipient_account_type = 'savings'

        # Create transactions for both sender and recipient
        create_transaction(
            user.id,
            'debit',
            amount,
            f"Transfer to {recipient_user.full_name} ({recipient_account})",
            from_account,
            user.checking_balance if from_account == 'checking' else user.savings_balance
        )
        
        create_transaction(
            recipient_user.id,
            'credit',
            amount,
            f"Transfer from {user.full_name} ({user.checking_account if from_account == 'checking' else user.savings_account})",
            recipient_account_type,
            recipient_user.checking_balance if recipient_account_type == 'checking' else recipient_user.savings_balance
        )

        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': f'Transfer of ₵{amount:.2f} successful!',
            'new_balance': user.checking_balance if from_account == 'checking' else user.savings_balance
        })
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': f'Transfer failed: {str(e)}'}), 500

@app.route('/api/pay_bills', methods=['POST'])
@jwt_required()
def api_pay_bills():
    try:
        user_id = get_jwt_identity()
        data = request.get_json()
        
        bill_type = data.get('bill_type')
        provider = data.get('provider')
        account_number = data.get('account_number')
        amount = float(data.get('amount'))
        payment_method = data.get('payment_method')
        
        # Validate amount
        if amount <= 0:
            return jsonify({'success': False, 'message': 'Amount must be greater than zero'}), 400
        
        # Get user
        user = User.query.get(user_id)
        
        # Check available balance
        if payment_method in ['checking', 'savings']:
            balance = user.checking_balance if payment_method == 'checking' else user.savings_balance
            if balance < amount:
                return jsonify({'success': False, 'message': 'Insufficient funds'}), 400
            
            # Deduct from account
            if payment_method == 'checking':
                user.checking_balance -= amount
            else:
                user.savings_balance -= amount
                
            # Create transaction
            create_transaction(
                user.id,
                'debit',
                amount,
                f"Bill payment to {provider}",
                payment_method,
                user.checking_balance if payment_method == 'checking' else user.savings_balance
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
            reference_id=f"BILL{secrets.token_hex(8).upper()}"
        )
        db.session.add(bill_payment)
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'Bill payment successful!',
            'reference_id': bill_payment.reference_id,
            'new_balance': user.checking_balance if payment_method == 'checking' else user.savings_balance
        })
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': f'Bill payment failed: {str(e)}'}), 500

@app.route('/api/fund_wallet', methods=['POST'])
@jwt_required()
def api_fund_wallet():
    try:
        user_id = get_jwt_identity()
        data = request.get_json()
        
        amount = float(data.get('amount'))
        account_type = data.get('account_type', 'checking')
        
        # Validate amount
        if amount <= 0:
            return jsonify({'success': False, 'message': 'Amount must be greater than zero'}), 400
        
        # Get user
        user = User.query.get(user_id)
        
        # Update account balance
        if account_type == 'checking':
            user.checking_balance += amount
        else:
            user.savings_balance += amount
            
        # Create transaction
        create_transaction(
            user.id,
            'credit',
            amount,
            'Wallet funding',
            account_type,
            user.checking_balance if account_type == 'checking' else user.savings_balance
        )
        
        # Create wallet funding record
        wallet_funding = WalletFunding(
            user_id=user.id,
            amount=amount,
            account_type=account_type,
            reference_id=f"FUND{secrets.token_hex(8).upper()}",
            status='completed'
        )
        db.session.add(wallet_funding)
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'Wallet funded successfully!',
            'new_balance': user.checking_balance if account_type == 'checking' else user.savings_balance
        })
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': f'Wallet funding failed: {str(e)}'}), 500

@app.route('/api/budgets', methods=['GET', 'POST'])
@jwt_required()
def api_budgets():
    try:
        user_id = get_jwt_identity()
        
        if request.method == 'GET':
            # Get all budgets for user
            budgets = Budget.query.filter_by(user_id=user_id).all()
            
            return jsonify({
                'success': True,
                'budgets': [{
                    'id': budget.id,
                    'category': budget.category,
                    'budget_amount': budget.budget_amount,
                    'spent': budget.spent,
                    'remaining': budget.budget_amount - budget.spent
                } for budget in budgets]
            })
            
        elif request.method == 'POST':
            # Create new budget
            data = request.get_json()
            category = data.get('category')
            budget_amount = float(data.get('budget_amount'))
            
            # Check if budget already exists
            existing = Budget.query.filter_by(user_id=user_id, category=category).first()
            if existing:
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
                'message': 'Budget created successfully!',
                'budget': {
                    'id': budget.id,
                    'category': budget.category,
                    'budget_amount': budget.budget_amount,
                    'spent': budget.spent
                }
            })
            
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': f'Budget operation failed: {str(e)}'}), 500

@app.route('/api/budgets/<int:budget_id>', methods=['PUT', 'DELETE'])
@jwt_required()
def api_budget(budget_id):
    try:
        user_id = get_jwt_identity()
        budget = Budget.query.get_or_404(budget_id)
        
        # Validate user ownership
        if budget.user_id != user_id:
            return jsonify({'success': False, 'message': 'Unauthorized'}), 403
        
        if request.method == 'PUT':
            # Update budget
            data = request.get_json()
            budget.budget_amount = float(data.get('budget_amount', budget.budget_amount))
            budget.spent = float(data.get('spent', budget.spent))
            
            db.session.commit()
            
            return jsonify({
                'success': True,
                'message': 'Budget updated successfully!',
                'budget': {
                    'id': budget.id,
                    'category': budget.category,
                    'budget_amount': budget.budget_amount,
                    'spent': budget.spent
                }
            })
            
        elif request.method == 'DELETE':
            # Delete budget
            db.session.delete(budget)
            db.session.commit()
            
            return jsonify({'success': True, 'message': 'Budget deleted successfully!'})
            
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': f'Budget operation failed: {str(e)}'}), 500

# Existing web routes (keep these for web interface)
@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

# ... (keep all your existing web routes below this point) ...

# Error handlers
@app.errorhandler(404)
def not_found(error):
    if request.path.startswith('/api/'):
        return jsonify({'success': False, 'message': 'Endpoint not found'}), 404
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    if request.path.startswith('/api/'):
        return jsonify({'success': False, 'message': 'Internal server error'}), 500
    return render_template('500.html'), 500

@app.errorhandler(401)
def unauthorized(error):
    if request.path.startswith('/api/'):
        return jsonify({'success': False, 'message': 'Authentication required'}), 401
    return redirect(url_for('login'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()

    # Start development server
    app.run(debug=os.environ.get('FLASK_DEBUG', 'False').lower() == 'true', 
            host='0.0.0.0', 
            port=int(os.environ.get('PORT', 5000)))
