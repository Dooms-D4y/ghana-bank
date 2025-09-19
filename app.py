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

app = Flask(__name__)
app.config['SECRET_KEY'] = secrets.token_hex(16)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///banking.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif'}
app.config['MAX_CONTENT_LENGTH'] = 2 * 1024 * 1024  # 2MB max

# IMPORTANT: Replace these dummy values with your actual Google OAuth credentials.
# You can get these from the Google Cloud Console: https://console.cloud.com/apis/credentials
# For development, you can set them as environment variables or replace the dummy strings directly.
app.config['GOOGLE_OAUTH_CLIENT_ID'] = os.environ.get('GOOGLE_OAUTH_CLIENT_ID', 'DUMMY_CLIENT_ID_REPLACE_ME')
app.config['GOOGLE_OAUTH_CLIENT_SECRET'] = os.environ.get('GOOGLE_OAUTH_CLIENT_SECRET', 'DUMMY_CLIENT_SECRET_REPLACE_ME')

# Ensure upload folder exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Mail configuration for local SMTP
app.config['MAIL_SERVER'] = 'localhost'
app.config['MAIL_PORT'] = 1025
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = False
app.config['MAIL_DEFAULT_SENDER'] = 'noreply@ghanabank.com'

db = SQLAlchemy(app)
mail = Mail(app)

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
            return redirect(url_for('login'))
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

# Routes
@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email_or_phone = request.form.get('email_or_phone')
        password = request.form.get('password')
        remember_me = request.form.get('remember_me')
        
        # Find user by email or phone
        user = User.query.filter(
            (User.email == email_or_phone) | (User.phone == email_or_phone)
        ).first()
        
        if user and user.password_hash and check_password_hash(user.password_hash, password):
            session['user_id'] = user.id
            session['user_name'] = user.full_name
            session['profile_image'] = user.profile_image
            
            # Log in with Flask-Login
            login_user(user)
            
            if remember_me:
                session.permanent = True
                app.permanent_session_lifetime = timedelta(days=30)
            
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid email/phone or password', 'error')
    
    return render_template('login.html')

@app.route('/login/google')
def google_login():
    if not google.authorized:
        return redirect(url_for('google.login'))
    
    try:
        resp = google.get("/oauth2/v1/userinfo")
        if resp.ok:
            return redirect(url_for('dashboard'))
        else:
            flash("Google authentication failed", "error")
            return redirect(url_for('login'))
    except Exception as e:
        flash(f"Error during Google authentication: {str(e)}", "error")
        return redirect(url_for('login'))

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        # Get form data
        full_name = request.form.get('full_name')
        email = request.form.get('email')
        phone = request.form.get('phone')
        date_of_birth = request.form.get('date_of_birth')
        gps_address = request.form.get('gps_address')
        ghana_card_id = request.form.get('ghana_card_id')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        checking_account = request.form.get('checking_account')
        savings_account = request.form.get('savings_account')
        
        # Validation
        if password != confirm_password:
            flash('Passwords do not match', 'error')
            return render_template('signup.html')
        
        is_valid, message = validate_password(password)
        if not is_valid:
            flash(message, 'error')
            return render_template('signup.html')
        
        if not validate_ghana_card(ghana_card_id):
            flash('Invalid Ghana Card ID format. Use: GHA-XXXXXXXXX-X', 'error')
            return render_template('signup.html')
        
        if not validate_gps_address(gps_address):
            flash('Invalid GPS address format. Use: XX-XXXX-XXXX', 'error')
            return render_template('signup.html')
        
        # Check if user already exists
        if User.query.filter_by(email=email).first():
            flash('Email already registered', 'error')
            return render_template('signup.html')
        
        if phone and User.query.filter_by(phone=phone).first():
            flash('Phone number already registered', 'error')
            return render_template('signup.html')
        
        if ghana_card_id and User.query.filter_by(ghana_card_id=ghana_card_id).first():
            flash('Ghana Card ID already registered', 'error')
            return render_template('signup.html')
        
        # Create new user
        user = User(
            full_name=full_name,
            email=email,
            phone=phone,
            date_of_birth=datetime.strptime(date_of_birth, '%Y-%m-%d').date() if date_of_birth else None,
            gps_address=gps_address,
            ghana_card_id=ghana_card_id,
            password_hash=generate_password_hash(password),
            checking_account=checking_account or generate_account_number(),
            savings_account=savings_account or generate_account_number()
        )
        
        db.session.add(user)
        db.session.commit()
        
        # Send welcome email
        send_email(
            user.email,
            'Welcome to Ghana Bank',
            'emails/welcome.html',
            user=user
        )
        
        flash('Registration successful! Please login.', 'success')
        return redirect(url_for('login'))
    
    return render_template('signup.html')

@app.route('/dashboard')
@login_required
def dashboard():
    user = User.query.get(session['user_id'])
    recent_transactions = Transaction.query.filter_by(user_id=user.id).order_by(Transaction.created_at.desc()).limit(5).all()
    return render_template('dashboard.html', user=user, transactions=recent_transactions)

@app.route('/bank_hub')
@login_required
def bank_hub():
    user = User.query.get(session['user_id'])
    
    # Get linked bank accounts
    linked_accounts = ExternalBankAccount.query.filter_by(user_id=user.id).all()
    
    # Format linked accounts with bank names
    formatted_accounts = []
    for account in linked_accounts:
        bank_name = BANKS.get(account.bank_code, {}).get('name', account.bank_code)
        formatted_accounts.append({
            'bank_name': bank_name,
            'account_name': account.account_name,
            'account_number': account.account_number
        })
    
    return render_template('bank_hub.html', 
                          user=user, 
                          linked_accounts=formatted_accounts)

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out', 'info')
    return redirect(url_for('login'))

@app.route('/transactions')
@login_required
def transactions():
    user = User.query.get(session['user_id'])
    all_transactions = Transaction.query.filter_by(user_id=user.id).order_by(Transaction.created_at.desc()).all()
    return render_template('transactions.html', user=user, transactions=all_transactions)

@app.route('/pay_bills', methods=['GET', 'POST'])
@login_required
def pay_bills():
    user = User.query.get(session['user_id'])
    
    if request.method == 'POST':
        bill_type = request.form.get('bill_type')
        provider = request.form.get('provider')
        account_number = request.form.get('account_number')
        amount = float(request.form.get('amount'))
        payment_method = request.form.get('payment_method')
        
        # Validate amount
        if amount <= 0:
            flash('Amount must be greater than zero', 'error')
            return render_template('pay_bills.html', user=user)
        
        # Check available balance
        if payment_method in ['checking', 'savings']:
            balance = user.checking_balance if payment_method == 'checking' else user.savings_balance
            if balance < amount:
                flash('Insufficient funds', 'error')
                return render_template('pay_bills.html', user=user)
            
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
        
        # Send confirmation email
        send_email(
            user.email,
            'Bill Payment Confirmation',
            'emails/bill_payment.html',
            user=user,
            bill_payment=bill_payment
        )
        
        flash('Bill payment successful!', 'success')
        return redirect(url_for('dashboard'))
    
    return render_template('pay_bills.html', user=user)

@app.route('/account_settings', methods=['GET', 'POST'])
@login_required
def account_settings():
    user = User.query.get(session['user_id'])
    
    if request.method == 'POST':
        # Update profile
        if 'update_profile' in request.form:
            full_name = request.form.get('full_name')
            email = request.form.get('email')
            phone = request.form.get('phone')
            gps_address = request.form.get('gps_address')
            date_of_birth = request.form.get('date_of_birth')
            ghana_card_id = request.form.get('ghana_card_id')
            
            # Validate changes
            if email != user.email and User.query.filter_by(email=email).first():
                flash('Email already in use', 'error')
                return redirect(url_for('account_settings'))
                
            if phone and phone != user.phone and User.query.filter_by(phone=phone).first():
                flash('Phone number already in use', 'error')
                return redirect(url_for('account_settings'))
                
            if ghana_card_id and ghana_card_id != user.ghana_card_id and User.query.filter_by(ghana_card_id=ghana_card_id).first():
                flash('Ghana Card ID already in use', 'error')
                return redirect(url_for('account_settings'))
                
            user.full_name = full_name
            user.email = email
            user.phone = phone
            user.gps_address = gps_address
            user.date_of_birth = datetime.strptime(date_of_birth, '%Y-%m-%d').date() if date_of_birth else None
            user.ghana_card_id = ghana_card_id
            
            # Handle profile image upload
            if 'profile_image' in request.files:
                file = request.files['profile_image']
                if file.filename != '':
                    filename = save_profile_image(file, user.id)
                    if filename:
                        # Delete old image if exists
                        if user.profile_image:
                            try:
                                old_image_path = os.path.join(app.config['UPLOAD_FOLDER'], user.profile_image)
                                if os.path.exists(old_image_path):
                                    os.remove(old_image_path)
                            except OSError:
                                pass
                        user.profile_image = filename
                        session['profile_image'] = filename
            
            db.session.commit()
            flash('Profile updated successfully', 'success')
        
        # Change password
        elif 'change_password' in request.form:
            current_password = request.form.get('current_password')
            new_password = request.form.get('new_password')
            confirm_password = request.form.get('confirm_password')
            
            # Skip password check for Google users without password
            if user.password_hash:
                if not check_password_hash(user.password_hash, current_password):
                    flash('Current password is incorrect', 'error')
                    return redirect(url_for('account_settings'))
            
            if new_password != confirm_password:
                flash('New passwords do not match', 'error')
                return redirect(url_for('account_settings'))
                
            is_valid, message = validate_password(new_password)
            if not is_valid:
                flash(message, 'error')
                return redirect(url_for('account_settings'))
                
            user.password_hash = generate_password_hash(new_password)
            db.session.commit()
            flash('Password changed successfully', 'success')
        
        # Update accounts
        elif 'update_accounts' in request.form:
            checking_account = request.form.get('checking_account')
            savings_account = request.form.get('savings_account')
            
            if checking_account != user.checking_account and User.query.filter_by(checking_account=checking_account).first():
                flash('Checking account number already in use', 'error')
                return redirect(url_for('account_settings'))
                
            if savings_account != user.savings_account and User.query.filter_by(savings_account=savings_account).first():
                flash('Savings account number already in use', 'error')
                return redirect(url_for('account_settings'))
                
            user.checking_account = checking_account
            user.savings_account = savings_account
            db.session.commit()
            flash('Account numbers updated successfully', 'success')
    
    return render_template('account_settings.html', user=user)

@app.route('/send_money', methods=['POST'])
@login_required
def send_money():
    user = User.query.get(session['user_id'])
    recipient = request.form.get('recipient')
    amount = float(request.form.get('amount'))
    from_account = request.form.get('from_account')
    description = request.form.get('description', 'Money transfer')
    
    # Validate amount
    if amount <= 0:
        flash('Amount must be greater than zero', 'error')
        return redirect(url_for('dashboard'))
    
    # Check sender balance
    if from_account == 'checking':
        if user.checking_balance < amount:
            flash('Insufficient funds in checking account', 'error')
            return redirect(url_for('dashboard'))
        user.checking_balance -= amount
    else:
        if user.savings_balance < amount:
            flash('Insufficient funds in savings account', 'error')
            return redirect(url_for('dashboard'))
        user.savings_balance -= amount
    
    # Find recipient (demo only - would be real lookup in production)
    recipient_user = None
    if '@' in recipient:
        recipient_user = User.query.filter_by(email=recipient).first()
    else:
        recipient_user = User.query.filter_by(phone=recipient).first()
    
    # Create transactions
    if recipient_user:
        if from_account == 'checking':
            recipient_user.checking_balance += amount
        else:
            recipient_user.savings_balance += amount
        
        # Create transaction for sender
        create_transaction(
            user.id,
            'debit',
            amount,
            f"Transfer to {recipient_user.full_name}",
            from_account,
            user.checking_balance if from_account == 'checking' else user.savings_balance
        )
        
        # Create transaction for recipient
        create_transaction(
            recipient_user.id,
            'credit',
            amount,
            f"Transfer from {user.full_name}",
            from_account,
            recipient_user.checking_balance if from_account == 'checking' else recipient_user.savings_balance
        )
        
        db.session.commit()
        flash(f'Transfer of ₵{amount:.2f} to {recipient_user.full_name} successful!', 'success')
    else:
        flash('Recipient not found', 'error')
    
    return redirect(url_for('dashboard'))

@app.route('/request_money', methods=['POST'])
@login_required
def request_money():
    user = User.query.get(session['user_id'])
    recipient = request.form.get('recipient')
    amount = float(request.form.get('amount'))
    message = request.form.get('message', 'Please send money')
    
    # Validate amount
    if amount <= 0:
        flash('Amount must be greater than zero', 'error')
        return redirect(url_for('dashboard'))
    
    # Find recipient (demo only)
    recipient_user = None
    if '@' in recipient:
        recipient_user = User.query.filter_by(email=recipient).first()
    else:
        recipient_user = User.query.filter_by(phone=recipient).first()
    
    if recipient_user:
        # Send email notification
        send_email(
            recipient_user.email,
            'Money Request',
            'emails/money_request.html',
            sender=user,
            recipient=recipient_user,
            amount=amount,
            message=message
        )
        flash(f'Money request sent to {recipient_user.full_name}', 'success')
    else:
        flash('Recipient not found', 'error')
    
    return redirect(url_for('dashboard'))

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email')
        user = User.query.filter_by(email=email).first()
        
        if user:
            # Generate reset token
            reset_token = secrets.token_urlsafe(32)
            user.reset_token = reset_token
            user.reset_token_expiry = datetime.utcnow() + timedelta(hours=1)
            db.session.commit()
            
            # Send reset email
            reset_link = url_for('reset_password', token=reset_token, _external=True)
            send_email(
                user.email,
                'Password Reset Request',
                'emails/password_reset.html',
                user=user,
                reset_link=reset_link
            )
        
        flash('If an account with that email exists, a password reset link has been sent', 'info')
        return redirect(url_for('login'))
    
    return render_template('forgot_password.html')

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    user = User.query.filter_by(reset_token=token).first()
    
    if not user or user.reset_token_expiry < datetime.utcnow():
        flash('Invalid or expired reset token', 'error')
        return redirect(url_for('forgot_password'))
    
    if request.method == 'POST':
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        if password != confirm_password:
            flash('Passwords do not match', 'error')
            return render_template('reset_password.html', token=token)
        
        is_valid, message = validate_password(password)
        if not is_valid:
            flash(message, 'error')
            return render_template('reset_password.html', token=token)
        
        # Update password
        user.password_hash = generate_password_hash(password)
        user.reset_token = None
        user.reset_token_expiry = None
        db.session.commit()
        
        flash('Your password has been reset successfully', 'success')
        return redirect(url_for('login'))
    
    return render_template('reset_password.html', token=token)

@app.route('/budget')
@login_required
def budget():
    user = User.query.get(session['user_id'])
    budgets = Budget.query.filter_by(user_id=user.id).all()
    
    # Calculate total budget and spending
    total_budget = sum(b.budget_amount for b in budgets)
    total_spent = sum(b.spent for b in budgets)
    
    return render_template('budgeting.html', 
                          user=user, 
                          budgets=budgets,
                          total_budget=total_budget,
                          total_spent=total_spent)

@app.route('/add_budget', methods=['POST'])
@login_required
def add_budget():
    user = User.query.get(session['user_id'])
    category = request.form.get('category')
    amount = float(request.form.get('amount'))
    
    # Check if budget already exists
    existing = Budget.query.filter_by(user_id=user.id, category=category).first()
    if existing:
        flash('Budget for this category already exists', 'error')
        return redirect(url_for('budget'))
    
    # Create new budget
    budget = Budget(
        user_id=user.id,
        category=category,
        budget_amount=amount
    )
    
    db.session.add(budget)
    db.session.commit()
    
    flash('Budget category added!', 'success')
    return redirect(url_for('budget'))

@app.route('/update_budget/<int:id>', methods=['POST'])
@login_required
def update_budget(id):
    budget = Budget.query.get_or_404(id)
    
    # Validate user ownership
    if budget.user_id != session['user_id']:
        flash('Unauthorized action', 'error')
        return redirect(url_for('budget'))
    
    # Update budget
    budget.budget_amount = float(request.form.get('amount'))
    budget.spent = float(request.form.get('spent'))
    db.session.commit()
    
    flash('Budget updated!', 'success')
    return redirect(url_for('budget'))

@app.route('/delete_budget/<int:id>')
@login_required
def delete_budget(id):
    budget = Budget.query.get_or_404(id)
    
    # Validate user ownership
    if budget.user_id != session['user_id']:
        flash('Unauthorized action', 'error')
        return redirect(url_for('budget'))
    
    db.session.delete(budget)
    db.session.commit()
    
    flash('Budget category deleted!', 'success')
    return redirect(url_for('budget'))

@app.route('/link_external_account', methods=['POST'])
@login_required
def link_external_account():
    user = User.query.get(session['user_id'])
    bank_code = request.form.get('bank_code')
    account_name = request.form.get('account_name')
    account_number = request.form.get('account_number')
    
    # Check if account already linked
    existing = ExternalBankAccount.query.filter_by(
        user_id=user.id,
        bank_code=bank_code,
        account_number=account_number
    ).first()
    
    if existing:
        flash('This account is already linked', 'error')
        return redirect(url_for('bank_hub'))
    
    # Create new linked account
    bank_account = ExternalBankAccount(
        user_id=user.id,
        bank_code=bank_code,
        account_name=account_name,
        account_number=account_number
    )
    
    db.session.add(bank_account)
    db.session.commit()
    
    flash('Bank account linked successfully!', 'success')
    return redirect(url_for('bank_hub'))

@app.route('/unlink_bank_account/<int:id>')
@login_required
def unlink_bank_account(id):
    bank_account = ExternalBankAccount.query.get_or_404(id)
    
    # Validate user ownership
    if bank_account.user_id != session['user_id']:
        flash('Unauthorized action', 'error')
        return redirect(url_for('bank_hub'))
    
    db.session.delete(bank_account)
    db.session.commit()
    
    flash('Bank account unlinked successfully!', 'success')
    return redirect(url_for('bank_hub'))

@app.route('/transfer_external', methods=['POST'])
@login_required
def transfer_external():
    user = User.query.get(session['user_id'])
    bank_name = request.form.get('bank_name')
    recipient_account = request.form.get('recipient_account')
    amount = float(request.form.get('amount'))
    from_account = request.form.get('from_account')
    description = request.form.get('description', 'External transfer')
    
    # Validate amount
    if amount <= 0:
        flash('Amount must be greater than zero', 'error')
        return redirect(url_for('bank_hub'))
    
    # Check sender balance
    if from_account == 'checking':
        if user.checking_balance < amount:
            flash('Insufficient funds in checking account', 'error')
            return redirect(url_for('bank_hub'))
        user.checking_balance -= amount
    else:
        if user.savings_balance < amount:
            flash('Insufficient funds in savings account', 'error')
            return redirect(url_for('bank_hub'))
        user.savings_balance -= amount
    
    # Create transaction
    create_transaction(
        user.id,
        'debit',
        amount,
        f"External transfer to {bank_name} - {recipient_account}",
        from_account,
        user.checking_balance if from_account == 'checking' else user.savings_balance
    )
    
    # Create external transaction record
    external_txn = ExternalTransaction(
        user_id=user.id,
        transaction_type='debit',
        amount=amount,
        description=description,
        status='completed',
        reference_id=f"EXT{secrets.token_hex(8).upper()}"
    )
    
    db.session.add(external_txn)
    db.session.commit()
    
    flash(f'Transfer of ₵{amount:.2f} to {bank_name} successful!', 'success')
    return redirect(url_for('bank_hub'))

@app.route('/api/transactions')
@login_required
def api_transactions():
    user = User.query.get(session['user_id'])
    transactions = Transaction.query.filter_by(user_id=user.id).order_by(Transaction.created_at.desc()).limit(10).all()
    
    return jsonify([{
        'type': txn.transaction_type,
        'amount': txn.amount,
        'description': txn.description,
        'date': txn.created_at.strftime('%Y-%m-%d %H:%M'),
        'balance': txn.balance_after
    } for txn in transactions])

@app.route('/api/balance')
@login_required
def api_balance():
    user = User.query.get(session['user_id'])
    return jsonify({
        'checking': user.checking_balance,
        'savings': user.savings_balance
    })

# Add the new 'transfer' endpoint
@app.route('/transfer', methods=['POST'])
@login_required
def transfer():
    user = User.query.get(session['user_id'])
    recipient_account = request.form.get('recipient_account')
    amount = float(request.form.get('amount'))
    from_account = request.form.get('from_account')
    description = request.form.get('description', 'Internal transfer')
    
    # Validate amount
    if amount <= 0:
        flash('Amount must be greater than zero', 'error')
        return redirect(url_for('bank_hub'))
    
    # Find recipient by their checking or savings account number
    recipient_user = User.query.filter(
        (User.checking_account == recipient_account) | (User.savings_account == recipient_account)
    ).first()
    
    if not recipient_user:
        flash('Recipient account not found', 'error')
        return redirect(url_for('bank_hub'))
    
    # Prevent self-transfer
    if recipient_user.id == user.id:
        flash('Cannot transfer to your own account', 'error')
        return redirect(url_for('bank_hub'))
        
    # Check sender balance
    if from_account == 'checking':
        if user.checking_balance < amount:
            flash('Insufficient funds in checking account', 'error')
            return redirect(url_for('bank_hub'))
        user.checking_balance -= amount
    else:
        if user.savings_balance < amount:
            flash('Insufficient funds in savings account', 'error')
            return redirect(url_for('bank_hub'))
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
    flash(f'Transfer of ₵{amount:.2f} to {recipient_user.full_name} successful!', 'success')
    return redirect(url_for('bank_hub'))

# Fully implemented map route
@app.route('/map_view')
@login_required
def map_view():
    user = User.query.get(session['user_id'])

    # Sample agent locations (latitude, longitude)
    agent_locations = [
        (5.6037, -0.1870, 'Accra Main Branch'),
        (5.5780, -0.2188, 'Osu Agent Point'),
        (5.6148, -0.2058, 'Kwame Nkrumah Circle Office'),
        (6.6885, -1.6244, 'Kumasi Branch'),
        (4.9009, -1.7486, 'Takoradi Agent'),
        (5.1009, -1.2612, 'Cape Coast Agent')
    ]

    # Create a map centered on Ghana
    m = folium.Map(location=[7.9465, -1.0232], zoom_start=6)

    # Add markers for each agent location
    for lat, lon, name in agent_locations:
        folium.Marker(
            location=[lat, lon],
            popup=name,
            tooltip=name,
            icon=folium.Icon(color='blue', icon='info-sign')
        ).add_to(m)

    # Save map to an HTML string
    map_html = m.get_root().render()

    return render_template('map_view.html', user=user, map_html=map_html)

@app.errorhandler(404)
def not_found(error):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    return render_template('500.html'), 500

# Start local SMTP server for development
def start_smtp_server():
    from aiosmtpd.controller import Controller
    from aiosmtpd.handlers import Message
    
    class DebuggingHandler:
        async def handle_DATA(self, server, session, envelope):
            print(f"Received message from: {envelope.mail_from}")
            print(f"To: {envelope.rcpt_tos}")
            print(f"Message data:\n{envelope.content.decode('utf8', errors='replace')}")
            print("=" * 50)
            return '250 Message accepted for delivery'
    
    controller = Controller(DebuggingHandler(), hostname='127.0.0.1', port=1025)
    controller.start()
    print("SMTP server started on localhost:1025")
    return controller

if __name__ == '__main__':
    with app.app_context():
        db.create_all()

    smtp_controller = None
    # The reloader (when debug=True) sets this environment variable.
    # We only want to start the SMTP server in the main "watcher" process,
    # not in the reloaded "worker" process.
    if os.environ.get("WERKZEUG_RUN_MAIN") != "true":
        smtp_controller = start_smtp_server()

    try:
        app.run(debug=True, host='0.0.0.0', port=5000)
    finally:
        if smtp_controller:
            print("Stopping SMTP server...")
            smtp_controller.stop()
