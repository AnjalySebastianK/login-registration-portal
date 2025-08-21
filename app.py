from flask import Flask, render_template, request, redirect, url_for, session, make_response
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from models import Base,User, PendingUser
from flask_bcrypt import Bcrypt
from flask_mail import Mail, Message
from datetime import datetime, timedelta
from dotenv import load_dotenv
import os, random, requests, secrets,hashlib, re

# Load environment variables
load_dotenv()
app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY')

bcrypt = Bcrypt(app)

engine = create_engine('sqlite:///users.db')
Base.metadata.create_all(engine)
Session = sessionmaker(bind=engine)
db_session = Session()


# Flask-Mail configuration
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')  # yourapp@gmail.com
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')  # app password
app.config['MAIL_DEFAULT_SENDER'] = os.getenv('MAIL_DEFAULT_SENDER')  # same as username
mail = Mail(app)

# reCAPTCHA verification
def verify_recaptcha(response_token):
    payload = {
        'secret': os.getenv('RECAPTCHA_SECRET_KEY'),
        'response': response_token
    }
    r = requests.post('https://www.google.com/recaptcha/api/siteverify', data=payload)
    return r.json().get('success', False)

# Generate a secure OTP and its expiry
def generate_otp():
    otp = str(secrets.randbelow(10**6)).zfill(6)  # Always 6 digits
    expiry = datetime.now() + timedelta(minutes=1)
    # Hash the OTP before storing
    hashed_otp = hashlib.sha256(otp.encode()).hexdigest()
    return otp, hashed_otp, expiry

# Send OTP email
def send_otp_email(recipient_email, first_name, otp, subject="Your OTP for Registration"):
    try:
        msg = Message(
            subject=subject,
            recipients=[recipient_email],
            body=f"Hello {first_name},\n\nYour OTP is: {otp}\nIt will expire in 1 minutes.\nIf you did not request this, please ignore this message."
        )
        mail.send(msg)
        return True
    except Exception as e:
        print(f"Error sending OTP to {recipient_email}: {e}")
        return False
    
def prevent_cache(response):
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, post-check=0, pre-check=0, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response

def cleanup_expired_pending_users():
    expiry_time = datetime.utcnow() - timedelta(hours=1)
    expired_users = db_session.query(PendingUser).filter(PendingUser.created_at < expiry_time).all()
    
    for user in expired_users:
        db_session.delete(user)
    
    db_session.commit()

def is_strong_password(password):
    return (
        len(password) >= 8 and
        re.search(r'[A-Z]', password) and
        re.search(r'[a-z]', password) and
        re.search(r'\d', password) and
        re.search(r'[!@#$%^&*(),.?":{}|<>]', password)
    )



@app.route('/')
def home():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '').strip()
        recaptcha_response = request.form.get('g-recaptcha-response')

        if not verify_recaptcha(recaptcha_response):
            response = make_response(render_template('login.html',error="Please complete the CAPTCHA.",site_key=os.getenv('RECAPTCHA_SITE_KEY')))
        else:
            user = db_session.query(User).filter_by(email=email).first()
            
            if user and bcrypt.check_password_hash(user.password, password):
                session['username'] = email
                return redirect(url_for('dashboard'))
            else:
                response = make_response(render_template('login.html',error="Invalid email or password.",site_key=os.getenv('RECAPTCHA_SITE_KEY')))
    else:
        message = request.args.get('message', '')
        error = request.args.get('error', '')
        response = make_response(render_template('login.html',message=message,error=error,site_key=os.getenv('RECAPTCHA_SITE_KEY')))

    response = prevent_cache(response)
    return response

@app.route('/dashboard')
def dashboard():
    if 'username' in session:
        email = session['username']
        user = db_session.query(User).filter_by(email=email).first()
        response = make_response(render_template('dashboard.html', username=email, user=user))
        response = prevent_cache(response)
        return response
    return redirect(url_for('login'))

@app.route('/logout')
def logout():
    session.clear()  # Clears all session data
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    error=""
    if request.method == 'POST':

        # Get form data
        first_name = request.form.get('first_name', '').strip()
        last_name = request.form.get('last_name', '').strip()
        email = request.form.get('email','').strip()
        confirm_email = request.form.get('confirm_email','').strip()
        password = request.form.get('password','').strip()
        confirm_password = request.form.get('confirm_password','').strip()
        
        # Verify reCAPTCHA
        recaptcha_response = request.form.get('g-recaptcha-response')
        if not verify_recaptcha(recaptcha_response):
            response = make_response(render_template('register.html', error="Please complete the CAPTCHA.", site_key=os.getenv('RECAPTCHA_SITE_KEY')))
            response = prevent_cache(response)
            return response

        # Server-side email match check
        if email != confirm_email:
            error = "Email addresses do not match."
        elif db_session.query(PendingUser).filter_by(email=email).first():
            error = "An account with this email already exists."
        elif db_session.query(User).filter_by(email=email).first():
            error = "An account with this email already exists."


        # Server-side password strength check
        elif len(password) < 8 or not any(c.isupper() for c in password) or not any(c.islower() for c in password) or not any(c.isdigit() for c in password) or not any(c in "@$!%*?&" for c in password):
            error = "Password must be at least 8 characters long and include uppercase, lowercase, number, and symbol."
        elif password != confirm_password:
            error = "Passwords do not match."

        if error:
            response = make_response(render_template('register.html', error=error, site_key=os.getenv('RECAPTCHA_SITE_KEY')))
            response = prevent_cache(response)
            return response

        # Generate OTP
        otp,hashed_otp, otp_expiry = generate_otp()
        if not send_otp_email(email, first_name, otp):
            response = make_response(render_template('register.html', error="Failed to send OTP. Please check your email settings.", site_key=os.getenv('RECAPTCHA_SITE_KEY')))
            response = prevent_cache(response)
            return response

        # Store user in database
        new_user = PendingUser(
            email=email,
            first_name=first_name,
            last_name=last_name,
            password=bcrypt.generate_password_hash(password).decode('utf-8'),
            otp=hashed_otp,
            otp_expiry=otp_expiry,
            resend_count=0,
            resend_block_until=None
        )
        db_session.add(new_user)
        db_session.commit()

        return redirect(url_for('verify_otp', email=email))
    
    # GET request — render form with cache-control
    response = make_response(render_template('register.html', error=error, site_key=os.getenv('RECAPTCHA_SITE_KEY')))
    response = prevent_cache(response)
    return response

MAX_ATTEMPTS = 3
BLOCK_DURATION = timedelta(minutes=5)

@app.route('/verify_otp/<email>', methods=['GET', 'POST'])
def verify_otp(email):
    error = ""
    message = ""
    user_data = db_session.query(PendingUser).filter_by(email=email).first()

    if request.method == 'POST':
        entered_otp = request.form.get('otp', '').strip()
        
        if not user_data:
            error = "Session expired or invalid email."
        
        elif user_data.resend_block_until and datetime.now() < user_data.resend_block_until:
            error = f"Too many failed attempts. Please try again after {user_data.resend_block_until.strftime('%H:%M:%S')}."

        elif datetime.now() > user_data.otp_expiry:
            error = "OTP has expired. Please register again."
            db_session.delete(user_data)
            db_session.commit()

        elif hashlib.sha256(entered_otp.encode()).hexdigest() == user_data.otp:
            username = email.split('@')[0]
            new_user = User(
                username=username,
                email=user_data.email,
                password=user_data.password
            )

            db_session.add(new_user)
            db_session.delete(user_data)
            db_session.commit()

            return redirect(url_for('login', message='Registration successful! Please log in.'))
        else:
            user_data.resend_count += 1

            if user_data.resend_count >= MAX_ATTEMPTS:
                user_data.resend_block_until = datetime.now() + BLOCK_DURATION
                error = f"Too many failed attempts. You are blocked for {BLOCK_DURATION.total_seconds() // 60:.0f} minutes."
            else:
                error = f"Invalid OTP. You have {MAX_ATTEMPTS - user_data.resend_count} attempts left."

            db_session.commit()


    response = make_response(render_template('verify_otp.html', email=email, error=error, message=message))
    response = prevent_cache(response)
    return response


# Resend OTP
@app.route('/resend_otp/<email>', methods=['GET', 'POST'])
def resend_otp(email):
    user_data = db_session.query(PendingUser).filter_by(email=email).first()

    if not user_data:
        return redirect(url_for('register'))

    now = datetime.now()

    # Check if user is currently blocked
    if user_data.resend_block_until and now < user_data.resend_block_until:
        error = "You've reached the resend limit. Please wait 1 hour before trying again."
        return render_template('verify_otp.html', email=email, error=error)

    # Check resend count
    if user_data.resend_count >= 3:
        user_data.resend_block_until = now + timedelta(hours=1)
        user_data.resend_count = 0  # Optional: reset after block
        db_session.commit()
        error = "OTP resend limit reached. Try again in 1 hour."
        return render_template('verify_otp.html', email=email, error=error)

    # Generate new OTP and expiry
    new_otp = str(secrets.randbelow(10**6)).zfill(6)  # Always 6 digits
    hashed_otp = hashlib.sha256(new_otp.encode()).hexdigest()

    user_data.otp = hashed_otp
    user_data.otp_expiry = now + timedelta(minutes=1)
    user_data.resend_count += 1
    db_session.commit()

    if not send_otp_email(email, user_data.first_name, new_otp, subject="Your New OTP for Registration"):
        return render_template('verify_otp.html', email=email, error="Failed to resend OTP. Please try again.")

    message = f"A new OTP has been sent to your email. Attempt {user_data.resend_count} of 3."
    return render_template('verify_otp.html', email=email, message=message)

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        user = db_session.query(User).filter_by(email=email).first()

        if not user:
            return render_template('forgot_password.html', error="Email not found.")

        # Use the updated generate_otp() that returns plain and hashed OTP
        plain_otp, hashed_otp, expiry = generate_otp()

        # Store hashed OTP and expiry in the database
        user.reset_otp = hashed_otp
        user.reset_expiry = expiry
        db_session.commit()

        # Send plain OTP to user via email
        send_otp_email(email, user.username, plain_otp, subject="Your Password Reset OTP")
        return redirect(url_for('reset_password', email=email))
    return render_template('forgot_password.html')


@app.route('/reset_password/<email>', methods=['GET', 'POST'])
def reset_password(email):
    user = db_session.query(User).filter_by(email=email).first()
    if not user:
        return redirect(url_for('forgot_password'))

    step = request.args.get('step', 'otp')  # Default step is OTP

    if request.method == 'POST':
        if step == 'otp':
            entered_otp = request.form.get('otp', '').strip()

            if datetime.now() > (user.reset_expiry or datetime.min):
                response = make_response(render_template('reset_password.html', email=email, error="OTP expired.", step="otp"))
                response = prevent_cache(response)
                return response
            
            # Hash entered OTP before comparing
            hashed_entered_otp = hashlib.sha256(entered_otp.encode()).hexdigest()
            if hashed_entered_otp != user.reset_otp:
                response = make_response(render_template('reset_password.html',email=email,error="Invalid OTP.",step="otp"))
                response = prevent_cache(response)
                return response
            
            # OTP is valid — move to password step
            response = make_response(render_template('reset_password.html',email=email,step="password"))
            response = prevent_cache(response)
            return response

        elif step == 'password':
            new_password = request.form.get('new_password', '').strip()
            confirm_password = request.form.get('confirm_password', '').strip()

            if new_password != confirm_password:
                response = make_response(render_template('reset_password.html', email=email, error="Passwords do not match.", step="password"))
                response = prevent_cache(response)
                return response
            
            if not is_strong_password(new_password):
                response = make_response(render_template('reset_password.html', email=email, error="Password must be at least 8 characters and include uppercase, lowercase, number, and symbol.", step="password"))
                response = prevent_cache(response)
                return response

            if bcrypt.check_password_hash(user.password, new_password):
                response = make_response(render_template('reset_password.html', email=email, error="New password must be different from the old password.", step="password"))
                response = prevent_cache(response)
                return response

            user.password = bcrypt.generate_password_hash(new_password).decode('utf-8')
            user.reset_otp = None
            user.reset_expiry = None
            db_session.commit()

            response = make_response(redirect(url_for('login', message="Password reset successful. Please log in.")))
            response = prevent_cache(response)
            return response

    # Initial GET request — show OTP form
    response = make_response(render_template('reset_password.html', email=email, step=step))
    response = prevent_cache(response)
    return response

from apscheduler.schedulers.background import BackgroundScheduler

scheduler = BackgroundScheduler()
scheduler.add_job(cleanup_expired_pending_users, 'interval', minutes=30)
scheduler.start()

if __name__ == '__main__':
    app.run(debug=True)
