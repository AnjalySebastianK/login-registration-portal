from flask import Flask, render_template, request, redirect, url_for, session, make_response
from werkzeug.security import generate_password_hash, check_password_hash
from flask_mail import Mail, Message
from datetime import datetime, timedelta
from dotenv import load_dotenv
import os, random, requests, json

# Load environment variables
load_dotenv()
app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY')

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

# Temporary user storage
users = {}
pending_users = {}

# Load users from file
def load_users():
    try:
        with open("users.json", "r") as f:
            return json.load(f)
    except FileNotFoundError:
        return {}

#def save_users(users_data):
 #   with open("users.json", "w") as f:
  #      json.dump(users_data, f, indent=4)

users = load_users()

# Send OTP email
def send_otp_email(recipient_email, first_name, otp, subject="Your OTP for Registration"):
    try:
        msg = Message(
            subject=subject,
            recipients=[recipient_email],
            body=f"Hello {first_name},\n\nYour OTP is: {otp}\nIt will expire in 1 minutes."
        )
        mail.send(msg)
        return True
    except Exception as e:
        print(f"Error sending OTP to {recipient_email}: {e}")
        return False
    
def generate_otp():
    otp = str(random.randint(100000, 999999))
    expiry = datetime.now() + timedelta(minutes=1)
    return otp, expiry

def save_users(users):
    with open('users.json', 'w') as f:
        json.dump(users, f, indent=4)


@app.route('/')
def home():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')
        recaptcha_response = request.form.get('g-recaptcha-response')

        if not verify_recaptcha(recaptcha_response):
            response = make_response(render_template('login.html',error="Please complete the CAPTCHA.",site_key=os.getenv('RECAPTCHA_SITE_KEY')))
        else:
            user = users.get(email)
            if user and check_password_hash(user['password'], password):
                session['username'] = email
                return redirect(url_for('dashboard'))
            else:
                response = make_response(render_template('login.html',error="Invalid email or password.",site_key=os.getenv('RECAPTCHA_SITE_KEY')))
    else:
        message = request.args.get('message', '')
        error = request.args.get('error', '')
        response = make_response(render_template('login.html',message=message,error=error,site_key=os.getenv('RECAPTCHA_SITE_KEY')))

    # Prevent caching of login page
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, post-check=0, pre-check=0, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response

@app.route('/dashboard')
def dashboard():
    if 'username' in session:
        username = session['username']
        user = users.get(username)
        response = make_response(render_template('dashboard.html', username=username, user=user))
        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, post-check=0, pre-check=0, max-age=0'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'  # Prevent caching
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
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password','').strip()
        birth_year = request.form.get('birth_year', '').strip()
        
        # Verify reCAPTCHA
        recaptcha_response = request.form.get('g-recaptcha-response')
        if not verify_recaptcha(recaptcha_response):
            response = make_response(render_template('register.html', error="Please complete the CAPTCHA.", site_key=os.getenv('RECAPTCHA_SITE_KEY')))
            response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
            response.headers['Pragma'] = 'no-cache'
            return response

        # Server-side email match check
        if email != confirm_email:
            error = "Email addresses do not match."
        elif email in users:
            error = "An account with this email already exists."

        # Server-side password strength check
        elif len(password) < 8 or not any(c.isupper() for c in password) or not any(c.islower() for c in password) or not any(c.isdigit() for c in password) or not any(c in "@$!%*?&" for c in password):
            error = "Password must be at least 8 characters long and include uppercase, lowercase, number, and symbol."
        elif password != confirm_password:
            error = "Passwords do not match."
        # Validate birth year
        else:
            try:
                birth_year_int = int(birth_year)
                if birth_year_int < 1900 or birth_year_int > 2025:
                    error = "Please enter a valid birth year between 1900 and 2025."
            except ValueError:
                error = "Birth year must be a number."

        if error:
            response = make_response(render_template('register.html', error=error, site_key=os.getenv('RECAPTCHA_SITE_KEY')))
            response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
            response.headers['Pragma'] = 'no-cache'
            return response

        # Generate OTP
        otp, otp_expiry = generate_otp()
        if not send_otp_email(email, first_name, otp):
            response = make_response(render_template('register.html', error="Failed to send OTP. Please check your email settings.", site_key=os.getenv('RECAPTCHA_SITE_KEY')))
            response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
            response.headers['Pragma'] = 'no-cache'
            return response

        # Store user
        pending_users[email] = {
            'first_name': first_name,
            'last_name': last_name,
            'password': generate_password_hash(password),
            'birth_year': birth_year_int,
            'otp': otp,
            'otp_expiry': otp_expiry,
            'resend_count': 0,
            'resend_block_until': None
        }
        return redirect(url_for('verify_otp', email=email))
    
    # GET request — render form with cache-control
    response = make_response(render_template('register.html', error=error, site_key=os.getenv('RECAPTCHA_SITE_KEY')))
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    return response

@app.route('/verify_otp/<email>', methods=['GET', 'POST'])
def verify_otp(email):
    error = ""
    message = ""
    user_data = pending_users.get(email)

    if request.method == 'POST':
        entered_otp = request.form.get('otp', '').strip()
        
        if not user_data:
            error = "Session expired or invalid email."
        elif datetime.now() > user_data['otp_expiry']:
            error = "OTP has expired. Please register again."
            pending_users.pop(email, None)
        elif entered_otp == user_data['otp']:
            users[email] = {
                'first_name': user_data['first_name'],
                'last_name': user_data['last_name'],
                'password': user_data['password'],
                'birth_year': user_data['birth_year']
            }
            save_users(users)
            pending_users.pop(email, None)
            return redirect(url_for('login', message='Registration successful! Please log in.'))
        else:
            error = "Invalid OTP. Please try again."

    response = make_response(render_template('verify_otp.html', email=email, error=error, message=message))
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    return response


# Resend OTP
from datetime import datetime, timedelta

@app.route('/resend_otp/<email>', methods=['GET', 'POST'])
def resend_otp(email):
    user_data = pending_users.get(email)

    if not user_data:
        return redirect(url_for('register'))

    now = datetime.now()

    # Initialize resend tracking if not present
    if 'resend_count' not in user_data:
        user_data['resend_count'] = 0
    if 'resend_block_until' not in user_data:
        user_data['resend_block_until'] = None

    # Check if user is currently blocked
    if user_data['resend_block_until'] and now < user_data['resend_block_until']:
        error = "You've reached the resend limit. Please wait 1 hour before trying again."
        return render_template('verify_otp.html', email=email, error=error)

    # Check resend count
    if user_data['resend_count'] >= 3:
        user_data['resend_block_until'] = now + timedelta(hours=1)
        user_data['resend_count'] = 0  # Optional: reset after block
        error = "OTP resend limit reached. Try again in 1 hour."
        return render_template('verify_otp.html', email=email, error=error)

    # Generate new OTP and expiry
    new_otp = str(random.randint(100000, 999999))
    user_data.update({
        'otp': new_otp,
        'otp_expiry': now + timedelta(minutes=1),
        'resend_count': user_data['resend_count'] + 1
    })

    if not send_otp_email(email, user_data['first_name'], new_otp, subject="Your New OTP for Registration"):
        return render_template('verify_otp.html', email=email, error="Failed to resend OTP. Please try again.")

    message = f"A new OTP has been sent to your email. Attempt {user_data['resend_count']} of 3."
    return render_template('verify_otp.html', email=email, message=message)

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        user = users.get(email)

        if not user:
            return render_template('forgot_password.html', error="Email not found.")

        # Generate OTP or token
        reset_otp, expiry = generate_otp()
        user['reset_otp'] = str(reset_otp)
        user['reset_expiry'] = expiry

        send_otp_email(email, user['first_name'], reset_otp, subject="Your Password Reset OTP")
        return redirect(url_for('reset_password', email=email))

    return render_template('forgot_password.html')

@app.route('/reset_password/<email>', methods=['GET', 'POST'])
def reset_password(email):
    user = users.get(email)
    if not user:
        return redirect(url_for('forgot_password'))

    step = request.args.get('step', 'otp')  # Default step is OTP

    if request.method == 'POST':
        if step == 'otp':
            entered_otp = request.form.get('otp', '').strip()

            if datetime.now() > user.get('reset_expiry', datetime.min):
                response = make_response(render_template('reset_password.html', email=email, error="OTP expired.", step="otp"))
                response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, post-check=0, pre-check=0'
                response.headers['Pragma'] = 'no-cache'
                return response

            if entered_otp != str(user.get('reset_otp')):
                response = make_response(render_template('reset_password.html', email=email, error="Invalid OTP.", step="otp"))
                response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, post-check=0, pre-check=0'
                response.headers['Pragma'] = 'no-cache'
                return response

            # OTP is valid — move to password step
            response = make_response(render_template('reset_password.html', email=email, step="password"))
            response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, post-check=0, pre-check=0'
            response.headers['Pragma'] = 'no-cache'
            return response

        elif step == 'password':
            new_password = request.form.get('new_password', '').strip()
            confirm_password = request.form.get('confirm_password', '').strip()

            if new_password != confirm_password:
                response = make_response(render_template('reset_password.html', email=email, error="Passwords do not match.", step="password"))
                response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, post-check=0, pre-check=0'
                response.headers['Pragma'] = 'no-cache'
                return response

            if check_password_hash(user['password'], new_password):
                response = make_response(render_template('reset_password.html', email=email, error="New password must be different from the old password.", step="password"))
                response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, post-check=0, pre-check=0'
                response.headers['Pragma'] = 'no-cache'
                return response

            user['password'] = generate_password_hash(new_password)
            user.pop('reset_otp', None)
            user.pop('reset_expiry', None)
            save_users(users)

            response = make_response(redirect(url_for('login', message="Password reset successful. Please log in.")))
            response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, post-check=0, pre-check=0'
            response.headers['Pragma'] = 'no-cache'
            return response

    # Initial GET request — show OTP form
    response = make_response(render_template('reset_password.html', email=email, step=step))
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, post-check=0, pre-check=0'
    response.headers['Pragma'] = 'no-cache'
    return response

if __name__ == '__main__':
    app.run(debug=True)
