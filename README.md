# Flask-Based Login & Registration Portal
A beginner-friendly project built with Flask, HTML, CSS, and JavaScript that demonstrates secure user authentication, OTP verification, and session management.

## Technologies Used
- **Flask (Python)** – Lightweight web framework for backend logic  
- **HTML5 & CSS3** – Structure and styling of the web pages  
- **JavaScript** – Frontend interactivity and form validation  
- **Flask-Mail** – Sending OTPs via email  
- **Werkzeug Security** – Secure password hashing  
- **Python Dotenv** – Managing environment variables securely  
- **reCAPTCHA** – Bot protection using Google’s reCAPTCHA  
- **JSON** – Lightweight format for storing user data  

## Features
- **User Registration with OTP Verification**  
  - OTP valid for 1 minute  
  - Max 3 resend attempts  
  - Blocks further attempts for 1 hour after the limit

- **Login with Email and Password**

- **Forgot Password Flow with OTP Verification**

- **reCAPTCHA Integration**  
  - Prevents bot-based form submissions

- **Form Validation Rules**  
  - Names must contain only alphabets  
  - Passwords must be at least 8 characters and include:
    - Uppercase letters  
    - Lowercase letters  
    - Numbers  
    - Special symbols

- **Session Management**  
  - Prevents access to the dashboard after logout via the browser back button

- **Secure Password Hashing**  
  - Uses `werkzeug.security` for encryption

- **Environment Variables**  
  - Managed via the `.env` file to keep sensitive data safe

## Installation
1. **Clone the repository**
   ```bash
   git clone https://github.com/<your_username>/login-registration-portal.git
   cd login-registration-portal

2. **Create and activate a virtual environment**
   ```bash
   python -m venv venv
   source venv/bin/activate # On Mac/Linux
   venv\Scripts\activate  # On Windows

3. **Install Required Packages**
   ```Bash
	 pip install -r requirements.txt #Install all necessary Python libraries listed in requirements.txt.

4. **Create a .env file**
   ```env
   SECRET_KEY=your-secret-key
   
   MAIL_SERVER=smtp.gmail.com
   MAIL_PORT=587
   MAIL_USERNAME=your-email@example.com
   MAIL_PASSWORD=your-app-password
   MAIL_DEFAULT_SENDER=your-email@example.com
   
   RECAPTCHA_SITE_KEY=your_recaptcha_site_key
   RECAPTCHA_SECRET_KEY=your_recaptcha_secret_key

5. **Run the Flask Application**
   ```Bash
   python app.py

6. **Open your Browser and Visit**
   http://localhost:5000

## Folder Structure
```Markdown
login-registration-portal/
├── templates/           # HTML templates with CSS and JS
    ├── login.html             # User login form
    ├── register.html          # User registration form
    ├── verify_otp.html        # User verify otp 
    ├── dashboard.html         # User dashboard after login
    ├── forgot_password.html   # User dashboard after login
    └── reset_password.html    # User dashboard after login     
├── app.py               # Main Flask application
├── requirements.txt     # Python dependencies
├── .env                 # Environment variables
└── README.md            # Project documentation
```

## Security Features
This project includes several built-in security measures to protect user data and application integrity:

**Password Handling**
- **Hashed Passwords**: User passwords are securely hashed using `werkzeug.security` before storing in the database.
- **No Plaintext Storage**: Passwords are never stored or transmitted in plaintext.

**Input Validation**
- **Form Validation**: All user inputs are validated to prevent malformed or malicious data.
- **Length & Format Checks**: Email, username, and password fields are checked for proper format and length.

**Session Management**
- **Secure Sessions**: Flask sessions are used to manage user authentication securely.
- **Session Expiry**: Sessions can be configured to expire after a set duration to reduce risk of hijacking.

**Environment Variables**
- **Sensitive Data Isolation**: Secrets like database URIs and secret keys are stored in a `.env` file and loaded using `python-dotenv`.

**OTP-Based Security**
- **OTP Verification**: Required for both registration and forgot password workflows
- **OTP Validity**: Each OTP is valid for **1 minute**
- **Resend Limit**: Users can request a new OTP up to **3 times**
- **Temporary Block**: After 3 failed or expired attempts, the user is **blocked for 1 hour**

## License

This project is intended for **educational purposes only**.

**Usage Terms**

-  You may use, modify, and share this code for learning, teaching, or academic projects.
-  Commercial use, redistribution, or deployment in production environments is **not permitted** without explicit permission.
-  This project is provided "as is" with no warranties or guarantees.

> If you wish to use this project beyond educational scope, please contact the author for permission.
