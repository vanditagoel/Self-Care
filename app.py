from flask import Flask, request, jsonify
from flask_mail import Mail, Message
import mysql.connector
import bcrypt
import random
import string
from datetime import datetime, timedelta

app = Flask(__name__)

# Email configuration
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'your_email@gmail.com'  # Your Gmail
app.config['MAIL_PASSWORD'] = 'your_app_password'     # Your Gmail App Password
mail = Mail(app)

# Store OTPs temporarily (in production, use a database)
otps = {}

def get_db_connection():
    connection = mysql.connector.connect(
        host='localhost',
        user='root',
        password='password',
        database='userdb'
    )
    return connection

def generate_otp():
    return ''.join(random.choices(string.digits, k=4))

def send_otp_email(email, otp):
    msg = Message('Email Verification OTP',
                 sender='your_email@gmail.com',
                 recipients=[email])
    msg.body = f'Your OTP for account verification is: {otp}'
    mail.send(msg)

@app.route('/signup', methods=['POST'])
def signup():
    data = request.get_json()
    
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')
    rePassword = data.get('rePassword')

    if password != rePassword:
        return jsonify({"error": "Passwords do not match!"}), 400

    # Generate and send OTP
    otp = generate_otp()
    otps[email] = {
        'otp': otp,
        'username': username,
        'password': password,
        'timestamp': datetime.now()
    }
    
    try:
        send_otp_email(email, otp)
        return jsonify({"message": "OTP sent to email"}), 200
    except Exception as e:
        return jsonify({"error": "Failed to send OTP"}), 500

@app.route('/verify-otp', methods=['POST'])
def verify_otp():
    data = request.get_json()
    email = data.get('email')
    submitted_otp = data.get('otp')

    if email not in otps:
        return jsonify({"error": "No OTP request found"}), 400

    stored_data = otps[email]
    
    # Check if OTP is expired (15 minutes validity)
    if datetime.now() - stored_data['timestamp'] > timedelta(minutes=15):
        del otps[email]
        return jsonify({"error": "OTP expired"}), 400

    if submitted_otp != stored_data['otp']:
        return jsonify({"error": "Invalid OTP"}), 400

    # OTP verified, proceed with registration
    hashed_password = bcrypt.hashpw(stored_data['password'].encode('utf-8'), bcrypt.gensalt())

    connection = get_db_connection()
    cursor = connection.cursor()

    try:
        cursor.execute("INSERT INTO users (username, email, password, is_verified) VALUES (%s, %s, %s, %s)",
                      (stored_data['username'], email, hashed_password, True))
        connection.commit()
        del otps[email]  # Clear OTP after successful verification
        return jsonify({"message": "User registered successfully"}), 201
    except mysql.connector.Error as err:
        return jsonify({"error": str(err)}), 500
    finally:
        cursor.close()
        connection.close()

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    connection = get_db_connection()
    cursor = connection.cursor()

    try:
        cursor.execute("SELECT * FROM users WHERE username = %s AND is_verified = TRUE", (username,))
        user = cursor.fetchone()

        if not user:
            return jsonify({"error": "User not found or not verified"}), 404

        if bcrypt.checkpw(password.encode('utf-8'), user[3].encode('utf-8')):
            return jsonify({"message": "Login successful"}), 200
        else:
            return jsonify({"error": "Invalid credentials"}), 400
    finally:
        cursor.close()
        connection.close()

if __name__ == '__main__':
    app.run(debug=True)
