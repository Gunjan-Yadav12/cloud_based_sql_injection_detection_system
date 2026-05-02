from flask import Flask, request, render_template
import pymysql
import re
import datetime
import os
from dotenv import load_dotenv

load_dotenv()  # Loads variables from .env file

app = Flask(__name__)

# Credentials loaded from environment — never hardcoded
db = pymysql.connect(
    host=os.environ.get("RDS_HOST"),
    user=os.environ.get("RDS_USER"),
    password=os.environ.get("RDS_PASSWORD"),
    database=os.environ.get("RDS_DATABASE")
)

# SQL Injection detection
def detect_sqli(input_text):
    patterns = [
        r"(\bor\b|\band\b).*=.*",
        r"(--|#|;)",
        r"(union\s+select)",
        r"(drop\s+table)",
        r"(\bor 1=1)"
    ]
    for pattern in patterns:
        if re.search(pattern, input_text, re.IGNORECASE):
            return True
    return False

# Create log table
def create_log_table():
    cursor = db.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS attack_logs (
            id INT AUTO_INCREMENT PRIMARY KEY,
            username VARCHAR(100),
            input_text TEXT,
            time_stamp DATETIME
        )
    """)
    db.commit()

create_log_table()

# Log attack
def log_attack(username, input_text):
    cursor = db.cursor()
    time = datetime.datetime.now()
    query = "INSERT INTO attack_logs (username, input_text, time_stamp) VALUES (%s,%s,%s)"
    cursor.execute(query, (username, input_text, time))
    db.commit()

# LOGIN
@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if detect_sqli(username) or detect_sqli(password):
            log_attack(username, password)
            return """
            <script>
            alert('SQL Injection Detected! Attack Logged');
            window.location.href = '/';
            </script>
            """
        cursor = db.cursor()
        query = "SELECT * FROM users WHERE username=%s AND password=%s"
        cursor.execute(query, (username, password))
        result = cursor.fetchone()
        if result:
            return """
            <script>
            alert('Login Successful');
            window.location.href = '/';
            </script>
            """
        else:
            return """
            <script>
            alert('Invalid Credentials');
            window.location.href = '/';
            </script>
            """
    return render_template('login.html')

# SIGNUP
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if detect_sqli(username) or detect_sqli(password):
            log_attack(username, password)
            return """
            <script>
            alert('SQL Injection Detected! Attack Logged');
            window.location.href = '/signup';
            </script>
            """
        cursor = db.cursor()
        query = "INSERT INTO users (username, password) VALUES (%s,%s)"
        cursor.execute(query, (username, password))
        db.commit()
        return """
        <script>
        alert('Signup Successful');
        window.location.href = '/';
        </script>
        """
    return render_template('signup.html')

# VIEW LOGS
@app.route('/logs')
def logs():
    cursor = db.cursor()
    cursor.execute("SELECT * FROM attack_logs")
    data = cursor.fetchall()
    return str(data)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True) 
