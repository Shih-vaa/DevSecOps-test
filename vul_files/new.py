import sqlite3
import os
import flask
from flask import request, redirect
import pickle
import base64
import subprocess
import logging

# --- VULNERABILITY 1: SQL INJECTION ---
# The function directly formats user input into an SQL query, allowing
# an attacker to manipulate the database.
def vulnerable_sql_injection(username):
    conn = sqlite3.connect('example.db')
    cursor = conn.cursor()
    # DANGEROUS: User input is directly formatted into the query string
    query = f"SELECT * FROM users WHERE username = '{username}'"
    cursor.execute(query)
    data = cursor.fetchall()
    conn.close()
    return data

# --- VULNERABILITY 2: BROKEN ACCESS CONTROL ---
# A web route that fails to check a user's permissions, allowing anyone to access it.
app = flask.Flask(__name__)
@app.route('/admin_dashboard')
def vulnerable_access_control():
    # DANGEROUS: No authentication or authorization check is performed
    return "<h1>Welcome to the Admin Dashboard!</h1>"

# --- VULNERABILITY 3: HARDCODED SECRETS ---
# A secret key is stored directly in the source code.
API_KEY = "my_super_secret_api_key_12345"
def vulnerable_hardcoded_secrets():
    # DANGEROUS: The secret is visible to anyone with access to the code
    print(f"Using hardcoded API key: {API_KEY}")

# --- VULNERABILITY 4: VULNERABLE AND OUTDATED COMPONENTS ---
# This is a dependency issue, not a code issue. A requirements file would
# specify an outdated library with known vulnerabilities.
# Example: requests==2.22.0

# --- VULNERABILITY 5: CROSS-SITE SCRIPTING (XSS) ---
# A web page that renders unsanitized user input, allowing malicious
# JavaScript to be executed in a user's browser.
@app.route('/xss_page')
def vulnerable_xss():
    # DANGEROUS: Directly rendering user input without escaping
    user_input = request.args.get('name', 'Guest')
    return f"<h1>Hello, {user_input}!</h1>"

# --- VULNERABILITY 6: INSUFFICIENT LOGGING AND MONITORING ---
# A critical function that does not log important events.
def vulnerable_no_logging(amount, user_id):
    # DANGEROUS: No record of this critical transaction
    if amount > 1000:
        # What if this is a fraudulent transaction? There is no log to track it.
        pass
    return "Payment processed."

# --- VULNERABILITY 7: INSECURE DESERIALIZATION ---
# Deserializing data from an untrusted source, which can lead to
# remote code execution via a specially crafted payload.
def vulnerable_insecure_deserialization(encoded_data):
    # DANGEROUS: The pickle module can execute arbitrary code on deserialization
    data = base64.b64decode(encoded_data)
    return pickle.loads(data)

# --- VULNERABILITY 8: UNUSED CODE ---
# A function that is not called but contains a dangerous import.
def vulnerable_unused_code():
    # Unused import of subprocess which can be exploited if the function is called
    import subprocess
    pass

# --- VULNERABILITY 9: INVALID REDIRECTS AND FORWARDS ---
# A web endpoint that redirects based on unvalidated user input.
@app.route('/redirect')
def vulnerable_redirect():
    # DANGEROUS: Unvalidated user input is used for a redirect
    url = request.args.get('url')
    return redirect(url)

if __name__ == '__main__':
    # This is a dangerous script and should not be run for real.
    print("This script contains vulnerable code for educational purposes only.")
    print("Do NOT use this code in a real application.")