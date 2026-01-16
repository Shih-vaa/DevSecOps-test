password = "hardcoded123"
api_key = "sk_live_abcdef123456"

def query(user_input):
    return f"SELECT * FROM users WHERE name = '{user_input}'"

# This should trigger SQL injection detection
