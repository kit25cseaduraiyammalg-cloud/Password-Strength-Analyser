from flask import Flask, render_template, request
import sqlite3
import hashlib
import re
import secrets
import string

app = Flask(__name__)

# ---------------- DATABASE ---------------- #

def init_db():
    conn = sqlite3.connect("passwords.db")
    cursor = conn.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS password_history(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        password_hash TEXT UNIQUE
    )
    """)

    conn.commit()
    conn.close()

# ---------------- HASHING ---------------- #

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# ---------------- PASSWORD HISTORY ---------------- #

def is_reused(password):
    password_hash = hash_password(password)

    conn = sqlite3.connect("passwords.db")
    cursor = conn.cursor()

    cursor.execute(
        "SELECT * FROM password_history WHERE password_hash=?",
        (password_hash,)
    )

    result = cursor.fetchone()
    conn.close()

    return result is not None

def save_password(password):
    password_hash = hash_password(password)

    conn = sqlite3.connect("passwords.db")
    cursor = conn.cursor()

    try:
        cursor.execute(
            "INSERT INTO password_history(password_hash) VALUES(?)",
            (password_hash,)
        )
        conn.commit()
    except:
        pass

    conn.close()

# ---------------- PASSWORD GENERATOR ---------------- #

def generate_password(length=16):
    chars = (
        string.ascii_uppercase +
        string.ascii_lowercase +
        string.digits +
        "!@#$%^&*()"
    )

    return ''.join(
        secrets.choice(chars)
        for _ in range(length)
    )

# ---------------- ANALYZER ---------------- #

def analyze_password(password):

    score = 0
    suggestions = []

    common_passwords = [
        "password",
        "password123",
        "admin",
        "123456",
        "qwerty"
    ]

    if len(password) >= 12:
        score += 20
    else:
        suggestions.append("Use at least 12 characters")

    if re.search(r"[A-Z]", password):
        score += 15
    else:
        suggestions.append("Add uppercase letters")

    if re.search(r"[a-z]", password):
        score += 15
    else:
        suggestions.append("Add lowercase letters")

    if re.search(r"\d", password):
        score += 15
    else:
        suggestions.append("Add numbers")

    if re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        score += 15
    else:
        suggestions.append("Add special characters")

    if password.lower() not in common_passwords:
        score += 10
    else:
        suggestions.append("Avoid common passwords")

    if not re.search(r"(.)\1{2,}", password):
        score += 5
    else:
        suggestions.append("Avoid repeated characters")

    if not re.search(r"123|abc|qwerty", password.lower()):
        score += 5
    else:
        suggestions.append("Avoid predictable sequences")

    reused = is_reused(password)

    if reused:
        suggestions.append("Password was previously used")

    if score >= 80:
        strength = "Strong"
        color = "green"

    elif score >= 50:
        strength = "Medium"
        color = "orange"

    else:
        strength = "Weak"
        color = "red"

    return strength, score, suggestions, reused, color

# ---------------- ROUTE ---------------- #

@app.route("/", methods=["GET", "POST"])
def home():

    result = None
    generated_password = ""

    if request.method == "POST":

        if "generate" in request.form:
            generated_password = generate_password()

        elif "analyze" in request.form:

            password = request.form["password"]

            strength, score, suggestions, reused, color = analyze_password(password)

            if not reused:
                save_password(password)

            result = {
                "strength": strength,
                "score": score,
                "suggestions": suggestions,
                "reused": reused,
                "color": color
            }

    return render_template(
        "index.html",
        result=result,
        generated_password=generated_password
    )

if __name__ == "__main__":
    init_db()
    app.run(debug=True)
