from flask import Flask, render_template, request, redirect, flash, session
import sqlite3, bcrypt, random, smtplib
from datetime import datetime, timedelta
from email.message import EmailMessage
import re

app = Flask(__name__)
app.secret_key = "crypto_academic_key"

# ---------------- DATABASE ----------------
def get_db():
    return sqlite3.connect("database.db")

def init_db():
    db = get_db()
    cur = db.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            email TEXT UNIQUE,
            password BLOB,
            otp TEXT,
            otp_expiry TEXT,
            is_verified INTEGER
        )
    """)
    db.commit()
    db.close()

init_db()

# ---------------- PASSWORD POLICY ----------------
def valid_password(pw):
    return (
        len(pw) >= 8 and
        re.search(r"[A-Z]", pw) and
        re.search(r"[a-z]", pw) and
        re.search(r"\d", pw) and
        re.search(r"[!@#$%^&*]", pw)
    )

# ---------------- OTP EMAIL ----------------
def send_otp(email, otp):
    # ============================================================
    # 🔴 DEBUG MODE: PRINT OTP TO TERMINAL
    # ⚠️ REMOVE THIS BLOCK BEFORE PRODUCTION DEPLOYMENT
    # ============================================================
    print("\n" + "="*70)
    print(f"📧 EMAIL: {email}")
    print(f"🔑 OTP CODE: {otp}")
    print(f"⏰ EXPIRES IN: 5 minutes")
    print("="*70 + "\n")
    # ============================================================
    
    try:
        msg = EmailMessage()
        msg.set_content(f"Your OTP is {otp}. Valid for 5 minutes.")
        msg["Subject"] = "OTP Verification"
        msg["From"] = "yourgmail@gmail.com"
        msg["To"] = email

        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
            server.login("yourgmail@gmail.com", "APP_PASSWORD")
            server.send_message(msg)
    except Exception as e:
        print(f"⚠️ Email sending failed: {e}")
        print("(But OTP is printed above for testing)\n")

# ---------------- SIGNUP ----------------
@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        username = request.form["username"]
        email = request.form["email"]
        pw = request.form["password"]
        confirm = request.form["confirm"]

        if pw != confirm:
            flash("Passwords do not match")
            return redirect("/signup")

        if not valid_password(pw):
            flash("Password does not meet security requirements")
            return redirect("/signup")

        hashed = bcrypt.hashpw(pw.encode(), bcrypt.gensalt())
        otp = str(random.randint(100000, 999999))
        expiry = (datetime.now() + timedelta(minutes=5)).isoformat()

        try:
            db = get_db()
            cur = db.cursor()
            cur.execute("""
                INSERT INTO users VALUES (NULL,?,?,?,?,?,0)
            """, (username, email, hashed, otp, expiry))
            db.commit()
            db.close()

            send_otp(email, otp)
            
            # ✅ FIX: Store email in session
            session["pending_email"] = email
            
            # ✅ ISSUE 1 FIX: Always redirect to OTP verification page
            return redirect("/verify-otp")

        except:
            flash("Email already registered")
            return redirect("/signup")

    return render_template("signup.html")

# ---------------- OTP VERIFY (SIGNUP) ----------------
@app.route("/verify-otp", methods=["GET", "POST"])
def verify_otp():
    # ✅ CRITICAL BUG FIX: Use correct session key
    email = session.get("pending_email")  # Changed from "verify_email"
    
    if not email:
        flash("No pending verification. Please signup first.")
        return redirect("/signup")

    if request.method == "POST":
        entered = request.form["otp"]
        db = get_db()
        cur = db.cursor()
        cur.execute("SELECT otp, otp_expiry FROM users WHERE email=?", (email,))
        
        # ✅ BUG FIX: Check if user exists before unpacking
        result = cur.fetchone()
        if not result:
            flash("User not found. Please signup again.")
            db.close()
            return redirect("/signup")
        
        otp, expiry = result

        # ✅ ISSUE 5 FIX: Handle expired OTP
        if datetime.now() > datetime.fromisoformat(expiry):
            flash("OTP expired. Please sign up again.")
            cur.execute("DELETE FROM users WHERE email=? AND is_verified=0", (email,))
            db.commit()
            db.close()
            session.pop("pending_email", None)
            return redirect("/signup")

        # ✅ ISSUE 5 FIX: Handle incorrect OTP
        if entered != otp:
            flash("Incorrect OTP")
            db.close()
            return redirect("/verify-otp")

        # OTP is correct - verify the user
        cur.execute("""
            UPDATE users SET is_verified=1, otp=NULL, otp_expiry=NULL
            WHERE email=?
        """, (email,))
        db.commit()
        db.close()

        # Clear session
        session.pop("pending_email", None)
        
        # ✅ ISSUE 2 FIX: Redirect to login with success message
        flash("Registration successful. Please login.")
        return redirect("/")

    return render_template("verify_otp.html")

# ---------------- LOGIN ----------------
@app.route("/", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form["email"]
        pw = request.form["password"]

        db = get_db()
        cur = db.cursor()
        cur.execute("""
            SELECT password, is_verified FROM users WHERE email=?
        """, (email,))
        user = cur.fetchone()

        if not user:
            flash("User not found")
            db.close()
            return redirect("/")

        if not user[1]:
            flash("Email not verified. Please check your email for OTP.")
            db.close()
            return redirect("/")

        if not bcrypt.checkpw(pw.encode(), user[0]):
            flash("Invalid password")
            db.close()
            return redirect("/")

        otp = str(random.randint(100000, 999999))
        expiry = (datetime.now() + timedelta(minutes=5)).isoformat()
        cur.execute("""
            UPDATE users SET otp=?, otp_expiry=? WHERE email=?
        """, (otp, expiry, email))
        db.commit()
        db.close()

        send_otp(email, otp)
        session["login_email"] = email
        return redirect("/login-otp")

    return render_template("login.html")

# ---------------- LOGIN OTP ----------------
@app.route("/login-otp", methods=["GET", "POST"])
def login_otp():
    email = session.get("login_email")
    
    if not email:
        flash("Session expired. Please login again.")
        return redirect("/")

    if request.method == "POST":
        entered = request.form["otp"]
        db = get_db()
        cur = db.cursor()
        cur.execute("""
            SELECT otp, otp_expiry FROM users WHERE email=?
        """, (email,))
        
        # ✅ BUG FIX: Check if result exists
        result = cur.fetchone()
        if not result:
            flash("User not found")
            db.close()
            return redirect("/")
        
        otp, expiry = result

        if datetime.now() > datetime.fromisoformat(expiry):
            flash("OTP expired. Please login again.")
            db.close()
            return redirect("/")

        if entered != otp:
            flash("Incorrect OTP")
            db.close()
            return redirect("/login-otp")

        cur.execute("""
            UPDATE users SET otp=NULL, otp_expiry=NULL WHERE email=?
        """, (email,))
        db.commit()
        db.close()

        session["user"] = email
        session.pop("login_email", None)
        
        # ✅ ISSUE 3 FIX: Display "Login Successful" message
        flash("Login Successful")
        return redirect("/home")

    return render_template("login_otp.html")

# ---------------- HOME ----------------
@app.route("/home")
def home():
    if "user" not in session:
        return redirect("/")
    return render_template("home.html")

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")

if __name__ == "__main__":
    app.run(debug=True)