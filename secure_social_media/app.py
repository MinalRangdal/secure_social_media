"""
CRYPTOGRAPHIC CONTENT VERIFICATION SYSTEM
WITH SCREENSHOT DETECTION
"""

from flask import Flask, render_template, request, redirect, flash, session, url_for
import sqlite3
import bcrypt
import random
import smtplib
from datetime import datetime, timedelta
from email.message import EmailMessage
import re
import hashlib
import os
from werkzeug.utils import secure_filename

# For perceptual hashing (screenshot detection)
try:
    from PIL import Image
    import imagehash
    PHASH_AVAILABLE = True
except ImportError:
    PHASH_AVAILABLE = False
    print("⚠️ WARNING: imagehash not installed. Screenshot detection disabled.")
    print("   Install with: pip install Pillow ImageHash")

app = Flask(__name__)
app.secret_key = "crypto_academic_key_2025"
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# ============================================================================
# DATABASE
# ============================================================================

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
            is_verified INTEGER DEFAULT 0
        )
    """)
    
    cur.execute("""
        CREATE TABLE IF NOT EXISTS posts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            username TEXT,
            image_path TEXT,
            image_hash TEXT,
            perceptual_hash TEXT,
            caption TEXT,
            timestamp TEXT,
            is_verified INTEGER DEFAULT 1,
            duplicate_of INTEGER,
            FOREIGN KEY(user_id) REFERENCES users(id),
            FOREIGN KEY(duplicate_of) REFERENCES posts(id)
        )
    """)
    
    cur.execute("""
        CREATE TABLE IF NOT EXISTS verification_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            post_id INTEGER,
            attempted_hash TEXT,
            stored_hash TEXT,
            result TEXT,
            timestamp TEXT,
            FOREIGN KEY(post_id) REFERENCES posts(id)
        )
    """)
    
    db.commit()
    db.close()

init_db()

# ============================================================================
# CRYPTOGRAPHIC FUNCTIONS
# ============================================================================

def compute_image_hash(file_path):
    """SHA-256 cryptographic hash"""
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

def compute_perceptual_hash(file_path):
    """Perceptual hash for visual similarity detection"""
    if not PHASH_AVAILABLE:
        return None
    try:
        img = Image.open(file_path)
        return str(imagehash.phash(img, hash_size=8))
    except Exception as e:
        print(f"⚠️ Perceptual hash error: {e}")
        return None

def check_visual_similarity(phash1_str, phash2_str, threshold=10):
    """Check if two images are visually similar"""
    if not PHASH_AVAILABLE or not phash1_str or not phash2_str:
        return False, 999
    try:
        hash1 = imagehash.hex_to_hash(phash1_str)
        hash2 = imagehash.hex_to_hash(phash2_str)
        distance = hash1 - hash2
        return distance < threshold, distance
    except:
        return False, 999

def verify_image_integrity(uploaded_file_path, stored_hash):
    """Verify image hasn't been tampered"""
    current_hash = compute_image_hash(uploaded_file_path)
    return {
        'is_valid': current_hash == stored_hash,
        'current_hash': current_hash,
        'stored_hash': stored_hash,
        'match': current_hash == stored_hash
    }

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

def valid_password(pw):
    return (
        len(pw) >= 8 and
        re.search(r"[A-Z]", pw) and
        re.search(r"[a-z]", pw) and
        re.search(r"\d", pw) and
        re.search(r"[!@#$%^&*]", pw)
    )

def send_otp(email, otp):
    print("\n" + "="*70)
    print(f"📧 EMAIL: {email}")
    print(f"🔑 OTP CODE: {otp}")
    print(f"⏰ EXPIRES IN: 5 minutes")
    print("="*70 + "\n")
    
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
        print(f"⚠️ Email failed: {e}\n")

# ============================================================================
# AUTHENTICATION ROUTES
# ============================================================================

@app.route("/")
def index():
    if "user" in session:
        return redirect("/home")
    return redirect("/login")

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
            session["pending_email"] = email
            return redirect("/verify-otp")

        except:
            flash("Email already registered")
            return redirect("/signup")

    return render_template("signup.html")

@app.route("/verify-otp", methods=["GET", "POST"])
def verify_otp():
    email = session.get("pending_email")
    
    if not email:
        flash("No pending verification. Please signup first.")
        return redirect("/signup")

    if request.method == "POST":
        entered = request.form["otp"]
        db = get_db()
        cur = db.cursor()
        cur.execute("SELECT otp, otp_expiry FROM users WHERE email=?", (email,))
        
        result = cur.fetchone()
        if not result:
            flash("User not found. Please signup again.")
            db.close()
            return redirect("/signup")
        
        otp, expiry = result

        if datetime.now() > datetime.fromisoformat(expiry):
            flash("OTP expired. Please sign up again.")
            cur.execute("DELETE FROM users WHERE email=? AND is_verified=0", (email,))
            db.commit()
            db.close()
            session.pop("pending_email", None)
            return redirect("/signup")

        if entered != otp:
            flash("Incorrect OTP")
            db.close()
            return redirect("/verify-otp")

        cur.execute("""
            UPDATE users SET is_verified=1, otp=NULL, otp_expiry=NULL
            WHERE email=?
        """, (email,))
        db.commit()
        db.close()

        session.pop("pending_email", None)
        flash("Registration successful. Please login.")
        return redirect("/login")

    return render_template("verify_otp.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form["email"]
        pw = request.form["password"]

        db = get_db()
        cur = db.cursor()
        cur.execute("""
            SELECT id, username, password, is_verified FROM users WHERE email=?
        """, (email,))
        user = cur.fetchone()

        if not user:
            flash("User not found")
            db.close()
            return redirect("/login")

        if not user[3]:
            flash("Email not verified")
            db.close()
            return redirect("/login")

        if not bcrypt.checkpw(pw.encode(), user[2]):
            flash("Invalid password")
            db.close()
            return redirect("/login")

        otp = str(random.randint(100000, 999999))
        expiry = (datetime.now() + timedelta(minutes=5)).isoformat()
        cur.execute("""
            UPDATE users SET otp=?, otp_expiry=? WHERE email=?
        """, (otp, expiry, email))
        db.commit()
        db.close()

        send_otp(email, otp)
        session["login_email"] = email
        session["temp_user_id"] = user[0]
        session["temp_username"] = user[1]
        return redirect("/login-otp")

    return render_template("login.html")

@app.route("/login-otp", methods=["GET", "POST"])
def login_otp():
    email = session.get("login_email")
    
    if not email:
        flash("Session expired. Please login again.")
        return redirect("/login")

    if request.method == "POST":
        entered = request.form["otp"]
        
        db = get_db()
        cur = db.cursor()
        cur.execute("""
            SELECT otp, otp_expiry FROM users WHERE email=?
        """, (email,))
        
        result = cur.fetchone()
        if not result:
            flash("User not found")
            db.close()
            return redirect("/login")
        
        otp, expiry = result

        if datetime.now() > datetime.fromisoformat(expiry):
            flash("OTP expired. Please login again.")
            db.close()
            session.pop("login_email", None)
            return redirect("/login")

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
        session["user_id"] = session.pop("temp_user_id")
        session["username"] = session.pop("temp_username")
        session.pop("login_email", None)
        
        flash("Login Successful")
        return redirect("/home")

    return render_template("login_otp.html")

# ============================================================================
# MAIN APP ROUTES
# ============================================================================

@app.route("/home")
def home():
    if "user" not in session:
        flash("Please login first")
        return redirect("/login")
    
    db = get_db()
    cur = db.cursor()
    cur.execute("""
        SELECT id, username, image_path, image_hash, caption, timestamp, is_verified, duplicate_of
        FROM posts
        ORDER BY timestamp DESC
    """)
    posts = cur.fetchall()
    
    # Get original usernames for duplicates
    formatted_posts = []
    for post in posts:
        original_user = None
        if post[7]:  # duplicate_of
            cur.execute("SELECT username FROM posts WHERE id=?", (post[7],))
            result = cur.fetchone()
            if result:
                original_user = result[0]
        
        formatted_posts.append({
            'id': post[0],
            'username': post[1],
            'image_path': post[2],
            'image_hash': post[3],
            'caption': post[4],
            'timestamp': post[5],
            'is_verified': post[6],
            'original_user': original_user
        })
    
    db.close()
    return render_template("home.html", posts=formatted_posts, current_user=session.get('username'))

@app.route("/upload", methods=["GET", "POST"])
def upload():
    if "user" not in session:
        flash("Please login first")
        return redirect("/login")
    
    if request.method == "POST":
        if 'image' not in request.files:
            flash("No image file uploaded")
            return redirect("/upload")
        
        file = request.files['image']
        caption = request.form.get('caption', '')
        
        if file.filename == '':
            flash("No image selected")
            return redirect("/upload")
        
        if file and file.filename:
            filename = secure_filename(file.filename)
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"{session['user_id']}_{timestamp}_{filename}"
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            
            file.save(filepath)
            
            # Compute hashes
            image_hash = compute_image_hash(filepath)
            perceptual_hash = compute_perceptual_hash(filepath)
            
            print("\n" + "="*70)
            print("🔒 HASH COMPUTATION")
            print(f"📁 File: {filename}")
            print(f"🔑 SHA-256: {image_hash}")
            print(f"🎨 Perceptual: {perceptual_hash}")
            print(f"👤 User: {session['username']}")
            print("="*70)
            
            db = get_db()
            cur = db.cursor()
            
            is_verified = 1
            duplicate_of = None
            warning_msg = None
            
            print(f"\n🔍 DUPLICATE DETECTION START")
            print(f"   Current user: {session['username']}")
            print(f"   PHASH_AVAILABLE: {PHASH_AVAILABLE}")
            print(f"   Perceptual hash: {perceptual_hash}")
            
            # Check exact duplicate
            print(f"\n1️⃣ Checking exact SHA-256 duplicates...")
            cur.execute("SELECT id, username FROM posts WHERE image_hash=?", (image_hash,))
            exact = cur.fetchone()
            print(f"   Exact match found: {exact is not None}")
            
            if exact:
                if exact[1] != session['username']:
                    is_verified = 0
                    duplicate_of = exact[0]
                    warning_msg = f"❌ EXACT DUPLICATE of post by {exact[1]}"
                    print(f"\n{warning_msg}\n")
                else:
                    flash("You already posted this!")
                    os.remove(filepath)
                    db.close()
                    return redirect("/home")
            
            # Check visual similarity (screenshot detection)
            print(f"\n2️⃣ Checking visual similarity (screenshots)...")
            print(f"   Conditions:")
            print(f"   - Not exact match: {not exact}")
            print(f"   - Has perceptual hash: {perceptual_hash is not None}")
            print(f"   - Library available: {PHASH_AVAILABLE}")
            
            if not exact and perceptual_hash and PHASH_AVAILABLE:
                print("\n🔍 CHECKING FOR VISUAL SIMILARITY...")
                cur.execute("SELECT id, username, perceptual_hash FROM posts")
                all_posts = cur.fetchall()
                
                print(f"   Found {len(all_posts)} existing posts to compare")
                
                for pid, puser, phash in all_posts:
                    print(f"   - Post {pid} by {puser}: phash={phash}")
                    
                    if phash and puser != session['username']:
                        is_similar, distance = check_visual_similarity(perceptual_hash, phash, threshold=35)
                        print(f"     → Comparing: distance={distance}, similar={is_similar}")
                        
                        if is_similar:
                            is_verified = 0
                            duplicate_of = pid
                            warning_msg = f"❌ SCREENSHOT DETECTED! Similar to post by {puser} (distance: {distance})"
                            print(f"\n{warning_msg}\n")
                            break
                    else:
                        if not phash:
                            print(f"     → Skipped (no phash stored)")
                        if puser == session['username']:
                            print(f"     → Skipped (same user)")
                
                if is_verified == 1:
                    print("   ✅ No visual duplicates found")
            else:
                if exact:
                    print("   ⏭️  Skipped similarity check (exact match found)")
                elif not perceptual_hash:
                    print("   ⚠️  Skipped similarity check (phash computation failed)")
                elif not PHASH_AVAILABLE:
                    print("   ⚠️  Skipped similarity check (imagehash not installed)")
            
            print("="*70 + "\n")
            
            # Insert post
            try:
                cur.execute("""
                    INSERT INTO posts (user_id, username, image_path, image_hash, perceptual_hash, 
                                     caption, timestamp, is_verified, duplicate_of)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    session['user_id'],
                    session['username'],
                    filename,
                    image_hash,
                    perceptual_hash,
                    caption,
                    datetime.now().isoformat(),
                    is_verified,
                    duplicate_of
                ))
                db.commit()
                
                if is_verified:
                    flash("✅ Post uploaded successfully!")
                else:
                    flash(warning_msg if warning_msg else "⚠️ Post marked as UNVERIFIED")
                
            except Exception as e:
                print(f"Database error: {e}")
                flash("Error uploading post")
                os.remove(filepath)
            
            db.close()
            return redirect("/home")
    
    return render_template("upload.html")

@app.route("/verify/<int:post_id>")
def verify_post(post_id):
    if "user" not in session:
        flash("Please login first")
        return redirect("/login")
    
    db = get_db()
    cur = db.cursor()
    cur.execute("""
        SELECT image_path, image_hash, username, caption, timestamp
        FROM posts WHERE id=?
    """, (post_id,))
    post = cur.fetchone()
    
    if not post:
        flash("Post not found")
        return redirect("/home")
    
    image_path, stored_hash, username, caption, timestamp = post
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], image_path)
    
    verification = verify_image_integrity(filepath, stored_hash)
    
    cur.execute("""
        INSERT INTO verification_log (post_id, attempted_hash, stored_hash, result, timestamp)
        VALUES (?, ?, ?, ?, ?)
    """, (
        post_id,
        verification['current_hash'],
        stored_hash,
        "VERIFIED" if verification['is_valid'] else "TAMPERED",
        datetime.now().isoformat()
    ))
    
    cur.execute("""
        UPDATE posts SET is_verified=? WHERE id=?
    """, (1 if verification['is_valid'] else 0, post_id))
    
    db.commit()
    db.close()
    
    return render_template("verify_result.html", 
                         verification=verification, 
                         post={'id': post_id, 'username': username, 
                               'caption': caption, 'timestamp': timestamp})

@app.route("/crypto-demo")
def crypto_demo():
    if "user" not in session:
        flash("Please login first")
        return redirect("/login")
    return render_template("crypto_demo.html")

@app.route("/logout")
def logout():
    session.clear()
    flash("Logged out successfully")
    return redirect("/login")

if __name__ == "__main__":
    print("\n" + "="*70)
    print("🚀 CRYPTOGRAM - Cryptographic Content Verification System")
    if PHASH_AVAILABLE:
        print("✅ Screenshot detection: ENABLED")
    else:
        print("⚠️  Screenshot detection: DISABLED")
        print("    Install with: pip install Pillow ImageHash")
    print("="*70 + "\n")
    app.run(debug=True, port=5000)
