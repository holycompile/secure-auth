from flask import Flask, render_template, request, session, redirect, flash
import sqlite3
import bcrypt

def init_db():
    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT,
        password TEXT,
        role TEXT DEFAULT 'user'
    )
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS login_attempts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        status TEXT
    )
    """)
    
    cursor.execute("SELECT * FROM users WHERE username=?", ("admin",))
    admin = cursor.fetchone()

    if not admin:
        hashed_password = bcrypt.hashpw("admin123".encode("utf-8"), bcrypt.gensalt())
        cursor.execute(
            "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
            ("admin", hashed_password, "admin")
        )

    conn.commit()
    conn.close()

# Create Flask app
app = Flask(__name__)
app.secret_key = "supersecretkey"  # Needed for session management

init_db()


# Home route
@app.route("/")
def home():
    return render_template("index.html")

# Login route
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        
        conn = sqlite3.connect("database.db")
        cursor = conn.cursor()

        # Check rate limit: 5 failed attempts in the last 5 minutes
        cursor.execute(
            "SELECT COUNT(*) FROM login_attempts WHERE username=? AND status='failed' AND timestamp > datetime('now', '-5 minutes')",
            (username,)
        )
        failed_count = cursor.fetchone()[0]
        if failed_count >= 5:
            conn.close()
            return render_template("login.html", error="Too many failed attempts. Account temporarily locked (5 mins). 🔒")

        cursor.execute(
            "SELECT * FROM users WHERE username=?",
            (username,)
        )
        user = cursor.fetchone()

        if user and bcrypt.checkpw(
            password.encode("utf-8"), 
            user[2] if isinstance(user[2], bytes) else user[2].encode("utf-8")):
            
                # Log successful login
                cursor.execute("INSERT INTO login_attempts (username, status) VALUES (?, 'success')", (username,))
                conn.commit()
                conn.close()

                session["user"] = user[1]  # Store username in session
                session["role"] = user[3]  # Store user role in session
                return redirect("/dashboard")
        else:
            # Log failed login
            cursor.execute("INSERT INTO login_attempts (username, status) VALUES (?, 'failed')", (username,))
            conn.commit()
            conn.close()
            return render_template("login.html", error="Invalid username or password ❌")

    return render_template("login.html")

# Register route
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        
        conn = sqlite3.connect("database.db")
        cursor = conn.cursor()

        # Check if user already exists
        cursor.execute("SELECT * FROM users WHERE username=?", (username,))
        if cursor.fetchone():
            conn.close()
            return render_template("register.html", error="Username already exists. Please choose a different one. ❌")

        hashed_password = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())
        cursor.execute(
            "INSERT INTO users (username, password, role) VALUES (?, ?, 'user')", 
            (username, hashed_password)
        )
        conn.commit()
        conn.close()
        
        return render_template("register.html", success="Account created successfully ✅")
        
    return render_template("register.html")

# Dashboard route
@app.route("/dashboard")
def dashboard():
    if "user" in session:
        conn = sqlite3.connect("database.db")
        cursor = conn.cursor()
        if session.get("role") == "admin":
            cursor.execute("SELECT id, username, role FROM users")
            users_list = cursor.fetchall()
            cursor.execute("SELECT COUNT(*) FROM users")
            total_users = cursor.fetchone()[0]
            cursor.execute("SELECT COUNT(*) FROM login_attempts WHERE status='failed'")
            failed_logins = cursor.fetchone()[0]
            conn.close()
            return render_template("dashboard_admin.html", user=session["user"], users=users_list, total_users=total_users, failed_logins=failed_logins)
        else:
            conn.close()
            return render_template("dashboard_user.html", user=session["user"])
    else:
        return redirect("/login")

# Change Password route
@app.route("/change_password", methods=["POST"])
def change_password():
    if "user" not in session:
        return redirect("/login")
    
    current_password = request.form.get("current_password")
    new_password = request.form.get("new_password")
    confirm_password = request.form.get("confirm_password")
    
    if new_password != confirm_password:
        flash("New passwords do not match! ❌", "error")
        return redirect("/dashboard")
        
    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE username=?", (session["user"],))
    user = cursor.fetchone()
    
    if user and bcrypt.checkpw(
        current_password.encode("utf-8"), 
        user[2] if isinstance(user[2], bytes) else user[2].encode("utf-8")):
        
        hashed_password = bcrypt.hashpw(new_password.encode("utf-8"), bcrypt.gensalt())
        cursor.execute("UPDATE users SET password=? WHERE id=?", (hashed_password, user[0]))
        conn.commit()
        flash("Password updated successfully! ✅", "success")
    else:
        flash("Invalid current password! ❌", "error")
        
    conn.close()
    return redirect("/dashboard")

# Toggle User Role route
@app.route("/admin/toggle_role/<int:user_id>", methods=["POST"])
def toggle_role(user_id):
    if "user" not in session or session.get("role") != "admin":
        return "Access denied. Admins only.", 403
    
    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()
    cursor.execute("SELECT username, role FROM users WHERE id=?", (user_id,))
    user = cursor.fetchone()
    
    if not user:
        conn.close()
        return "User not found", 404
    
    username, role = user
    if username == "admin":
        conn.close()
        return "Cannot change role of primary admin", 400
    
    new_role = "admin" if role == "user" else "user"
    cursor.execute("UPDATE users SET role=? WHERE id=?", (new_role, user_id))
    conn.commit()
    conn.close()
    return redirect("/dashboard")

# Delete User route
@app.route("/admin/delete_user/<int:user_id>", methods=["POST"])
def delete_user(user_id):
    if "user" not in session or session.get("role") != "admin":
        return "Access denied. Admins only.", 403
    
    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()
    cursor.execute("SELECT username FROM users WHERE id=?", (user_id,))
    user = cursor.fetchone()
    
    if not user:
        conn.close()
        return "User not found", 404
    
    username = user[0]
    if username == "admin" or username == session["user"]:
        conn.close()
        return "Cannot delete primary admin or current session user", 400
    
    cursor.execute("DELETE FROM users WHERE id=?", (user_id,))
    conn.commit()
    conn.close()
    return redirect("/dashboard")

# Logout route
@app.route("/logout")
def logout():
    session.pop("user", None)
    session.pop("role", None)
    return redirect("/login")

# Admin Audit Log route
@app.route("/admin/logs")
@app.route("/admin")
def admin():
    if "user" in session and session.get("role") == "admin":
        conn = sqlite3.connect("database.db")
        cursor = conn.cursor()
        cursor.execute("SELECT id, username, timestamp, status FROM login_attempts ORDER BY timestamp DESC LIMIT 50")
        logs = cursor.fetchall()
        conn.close()
        return render_template("admin.html", logs=logs)
    else:
        return "Access denied. Admins only.", 403

# Run the server
if __name__ == "__main__":
    app.run(debug=True)


