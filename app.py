from flask import Flask, render_template, request,session,redirect
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

# Login route (connects HTML)
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        
        conn = sqlite3.connect("database.db")
        cursor = conn.cursor()

        cursor.execute(
            "SELECT * FROM users WHERE username=?",
            (username,)
        )
       # existing=cursor.fetchone()
        #if existing:
         #   return "Username already exists. Please choose a different one."

        user = cursor.fetchone()

        conn.close()

        if user and bcrypt.checkpw(
            password.encode("utf-8"), 
            user[2] if isinstance(user[2], bytes) else user[2].encode("utf-8")):
            
                session["user"] = user[1]  # Store usernamein session
                session["role"] = user[3]  # Store user role in session
                return redirect("/dashboard")
        else:
            return render_template("login.html", error="Invalid username or password ❌")

    return render_template("login.html")

# Register route (placeholder)
@app.route("/register", methods=["GET", "POST"])
def register():
     if request.method=="POST":
        username = request.form.get("username")
        password= request.form.get("password")
        hashed_password = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())
        conn= sqlite3.connect("database.db")
        cursor=conn.cursor()
        
        cursor.execute(
            "INSERT INTO users (username, password) VALUES (?, ?)", 
            (username, hashed_password)
        )
        
        conn.commit()
        conn.close()
        
        return render_template("register.html", success="Account created successfully ✅")
        
     return render_template("register.html")

    

# Dashboard route (placeholder)    
@app.route("/dashboard")
def dashboard():
    if "user" in session:
        if session.get("role") == "admin":
            return render_template("dashboard_admin.html", user=session["user"])
        else:
            return render_template("dashboard_user.html", user=session["user"])
    else:
        return redirect("/login")
    
#Logout route
@app.route("/logout")
def logout():
    session.pop("user", None)  # Remove user from session
    session.pop("role", None)  # Remove role from session
    return redirect("/login")

#Admin route (placeholder)
#admin pass: admin123

@app.route("/admin")
def admin():
    if "user" in session and session.get("role") == "admin":
        return render_template("admin.html")
    else:
        return "Access denied. Admins only."

# Run the server
if __name__ == "__main__":
    
    app.run(debug=True)

