from flask import (
    Flask,
    render_template,
    request,
    redirect,
    session,
    flash
)

import sqlite3

from werkzeug.security import (
    generate_password_hash,
    check_password_hash
)

app = Flask(__name__)

app.secret_key = "super_secret_key_change_this"

DATABASE = "database.db"


# -----------------------------
# Database Connection
# -----------------------------
def get_db_connection():

    connection = sqlite3.connect(DATABASE)

    connection.row_factory = sqlite3.Row

    return connection

# -----------------------------
# Register
# -----------------------------
@app.route("/register", methods=["GET", "POST"])
def register():

    if request.method == "POST":

        username = request.form["username"]
        email = request.form["email"]
        password = request.form["password"]

        hashed_password = generate_password_hash(password)

        connection = get_db_connection()

        existing_user = connection.execute(
            """
            SELECT * FROM users
            WHERE email = ?
            """,
            (email,)
        ).fetchone()

        if existing_user:

            flash("Email already exists!")

            connection.close()

            return redirect("/register")

        connection.execute(
            """
            INSERT INTO users
            (username, email, password)
            VALUES (?, ?, ?)
            """,
            (username, email, hashed_password)
        )

        connection.commit()

        connection.close()

        flash("Registration Successful! Please Login.")

        return redirect("/login")

    return render_template("register.html")

# -----------------------------
# Login
# -----------------------------
@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        email = request.form["email"]
        password = request.form["password"]

        connection = get_db_connection()

        user = connection.execute(
            """
            SELECT * FROM users
            WHERE email = ?
            """,
            (email,)
        ).fetchone()

        connection.close()

        if user and check_password_hash(user["password"], password):

            session["user_id"] = user["id"]
            session["username"] = user["username"]

            flash("Login Successful!")

            return redirect("/dashboard")

        flash("Invalid Email or Password!")

        return redirect("/login")

    return render_template("login.html")

# -----------------------------
# Home
# -----------------------------
@app.route("/")
def home():

    return render_template("index.html")


# -----------------------------
# Dashboard
# -----------------------------
@app.route("/dashboard")
def dashboard():

    if "user_id" not in session:

        flash("Please login first!")

        return redirect("/login")

    return render_template(
        "dashboard.html",
        username=session["username"]
    )


# -----------------------------
# Logout
# -----------------------------
@app.route("/logout")
def logout():

    session.clear()

    flash("Logged out successfully!")

    return redirect("/login")


# -----------------------------
# Run Flask App
# -----------------------------
if __name__ == "__main__":

    app.run(debug=True)
    