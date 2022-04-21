from flask import Flask, render_template, request, redirect, session, flash, escape, url_for
from flask_session import Session
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail, Message
from dataclasses import dataclass
from typing import Any
from sqlalchemy import func
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import MySQLdb
import pymysql
import sqlalchemy
import forms
import os
import bcrypt

# Constants
STRING_PARKING = "parking"
CREDENTIALS_FILE = "credentials.txt"
NUM_CREDENTIALS = 4 # When adding credentials to file, make sure to update this number!

# Read credentials from local file, halt program on any error or if number of credentials is invalid
try:
    with open(CREDENTIALS_FILE) as f:
        credentials = {}
        for line in f.read().splitlines():
            kv = line.split("=")
            credentials[kv[0]] = kv[1]
        if len(credentials) != NUM_CREDENTIALS:
                raise Exception(f"Invalid number of credentials.") 
except Exception as error:
    raise error

# App and database parameters
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = f"mysql://root:{credentials['mysql']}@192.168.1.219/trouwsitedb"
app.config["SECRET_KEY"] = credentials['secret_key']
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['TEMPLATES_AUTO_RELOAD'] = True
app.config['SESSION_TYPE'] = 'filesystem'
app.jinja_env.trim_blocks = True
app.jinja_env.lstrip_blocks = True
db = SQLAlchemy(app)
Session(app)
limiter = Limiter(
    app,
    key_func=get_remote_address
)


@dataclass
class Statistics:
    """Data class for storing generated statistics from database queries. This is purely a compact way of passing multiple arguments to the template render engine."""
    number_day_guests: Any
    number_evening_guests: Any
    number_total_guests: Any
    amount_parking: Any
    diet_wishes: Any
    comments: Any
    day_guests: Any
    evening_guests: Any


# Database model
class Users(db.Model): 
    """SQLAlchemy class for corresponding database table"""
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.VARCHAR(40))
    email = db.Column(db.VARCHAR(40))
    password = db.Column(db.Integer)
    diet_wishes = db.Column(db.VARCHAR(200))
    is_admin = db.Column(db.Boolean)
    parking = db.Column(db.Boolean)
    is_dayguest = db.Column(db.Boolean)
    comments = db.Column(db.VARCHAR(250))


def hash_password(password):
    """Takes a string and returns it in hashed form."""
    return bcrypt.hashpw(password.encode("utf8"), bcrypt.gensalt())


def check_password(password, db_user):
    """Takes a (plaintext) string and a database `db_user` (object).
    Hashes the string `password`, and checks it with the `password` attribute of the `db_user`, which should also be a hashed string.  
    Returns `True` if succesful, returns `False` when unsuccesful."""
    return bcrypt.checkpw(password.encode("utf8"), db_user.password.encode("utf8"))


def change_password(db_user, form):
    """ Takes a database `db_user` and a `form` object. Checks if both password fields of the `form` match, then checks if the `password` attribute of the `form matches with the `db_user` password attribute. Changes password attribute of `user` to new value if criteria are met.
    Returns correct flash messages and categories, when succesful or unsuccesful.""" 
    if form.password.data == form.password_check.data:
        if len(form.password.data) >= 4:
            db_user.password = hash_password(form.password.data)
            msg = "Wachtwoord gewijzigd."
            cat = "ok"
        else:
            msg = "Wachtwoord moet minimaal uit 4 tekens bestaan!"
            cat = "error"
    else:
        msg = "De wachtwoorden komen niet overeen!"
        cat = "error"
    return msg, cat


# Default route
@app.route("/", methods=["GET", "POST"])
# @limiter.limit("30 per minute")
def index():
    if not session.get("user_id"):
        return redirect("/login")
    if not session.get("admin"):
        session["admin"] = False

    user = Users.query.filter_by(id=session.get("user_id")).one()

    return render_template('index.html', name=user.name, admin=session["admin"])


# Route for changing preferences
@app.route("/preferences", methods=["GET", "POST"])
@limiter.limit("30 per minute")
def preferences():
    if not session.get("user_id"):
        return redirect("/login")
    if not session.get("admin"):
        session["admin"] = False

    user = Users.query.filter_by(id=session.get("user_id")).one()
    preferencesform = forms.PreferencesForm(obj=user)

    if preferencesform.validate_on_submit():
        msg = "Detail(s) gewijzigd."
        cat = "ok"
        if preferencesform.password.data != "":
            msg, cat = change_password(user, preferencesform)

        user.diet_wishes = request.form["diet_wishes"]
        user.email = request.form["email"]
        user.comments = request.form["comments"]
        if STRING_PARKING in request.form:
            user.parking = True
        else:
            user.parking = False
        db.session.commit()
        flash(msg, cat)

    preferencesform.password.data = ""
    preferencesform.password_check.data = ""

    if preferencesform.errors.get("email"):
        flash(preferencesform.errors["email"][0], "error")

    return render_template('preferences.html', preferencesform=preferencesform, name=user.name, admin=session["admin"])


# Route for showing location info
@app.route("/location", methods=["GET", "POST"])
@limiter.limit("30 per minute")
def location():
    if not session.get("user_id"):
        return redirect("/login")
    if not session.get("admin"):
        session["admin"] = False

    user = Users.query.filter_by(id=session.get("user_id")).one()
    return render_template('location.html', dayguest=user.is_dayguest, name=user.name, admin=session["admin"])


# Route for showing planning info
@app.route("/planning", methods=["GET", "POST"])
@limiter.limit("30 per minute")
def planning():
    if not session.get("user_id"):
        return redirect("/login")
    if not session.get("admin"):
        session["admin"] = False

    user = Users.query.filter_by(id=session.get("user_id")).one()
    return render_template('planning.html', dayguest=user.is_dayguest, name=user.name, admin=session["admin"])


# Route for new users to register
@app.route("/register", methods=["GET", "POST"])
@limiter.limit("30 per minute")
def register():
    if session["is_dayguest"] != None:
        registerform = forms.RegisterForm()

        if registerform.validate_on_submit():
            if Users.query.filter_by(email=registerform.email.data).all():
                flash('Emailadres al in gebruik, probeer in te loggen of neem contact op met Kevin!', "error")
                return render_template('register.html', registerform=registerform)
            
            name = request.form["name"]
            email = request.form["email"]
            password = request.form["password"]

            # Check if password and password_check do *not* match
            if request.form["password"] != request.form["password_check"]:
                flash("De wachtwoorden komen niet overeen!", "error")
                registerform.name.data = name
                registerform.email.data = email
                registerform.password.data = ""
                registerform.password_check.data = ""
                return render_template('register.html', registerform=registerform)

            # Add user to database 
            new_user = Users()
            new_user.password = hash_password(password)
            new_user.name = name
            new_user.email = email
            new_user.is_dayguest = session["is_dayguest"]
            new_user.is_admin = False            
            db.session.add(new_user)
            db.session.commit()
            
            # Automatically log in using 'normal' procedure to check if insertion of user was succesful
            db_user = Users.query.filter(func.lower(Users.email) == func.lower(request.form["email"])).first()
            if not db_user:
                # User doesn't exist in database
                return "Database error (user doesn't exist)"
            else:
                form_pw = request.form["password"]
                if check_password(form_pw, db_user):
                    # Password correct
                    session["user_id"] = int(db_user.id)
                    return redirect("/")
                else:
                    # Password incorrect
                    return "Database error (password incorrect)"

        if registerform.errors.get("email"):
            flash(registerform.errors["email"][0], "error")
        return render_template('register.html', registerform=registerform)

    else:
        return redirect("/")


# Route for existing users to log in, or for new users to be redirected to the `register` route
@app.route("/login", methods=["GET", "POST"])
@limiter.limit("30 per minute")
def login():
    if session.get("user_id"):
        return redirect("/")
    session["admin"] = False
    session["is_dayguest"] = None

    loginform = forms.LoginForm()
    codeform = forms.CodeForm()

    if loginform.validate_on_submit():
        email = request.form["email"]
        password = request.form["password"]
        db_user = Users.query.filter(func.lower(Users.email) == func.lower(email)).first()
        
        # User doesn't exist in database
        if not db_user:
            flash("Emailadres is niet bekend!", "login")
            
        else:
            # Password correct
            if check_password(password, db_user):
                session["user_id"] = int(db_user.id)
                session["admin"] = db_user.is_admin
                return redirect("/")
            # Password incorrect
            else:
                flash("Ongeldig wachtwoord!", "login")
   
    if codeform.validate_on_submit():
        code = request.form["code"]
        if code == credentials["code_evening"]:
            session["is_dayguest"] = False
        elif code == credentials["code_day"]:
            session["is_dayguest"] = True
        else:
            session["is_dayguest"] = None
            flash("Code ongeldig. Ben je de code kwijt? Neem dan contact op met Kevin.", "code")
            return render_template('login.html', loginform=loginform, codeform=codeform)

        return redirect("/register")

    if loginform.errors.get("email"):
        flash(loginform.errors["email"][0], "login")

    return render_template('login.html', loginform=loginform, codeform=codeform)


# Route for admins
@app.route("/admin")
@limiter.limit("30 per minute")
def admin():
    if not session.get("user_id"):
        return redirect("/login")
    if not session.get("admin"):
        session["admin"] = False

    if session["admin"] == True:
        # Make a number of queries for the admin page and pass the results in a Statistics object to the template render engine
        stats = Statistics
        stats.number_total_guests = len(Users.query.filter(Users.is_admin == False).all())
        stats.amount_parking = len(Users.query.filter(Users.parking == True, Users.is_admin == False).all())
        stats.diet_wishes = Users.query.filter(Users.diet_wishes != "",  Users.is_admin == False).all()
        stats.comments = Users.query.filter(Users.comments != "",  Users.is_admin == False).all()
        stats.day_guests = Users.query.filter(Users.is_dayguest == True, Users.is_admin == False).all()
        stats.evening_guests = Users.query.filter(Users.is_dayguest == False, Users.is_admin == False).all()
        stats.number_day_guests = len(stats.day_guests)
        stats.number_evening_guests = len(stats.evening_guests)

        return render_template('admin.html', stats=stats)

    else:
        return redirect("/")


# Route for admins, to change user data
@app.route("/user/<id>", methods=["GET", "POST"])
@limiter.limit("30 per minute")
def user(id):
    if not session.get("user_id"):
        return redirect("/login")
    if not session.get("admin"):
        session["admin"] = False
    if session["admin"] == True:

        user = Users.query.filter(Users.id == id).first()
        preferencesform = forms.PreferencesForm(obj=user)

        if preferencesform.validate_on_submit():
            msg = "Detail(s) gewijzigd."
            cat = "ok"
            if preferencesform.password.data != "":
                msg, cat = change_password(user, preferencesform)
            user.diet_wishes = request.form["diet_wishes"]
            user.email = request.form["email"]
            user.comments = request.form["comments"]
            if STRING_PARKING in request.form:
                user.parking = True
            else:
                user.parking = False
            db.session.commit()
            flash(msg, cat)

        preferencesform.password.data = ""
        preferencesform.password_check.data = ""

        if preferencesform.errors.get("email"):
            flash(preferencesform.errors["email"][0], "error")
        return render_template('user.html', preferencesform=preferencesform,id=id)
    else:
        return redirect("/")


# Route for logouts
@app.route("/logout")
@limiter.limit("30 per minute")
def logout():
    session.clear()
    return redirect("/login")



if __name__ == "__main__":
    app.run(host="0.0.0.0",debug=True)
