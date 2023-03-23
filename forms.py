import email_validator
import wtforms
from flask_wtf import FlaskForm
from wtforms.validators import InputRequired, Length, Email, StopValidation
from wtforms.widgets import PasswordInput
from werkzeug.utils import secure_filename

class LoginForm(FlaskForm):
    email = wtforms.StringField("Emailadres*", validators=[InputRequired(), Email(message="Geen geldig email-adres!"), Length(max=40)])
    password = wtforms.PasswordField("Wachtwoord*", widget=PasswordInput(hide_value=False), validators=[InputRequired(), Length(min=4)])
    submit = wtforms.SubmitField("Inloggen")

class CodeForm(FlaskForm):
    code = wtforms.StringField("Code*", validators=[InputRequired()])
    submit = wtforms.SubmitField("OK")

class RegisterForm(FlaskForm):
    name = wtforms.StringField("Naam*", validators=[InputRequired(), Length(max=40)])
    email = wtforms.StringField("Emailadres*", validators=[InputRequired(), Email(message="Geen geldig email-adres!"), Length(max=40)])
    password = wtforms.PasswordField("Wachtwoord*", widget=PasswordInput(hide_value=False), validators=[InputRequired(), Length(min=4)])
    password_check = wtforms.PasswordField("Wachtwoord (controle)*", widget=PasswordInput(hide_value=False), validators=[InputRequired(), Length(min=4)])
    submit = wtforms.SubmitField("Registreer")

class PreferencesForm(FlaskForm):
    name = wtforms.StringField("Naam*", validators=[InputRequired(), Length(max=40)])
    email = wtforms.StringField("Emailadres*", validators=[InputRequired(), Email(message="Geen geldig email-adres!"), Length(max=40)])
    password = wtforms.PasswordField("Wachtwoord*", widget=PasswordInput(hide_value=False))
    password_check = wtforms.PasswordField("Wachtwoord (controle)*", widget=PasswordInput(hide_value=False))
    parking = wtforms.BooleanField("We komen met de auto naar (...)")
    diet_wishes = wtforms.TextAreaField("Dieetwensen", validators=[Length(max=250)])
    comments = wtforms.TextAreaField("Opmerkingen", validators=[Length(max=250)])
    submit = wtforms.SubmitField("Bijwerken")

