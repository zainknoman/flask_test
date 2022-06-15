from .db import db
from flask_bcrypt import generate_password_hash, check_password_hash

from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, BooleanField
from wtforms.validators import DataRequired, Length, Email, EqualTo


class Movie(db.Document):
    name = db.StringField(required=True, unique=True)
    casts = db.ListField(db.StringField(), required=True)
    genres = db.ListField(db.StringField(), required=True)
    added_by = db.ReferenceField('User')

class User(db.Document):
    email = db.EmailField(required=True, unique=True)
    password = db.StringField(required=True, min_length=6)
    movies = db.ListField(db.ReferenceField('Movie', reverse_delete_rule=db.PULL))

    def hash_password(self):
        self.password = generate_password_hash(self.password).decode('utf8')

    def check_password(self, password):
        return check_password_hash(self.password, password)
		
class RegistrationForm(FlaskForm):
	username = StringField('Username', 
		validators=[DataRequired(), Length(min=5,max=15)])
	email_address = StringField('Email Address', 
		validators=[DataRequired(), Email()])
	full_name = StringField('Full Name', 
		validators=[DataRequired(), Length(min=5,max=100)])
	country = StringField('Country', 
		validators=[Length(min=5,max=30)])
	mobile = StringField('Mobile', 
		validators=[Length(min=10,max=30)])
	id_passport = StringField('ID / Passport', 
		validators=[Length(min=10,max=30)])
	referral_code = StringField('Referral Code', 
		validators=[Length(min=5,max=15)])
	password = PasswordField('Password', 
		validators=[DataRequired(), Length(min=8,max=15)])
	confirm_pass = PasswordField('Confirm Password', 
		validators=[DataRequired(), Length(min=8,max=15),EqualTo('password')])
	terms = StringField('Terms & Conditions',
		validators=[DataRequired()])
	submit = SubmitField('Sign Up')

class LoginForm(FlaskForm):
	email_address = StringField('Email', 
		validators=[DataRequired(), Email()])
	password = PasswordField('Password', 
		validators=[DataRequired(), Length(min=8,max=15)])
	remember = BooleanField('Remember Me')
	submit = SubmitField('Login')

User.register_delete_rule(Movie, 'added_by', db.CASCADE)