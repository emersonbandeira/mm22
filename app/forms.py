from wtforms import  Form, BooleanField, StringField, PasswordField, SubmitField, IntegerField, validators, FileField 
from wtforms.validators import DataRequired


class LoginForm(Form):
    username  = StringField('UserName', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])

class RegistrationForm(Form):
    username = StringField('Username', [validators.Length(min=4, max=25)])
    email = StringField('Email Address', [validators.Length(min=6, max=35)])
    password = PasswordField('New Password', [
        validators.DataRequired(),
        validators.EqualTo('confirm', message='Passwords must match')
    ])
    confirm = PasswordField('Repeat Password')
    accept_tos = BooleanField('I accept the TOS', [validators.DataRequired()])
    profile_id = IntegerField('Profile')

class ProfileForm(Form):
    name = StringField('Nome', [validators.Length(min=4, max=25)])
    description = StringField('Descrição', [validators.Length(min=4, max=31)])

class UserUpdateForm(Form):
    file = FileField('file')