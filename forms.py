from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Length, Regexp
from wtforms.validators import DataRequired, Length, Regexp
from wtforms.validators import DataRequired, Length, Regexp, Email


class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[
        DataRequired(),
        Length(min=4, max=20),
        Regexp('^[a-zA-Z0-9_]{4,20}$', message="Username can only include letters, numbers, underscores")
    ])
    password = PasswordField('Password', validators=[
        DataRequired(),
        Length(min=8),
        Regexp('^(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[@$!%*?&]).+$',
               message="Password must include uppercase, lowercase, number, and special character")
    ])
    submit = SubmitField('Register')


class LoginForm(FlaskForm):
    username = StringField('Username', validators=[
        DataRequired(),
        Length(min=4, max=20)
    ])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')


class ForgotPasswordForm(FlaskForm):
    username = StringField(
        'Username',
        validators=[
            DataRequired(),
            Length(min=4, max=20)
        ]
    )
    submit = SubmitField('Request Reset PIN')