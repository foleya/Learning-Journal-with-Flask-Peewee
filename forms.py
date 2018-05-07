from flask_wtf import Form
from wtforms import StringField, PasswordField, TextAreaField, DateField
from wtforms.validators import (DataRequired, ValidationError, Email,
                                Length, EqualTo)

from models import User


def email_exists(form, field):
    if User.select().where(User.email == field.data).exists():
        raise ValidationError('User with that email already exists.')


class RegisterForm(Form):
    email = StringField(
        'E-mail',
        validators =[
            DataRequired(),
            Email(),
            email_exists
        ]
    )
    password = PasswordField(
        'Password',
        validators=[
            DataRequired(),
            Length(min=8),
            EqualTo('password2', message='Passwords must match!')
        ]
    )
    password2 = PasswordField(
        'Confirm Password',
        validators=[DataRequired()]
    )


class LoginForm(Form):
    email = StringField('E-mail', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])

class EntryForm(Form):
    title = TextAreaField("Title", validators=[DataRequired()])
    date = DateField("Date", validators=[DataRequired()])
    time_spent = TextAreaField("Time Spent")
    what_i_learned = TextAreaField("What I Learned")
    resources_to_remember = TextAreaField("Resources to Remember")
    tags = TextAreaField("Tags")
