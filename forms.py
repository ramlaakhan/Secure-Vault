from flask_wtf import FlaskForm
from wtforms import (
    StringField, PasswordField, TextAreaField,
    FileField, SelectField, SubmitField
)
from wtforms.validators import (
    DataRequired, Email, Length, ValidationError,
    Regexp, EqualTo
)
import re
from country_list import countries_for_language


def validate_password_strength(form, field):
    """Custom password validator to ensure strong passwords."""
    password = field.data
    if not password:
        return  # Let DataRequired handle empty passwords

    if len(password) < 8:
        raise ValidationError('Password must be at least 8 characters long')
    if not re.search(r'[A-Z]', password):
        raise ValidationError('Password must contain at least one uppercase letter')
    if not re.search(r'[a-z]', password):
        raise ValidationError('Password must contain at least one lowercase letter')
    if not re.search(r'[0-9]', password):
        raise ValidationError('Password must contain at least one number')
    if not re.search(r'[^A-Za-z0-9]', password):
        raise ValidationError('Password must contain at least one special character')


def validate_phone_number(form, field):
    """Validates that the phone number starts with '03' and has 11 digits."""
    phone = field.data.strip()

    if not phone:
        raise ValidationError('Phone number is required')

    if not re.match(r'^03\d{9}$', phone):
        raise ValidationError('Phone number must start with 03 followed by 9 digits (e.g. 03001234567)')


class RegistrationForm(FlaskForm):
    first_name = StringField('First Name', validators=[
        DataRequired(),
        Length(min=2, max=50),
        Regexp(r'^[a-zA-Z\s\'\-]+$',
               message="First name can only contain letters, spaces, hyphens and apostrophes")
    ])

    last_name = StringField('Last Name', validators=[
        DataRequired(),
        Length(min=2, max=50),
        Regexp(r'^[a-zA-Z\s\'\-]+$',
               message="Last name can only contain letters, spaces, hyphens and apostrophes")
    ])

    email = StringField('Email', validators=[
        DataRequired(),
        Email(),
        Length(max=100),
        Regexp(r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$',
               message="Invalid email format")
    ])

    phone_number = StringField('Phone Number', validators=[
        DataRequired(),
        validate_phone_number
    ], render_kw={
        'placeholder': 'e.g. 03001234567',
        'pattern': r'^03\d{9}$',
        'title': 'Phone number must start with 03 followed by 9 digits (e.g. 03001234567)'
    })

    username = StringField('Username', validators=[
        DataRequired(),
        Length(min=4, max=25),
        Regexp('^[a-zA-Z0-9_]+$',
               message="Username can only contain letters, numbers and underscores")
    ])

    password = PasswordField('Password', validators=[
        DataRequired(),
        Length(min=8),
        validate_password_strength,
        EqualTo('confirm_password', message='Passwords must match')
    ])

    confirm_password = PasswordField('Confirm Password', validators=[
        DataRequired()
    ])


class LoginForm(FlaskForm):
    username = StringField('Username', validators=[
        DataRequired(),
        Regexp('^[a-zA-Z0-9_]+$',
               message="Invalid username format")
    ])
    password = PasswordField('Password', validators=[
        DataRequired()
    ])


class ContactForm(FlaskForm):
    name = StringField('Name', validators=[
        DataRequired(),
        Length(max=100),
        Regexp(r'^[a-zA-Z\s\'\-]+$',
               message="Name can only contain letters, spaces, hyphens and apostrophes")
    ])
    email = StringField('Email', validators=[
        DataRequired(),
        Email(),
        Length(max=100),
        Regexp(r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$',
               message="Invalid email format")
    ])
    subject = StringField('Subject', validators=[
        DataRequired(),
        Length(max=200),
        Regexp(r'^[a-zA-Z0-9\s\.,!?\'\"\-]+$',
               message="Subject contains invalid characters")
    ])
    message = TextAreaField('Message', validators=[
        DataRequired(),
        Length(max=2000),
        Regexp(r'^[\w\W\s\n\r]+$',
               message="Message contains invalid characters")
    ])


class UploadForm(FlaskForm):
    file = FileField('File', validators=[
        DataRequired(message="Please select a file to upload")
    ])


class OptionsForm(FlaskForm):
    action = StringField('Action', validators=[DataRequired()])
    submit = SubmitField('Continue')
