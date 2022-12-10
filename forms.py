from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField
from wtforms.validators import DataRequired, Email, Length, Optional


class UserAddForm(FlaskForm):
    """Form for adding users."""

    username = StringField('Username', validators=[DataRequired()])
    email = StringField('E-mail', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[Length(min=6)])
    city = StringField('City/Town', validators=[Optional()])
    state = StringField('State', validators=[Optional()])

class LoginForm(FlaskForm):
    """Login form."""

    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])

class UserProfileForm(FlaskForm):
    """Form to edit user profile"""

    email = StringField('E-mail', validators=[Email(), Optional()])
    password = PasswordField('Password', validators=[Optional()])
    city = StringField('City/Town', validators=[Optional()])
    state = StringField('State', validators=[Optional()])
    
class PasswordResetForm(FlaskForm):
    """Form to change user password"""

    current_password = PasswordField("Enter your current password", validators=[DataRequired()])
    new_password = PasswordField("Enter your new password", validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField("Confirm your new password", validators=[DataRequired(), Length(min=6)])
