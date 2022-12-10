"""SQLAlchemy models for Warbler."""

from datetime import datetime

from flask_bcrypt import Bcrypt
from flask_sqlalchemy import SQLAlchemy
import enum

bcrypt = Bcrypt()
db = SQLAlchemy()

class AccountTypes(enum.intEnum):
    PROXIMITY = "proximity"
    MUTUALS = "mututals"
    COMMON_FOLLOWING = "common_following"
    OTHER = "other"


class Followed_Account(db.Model):
    """Connection of a follower <-> followed_user."""

    __tablename__ = 'followed_accounts'

    account_id = db.Column(
        db.Integer,
        db.ForeignKey('accounts.id', ondelete="cascade"),
        primary_key=True,
    )

    user_following_id = db.Column(
        db.Integer,
        db.ForeignKey('users.id', ondelete="cascade"),
        primary_key=True,
    )

    account_type = db.Column(db.Enum(AccountTypes))


class Account(db.Model):
    """Twitter account being followed"""

    __tablename__ = 'accounts'

    id = db.Column(
        db.Integer,
        primary_key=True
    )

    twitter_id = db.Column(
        db.Integer,
        unique=True,
        nullable=False
    )

    handle = db.Column(
        db.String,
        unique=True,
    )

    followed_since = db.Column(
        db.DateTime,
        nullable=False,
        default=datetime.now()
    )


class User(db.Model):
    """Application user"""

    __tablename__ = 'users'

    id = db.Column(
        db.Integer,
        primary_key=True
    )

    username = db.Column(
        db.Text,
        nullable=False,
        unique=True
    )

    email = db.Column(
        db.Text,
        nullable=False,
        unique=True
    )

    password = db.Column(
        db.Text,
        nullable=False
    )

    city = db.Column(
        db.Text,
        default="Unknown"
    )

    state = db.Column(
        db.String(2),
        default="Unknown"
    )

    latitude = db.Column(
        db.Float
    )

    longitude = db.Column(
        db.Float
    )

    following = db.relationship(
        "Account",
        secondary="followed_accounts",
        primaryjoin=(Followed_Account.account_id == Account.id),
        secondaryjoin=(Followed_Account.user_following_id == id)
    )

    def __repr__(self):
        return f"<User #{self.id}: {self.username}, {self.email}>"

    def is_following(self, acct):
        """Is this user following a specific account?"""

        return acct in self.following

    @classmethod
    def signup(cls, username, email, password):
        """Sign up user.

        Hashes password and adds user to system.
        """

        hashed_pwd = bcrypt.generate_password_hash(password).decode('UTF-8')

        user = User(
            username=username,
            email=email,
            password=hashed_pwd,
        )

        db.session.add(user)
        return user

    @classmethod
    def authenticate(cls, username, password):
        """Find user with `username` and `password`.

        This is a class method (call it on the class, not an individual user.)
        It searches for a user whose password hash matches this password
        and, if it finds such a user, returns that user object.

        If can't find matching user (or if password is wrong), returns False.
        """

        user = cls.query.filter_by(username=username).first()

        if user:
            is_auth = bcrypt.check_password_hash(user.password, password)
            if is_auth:
                return user

        return False
    
    @classmethod
    def change_password(cls, user, password):

        hashed_pwd = bcrypt.generate_password_hash(password).decode('UTF-8')

        user.password = hashed_pwd
        db.session.add(user)
        db.session.commit()