import os

from flask import Flask, render_template, request, flash, redirect, session, g, url_for
#from flask_debugtoolbar import DebugToolbarExtension
from sqlalchemy.exc import IntegrityError
from forms import UserAddForm, LoginForm, UserProfileForm, PasswordResetForm
from models import db, connect_db, User, Followed_Account
from functools import wraps

CURR_USER_KEY = "curr_user"

app = Flask(__name__)

# Get DB_URI from environ variable (useful for production/testing) or,
# if not set there, use development local db.
app.config['SQLALCHEMY_DATABASE_URI'] = (
    os.environ.get('DATABASE_URL', 'postgresql:///twitter_friends'))

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_ECHO'] = True
#app.config['DEBUG_TB_INTERCEPT_REDIRECTS'] = True
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', "it's a secret")
#toolbar = DebugToolbarExtension(app)

connect_db(app)

##############################################################################
# User signup/login/logout


@app.before_request
def add_user_to_g():
    """If we're logged in, add curr user to Flask global."""

    if CURR_USER_KEY in session:
        g.user = User.query.get(session[CURR_USER_KEY])
    else:
        g.user = None
    

#############################HANDLERS################################
@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

def login_required(f):
    @wraps(f)

    def decorated_function(*args, **kwargs):
        if g.user is None:
            flash("You need to be logged in to perform that operation.", "danger")
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

#############################UTILITY##################################

def do_login(user):
    """Log in user."""

    session[CURR_USER_KEY] = user.id


def do_logout():
    """Logout user."""

    if CURR_USER_KEY in session:
        del session[CURR_USER_KEY]


@app.route('/signup', methods=["GET", "POST"])
def signup():
    """Handle user signup.

    Create new user and add to DB. Redirect to home page.

    If form not valid, present form.

    If the there already is a user with that username: flash message
    and re-present form.
    """

    form = UserAddForm()

    if form.validate_on_submit():
        try:
            user = User.signup(
                username=form.username.data,
                email=form.email.data,
                password=form.password.data,
                city=form.city.data,
                state=form.state.data
            )
            db.session.commit()

        except IntegrityError:
            flash("Username already taken", 'danger')
            return render_template('users/signup.html', form=form)

        do_login(user)

        return redirect(url_for('homepage'))

    else:
        return render_template('users/signup.html', form=form)


@app.route('/login', methods=["GET", "POST"])
def login():
    """Handle user login."""

    form = LoginForm()

    if form.validate_on_submit():
        user = User.authenticate(form.username.data,
                                 form.password.data)

        if user:
            do_login(user)
            flash(f"Hello, {user.username}!", "success")
            return redirect(url_for('homepage'))

        flash("Invalid credentials.", 'danger')

    return render_template('users/login.html', form=form)


@app.route('/logout')
def logout():
    """Handle logout of user."""

    do_logout()

    flash('You have successfully logged out of the application.', 'success')

    return redirect(url_for('login'))


#############################USER/ACCT RELATED#######################################

@app.route('/users')
def list_users():
    """Page with listing of users.

    Can take a 'q' param in querystring to search by that username.
    """

    search = request.args.get('q')

    if not search:
        users = User.query.all()
    else:
        users = User.query.filter(User.username.like(f"%{search}%")).all()

    return render_template('users/index.html', users=users)


@app.route('/users/<int:user_id>')
@login_required
def users_show(user_id):
    """Show user profile."""

    user = User.query.get_or_404(user_id)

    if user != g.user:
        return redirect(url_for('homepage'))
    else: 
        return render_template('users/show.html', accts=user.following, user=user)   

@app.route('/users/<int:user_id>/reset_password', methods=["GET", "POST"])
@login_required
def reset_password(user_id):
    """Handle user password change form"""

    if user_id != g.user.id and not g.user.admin:
        return render_template('401.html'), 401
    form = PasswordResetForm()

    if form.validate_on_submit():
        if form.current_password.data == form.new_password.data:
            flash("New password can't match the old one. Please try again.", 'danger')
            return redirect(url_for('users_show', user_id=user_id))
            
        user = User.authenticate(g.user.username, form.current_password.data)
        if user:
            if form.new_password.data == form.confirm_password.data:        
                User.change_password(user, form.new_password.data)
                flash("Password successfully updated!", 'success')
                return redirect(url_for('homepage'))
            else:
                flash("New passwords don't match. Please try again.", 'danger')
                return redirect(request.referrer)
        else: 
            flash('Unable to authenticate. Please try again.', 'danger')
            return redirect(request.referrer)

    return render_template('users/reset_password.html', form=form)

@app.route('/users/<int:user_id>/following')
@login_required
def show_following(user_id):
    """Show list of people this user is following."""

    user = User.query.get_or_404(user_id)
    return render_template('users/following.html', user=user)

@app.route('/users/stop-following/<int:acct_id>', methods=['POST'])
@login_required
def stop_following(acct_id):
    """Have currently-logged-in-user stop following this user."""

    followed_acct = Followed_Account.query.get_or_404(acct_id)
    g.user.following.remove(followed_acct)
    db.session.commit()

    return redirect(url_for('show_following', user_id=g.user.id))

@app.route('/users/profile/<int:user_id>', methods=["GET", "POST"])
def profile(user_id):
    """Update profile for current user."""

    if user_id != g.user.id and not g.user.admin:
        return render_template('401.html'), 401

    user = User.query.get_or_404(user_id)
    form = None
    
    form = UserProfileForm(obj=user)

    if form.validate_on_submit():
        if not g.user.admin:
            user = User.authenticate(form.username.data,
                                    form.password.data)

        if user:
            #data = {k: v for k, v in form.data.items() if k not in ("csrf_token", 'Password')}
            #user = User(**data)
            if user.username != form.username.data:
                user.username = form.username.data
            if user.email != form.email.data:
                user.email = form.email.data
            if user.city != form.city.data:
                user.city = form.city.data
            if user.state != form.state.data:
                user.state = form.state.data

            db.session.add(user)
            db.session.commit()

            return redirect(url_for('users_show', user_id=user.id))
        else:
            flash("Bad password. Profile not updated. Please try again!", 'danger')
            return redirect(request.referrer)

    return render_template('users/edit.html', form=form, id=user.id)

@app.route('/users/delete/<int:user_id>', methods=["POST"])
@login_required
def delete_user(user_id):
    """Delete user."""

    if user_id != g.user.id and not g.user.admin:
        return render_template('401.html'), 401

    if not g.user.admin:
        do_logout()

    db.session.delete(User.query.get_or_404(user_id))
    db.session.commit()

    return redirect(url_for('homepage'))

#####################HOMEPAGE############################

@app.route('/')
def homepage():
    """Show homepage:

    - prompt site sign in if not logged in
    - OR
    - prompt twitter sign in if logged in
    """

    if g.user:
        return render_template('home.html')
    else:
        return render_template('home-anon.html')
