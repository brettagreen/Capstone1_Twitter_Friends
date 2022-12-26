import os

from flask import Flask, render_template, request, flash, redirect, session, g, url_for
from sqlalchemy.exc import IntegrityError
from forms import UserAddForm, LoginForm, UserProfileForm, PasswordResetForm
from models import db, connect_db, User, Followed_Account
from functools import wraps
import jsonpickle, tweepy, requests, private

CURR_USER_KEY = "curr_user"
oauth1_user_handler = None

app = Flask(__name__)

# Get DB_URI from environ variable (useful for production/testing) or,
# if not set there, use development local db.
app.config['SQLALCHEMY_DATABASE_URI'] = (
    os.environ.get('DATABASE_URL', 'postgresql:///twitter_friends'))

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_ECHO'] = True
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', "rapunzel's demise")

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

        return redirect(url_for('auth_request'))

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
            return redirect(url_for('auth_request'))

        flash("Invalid credentials.", 'danger')

    return render_template('users/login.html', form=form)


@app.route('/logout')
def logout():
    """Handle logout of user."""

    do_logout()

    flash('You have successfully logged out of the application.', 'success')

    return redirect(url_for('login'))


#############################USER/ACCT RELATED#######################################

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

    if user_id != g.user.id:
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

    if user_id != g.user.id:
        return render_template('401.html'), 401

    user = User.query.get_or_404(user_id)
    form = None
    
    form = UserProfileForm(obj=user)

    if form.validate_on_submit():
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

    if user_id != g.user.id:
        return render_template('401.html'), 401

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

@app.route('/request_auth_token', methods=['GET'])
def request_token():
    """include_entities = "true"
    oauth_nonce = ''.join(random.choice(string.ascii_lowercase + string.ascii_uppercase + string.digits) for _ in range(42))
    oauth_consumer_key = 'LEvKT3XOMifnch9J2qZ4jpokg'
    oauth_signature_method = 'HMAC-SHA1'
    oauth_version = "1.0"
    oauth_token = "1247739711512358913-Mv3SrBIeu1AIrQhC1hOLjSdOsn8VHg"
    oauth_timestamp = str(int(time.time()))

    #signature_url = "https://api.twitter.com/1.1/statuses/update.json"
    request_token_url = f"https://api.twitter.com/oauth/request_token"

    auth_params = f"include_entities={include_entities}&oauth_consumer_key={oauth_consumer_key}&" \
            f"oauth_nonce={oauth_nonce}&oauth_signature_method={oauth_signature_method}&" \
            f"oauth_timestamp={oauth_timestamp}&oauth_token={oauth_token}&oauth_version={oauth_version}"

    base_signature = f"POST&https%3A%2F%2Fapi.twitter.com%2F1.1%2Fstatuses%2Fupdate.json&" + quote(auth_params, safe="")
    print(base_signature)

    key = bytes(private.SIGNING_KEY, encoding='utf-8')
    raw = bytes(base_signature, encoding='utf-8')

    hashed = hmac.new(key, raw, sha1)
    oauth_signature = quote(base64.b64encode(hashed.digest()), safe="")

    header = {'Authorization':f'OAuth oauth_consumer_key="{oauth_consumer_key}", oauth_nonce="{oauth_nonce}", ' \
        f'oauth_signature="{oauth_signature}", oauth_signature_method="{oauth_signature_method}", ' \
        f'oauth_timestamp="{oauth_timestamp}", oauth_version="{oauth_version}"'}

    resp = requests.post(
                request_token_url,
                params={"oauth_callback": f'https%3A%2F%2F97fc-107-204-176-106.ngrok.io%2Fauthorize'},                
                headers=header
            )"""

    oauth1_user_handler = tweepy.OAuth1UserHandler(private.API_KEY, private.API_KEY_SECRET,
            callback="https://97fc-107-204-176-106.ngrok.io/authorize")

    resp = oauth1_user_handler.get_authorization_url(signin_with_twitter=True)

    session['oauth_handler'] = jsonpickle.encode(oauth1_user_handler)

    return redirect(resp)

@app.route('/authorize')
def authorize():
    print("################STEPII####################")
    
    oauth1_user_handler = jsonpickle.decode(session['oauth_handler'])

    oauth_verifier = request.args.get("oauth_verifier")

    request_token = oauth1_user_handler.request_token["oauth_token"]
    request_secret = oauth1_user_handler.request_token["oauth_token_secret"]

    access_token, access_token_secret = (oauth1_user_handler.get_access_token(oauth_verifier))
    
    client = tweepy.Client(
    consumer_key=private.API_KEY,
    consumer_secret=private.API_KEY_SECRET,
    access_token=access_token,
    access_token_secret=access_token_secret)

    session['client'] = jsonpickle.encode(client)

    return redirect(url_for('homepage'))

@app.route('/get_followers')
def get_followers():
    client = jsonpickle.decode(session['client'])

    resp = client.get_me()
    id = resp.data.id

    resp = client.get_users_followers(id, user_auth=True)
    followers = []
    for user in resp.data:
        followers.append(user.id)

    following = []

    for id in followers:
        resp = client.get_users_following(id, user_auth=True)
        if resp.data is not None:
            for user in resp.data:
                following.append((id, user.username))

    list = [acct for acct in following if following.count(acct[0]) > 1]
    print('THE LIST HAS ARRIVED')
    print(list)

    return('success')