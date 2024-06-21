import secrets

from dotenv import load_dotenv
from flask import Flask, redirect, url_for, session, request, jsonify
from authlib.integrations.flask_client import OAuth
import os

load_dotenv(dotenv_path="oauth2.env")
app = Flask(__name__)
app.secret_key = os.urandom(24)

oauth = OAuth(app)
google = oauth.register(
    name='google',
    client_id=os.getenv('CLIENT_ID'),
    client_secret=os.getenv('CLIENT_SECRET'),
    access_token_url='https://accounts.google.com/o/oauth2/token',
    authorize_url='https://accounts.google.com/o/oauth2/auth',
    authorize_params=None,
    authorize_kwargs=None,
    client_kwargs={'scope': 'openid email profile'},
    jwks_uri='https://www.googleapis.com/oauth2/v3/certs',
)


@app.route('/')
def home():
    return 'Welcome to the OAuth 2.0 and OpenID Connect example! <a href="/login">Login with Google</a>'


@app.route('/login')
def login():
    nonce = secrets.token_urlsafe(16)
    session['nonce'] = nonce

    redirect_uri = url_for('authorize', _external=True)
    print(redirect_uri)
    return google.authorize_redirect(redirect_uri, nonce=nonce)


@app.route('/callback')
def authorize():
    token = google.authorize_access_token()
    user_info = google.parse_id_token(token, nonce=session['nonce'])
    session['user'] = user_info
    return redirect('/profile')


@app.route('/profile')
def profile():
    user_info = session.get('user')
    if user_info:
        return jsonify(user_info)
    return redirect('/')


if __name__ == '__main__':
    app.run(port=5000, debug=True)
