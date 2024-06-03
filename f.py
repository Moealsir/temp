import os
import json
import base64
from datetime import datetime, timedelta
from flask import Flask, request, redirect, session, url_for, jsonify
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow, Flow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
import logging
import secrets
import traceback
import pickle

# Generate a random secret key for Flask
flask_secret_key = secrets.token_urlsafe(32)

# Set up logging
logging.basicConfig(level=logging.DEBUG, handlers=[
    logging.FileHandler("app.log"),
    logging.StreamHandler()
])


app = Flask(__name__)
app.secret_key = flask_secret_key
app.config['PREFERRED_URL_SCHEME'] = 'https'

SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']
CREDENTIALS_FILE = 'credentials.json'
STORAGE_DIR = 'tokens'

if not os.path.exists(STORAGE_DIR):
    os.makedirs(STORAGE_DIR)


class DateTimeEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, datetime):
            return obj.isoformat()
        return json.JSONEncoder.default(self, obj)

def get_gmail_credentials(user_id):
    try:
        with open(CREDENTIALS_FILE, 'r') as f:
            credentials_data = json.load(f)
        for user in credentials_data['users']:
            if user['number'] == user_id:
                return {
                    "web": user['gmail_credentials']
                }
        raise ValueError("User ID not found in credentials file")
    except Exception as e:
        logging.error(f'Error loading credentials: {e}\n{traceback.format_exc()}')
        raise

@app.route('/')
def index():
    return 'Welcome to the Gmail Authorization App'

@app.route('/authorize/<user_id>')
def authorize(user_id):
    logging.debug(f'In authorize flask for user: {user_id}')
    try:
        gmail_credentials = get_gmail_credentials(user_id)
        with open('client_secret_temp.json', 'w') as temp_file:
            json.dump(gmail_credentials, temp_file)

        flow = InstalledAppFlow.from_client_secrets_file(
            'client_secret_temp.json', SCOPES)
        flow.redirect_uri = "https://auth.moealsir.tech/oauth2callback"
        authorization_url, state = flow.authorization_url(
            access_type='offline',
            include_granted_scopes='true')

        session['state'] = state
        session['user_id'] = user_id

        return redirect(authorization_url)
    except Exception as e:
        logging.error(f'Error in authorization: {e}\n{traceback.format_exc()}')
        return f'An error occurred: {e}', 500

@app.route('/oauth2callback')
def oauth2callback():
    try:
        state = session.get('state')
        user_id = session.get('user_id')

        if not state or not user_id:
            return 'State or user_id is missing from the session.', 400

        gmail_credentials = get_gmail_credentials(user_id)
        with open('client_secret_temp.json', 'w') as temp_file:
            json.dump(gmail_credentials, temp_file)

        flow = InstalledAppFlow.from_client_secrets_file(
            'client_secret_temp.json', SCOPES, state=state)

        flow.redirect_uri = "https://auth.moealsir.tech/oauth2callback"
        authorization_response = request.url

        flow.fetch_token(authorization_response=authorization_response)

        creds = flow.credentials
        token_file = os.path.join(STORAGE_DIR, f'{user_id}.json')

        with open(token_file, 'w') as token:
            token_data = {
                'token': creds.token,
                'refresh_token': creds.refresh_token,
                'token_uri': creds.token_uri,
                'client_id': creds.client_id,
                'client_secret': creds.client_secret,
                'scopes': creds.scopes
            }
            json.dump(token_data, token)

        os.remove('client_secret_temp.json')
        return redirect(url_for('check_emails', user_id=user_id))
    except Exception as e:
        logging.error(f'Error in oauth2callback: {e}\n{traceback.format_exc()}')
        return f'An error occurred: {e}', 500


if __name__ == '__main__':
    # Paths to Let's Encrypt SSL/TLS certificate files
    ssl_cert_path = "/etc/letsencrypt/live/auth.moealsir.tech/fullchain.pem"
    ssl_key_path = "/etc/letsencrypt/live/auth.moealsir.tech/privkey.pem"

    # Run Flask app with SSL/TLS enabled
    app.run(host='0.0.0.0', port=5000, debug=True, ssl_context=(ssl_cert_path, ssl_key_path))