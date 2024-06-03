import os
import json
import base64
from datetime import datetime, timedelta
from flask import Flask, request, redirect, session, url_for, jsonify
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
import logging
import traceback

app = Flask(__name__)
app.secret_key = os.urandom(24)
app.config['PREFERRED_URL_SCHEME'] = 'https'
CREDENTIALS_FILE = 'credentials.json'
STORAGE_DIR = 'users'

if not os.path.exists(STORAGE_DIR):
    os.makedirs(STORAGE_DIR)

logging.basicConfig(level=logging.DEBUG, handlers=[
    logging.FileHandler("app.log"),
    logging.StreamHandler()
])

formatter = logging.Formatter(
    '%(asctime)s - %(name)s - %(levelname)s - %(message)s')

for handler in logging.getLogger().handlers:
    handler.setFormatter(formatter)

with open(CREDENTIALS_FILE, 'r') as f:
    credentials_data = json.load(f)

SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']

class DateTimeEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, datetime):
            return obj.isoformat()
        return json.JSONEncoder.default(self, obj)

def get_user_emails(user_id):
    try:
        for user in credentials_data['users']:
            if user['user_id'] == user_id:
                return user['emails']
        raise ValueError("User ID not found in credentials file")
    except Exception as e:
        logging.error(f'Error loading emails for user {user_id}: {e}')
        raise

def get_gmail_credentials(email_id):
    try:
        for email in credentials_data['emails']:
            if email['email'] == email_id:
                return {
                    "web": email['gmail_credentials']
                }
        raise ValueError("Email ID not found in credentials file")
    except Exception as e:
        logging.error(f'Error loading credentials for email {email_id}: {e}')
        raise

def create_user_directory(user_id, email_id=None):
    user_directory = os.path.join(STORAGE_DIR, user_id)
    if email_id:
        user_directory = os.path.join(user_directory, email_id)
    if not os.path.exists(user_directory):
        os.makedirs(user_directory)
    return user_directory

def save_session(user_id, session_data):
    user_directory = create_user_directory(user_id)
    session_file = os.path.join(user_directory, 'session.json')
    with open(session_file, 'w') as f:
        json.dump(session_data, f)

def load_session(user_id):
    user_directory = create_user_directory(user_id)
    session_file = os.path.join(user_directory, 'session.json')
    if os.path.exists(session_file):
        with open(session_file, 'r') as f:
            return json.load(f)
    return None

def save_token(user_id, email_id, token_data):
    user_directory = create_user_directory(user_id, email_id)
    token_file = os.path.join(user_directory, 'token.json')
    with open(token_file, 'w') as token:
        json.dump(token_data, token)

def load_token(user_id, email_id):
    user_directory = create_user_directory(user_id, email_id)
    token_file = os.path.join(user_directory, 'token.json')
    if os.path.exists(token_file):
        with open(token_file, 'r') as token:
            return json.load(token)
    return None

@app.route('/')
def index():
    logging.debug('In index')
    return 'Welcome to the Gmail OAuth App'

@app.route('/authorize/<user_id>/<email_id>')
def authorize(user_id, email_id):
    logging.debug(f'In authorize for user: {user_id}, email: {email_id}')
    try:
        user_emails = get_user_emails(user_id)
        if email_id not in user_emails:
            return jsonify({'error': 'Email ID not found in user emails.'}), 404

        existing_token = load_token(user_id, email_id)
        if existing_token:
            return jsonify({'message': 'User is already authorized.'})

        gmail_credentials = get_gmail_credentials(email_id)
        logging.debug(f'Gmail credentials: {gmail_credentials}')
        with open('client_secret_temp.json', 'w') as temp_file:
            json.dump(gmail_credentials, temp_file)

        flow = InstalledAppFlow.from_client_secrets_file(
            'client_secret_temp.json', SCOPES)
        flow.redirect_uri = url_for('oauth2callback', _external=True)
        authorization_url, state = flow.authorization_url(
            access_type='offline',
            include_granted_scopes='true')

        session['state'] = state
        session['user_id'] = user_id
        session['email_id'] = email_id
        state_file = os.path.join(STORAGE_DIR, state)
        with open(state_file, 'w') as f:
            json.dump({'user_id': user_id, 'email_id': email_id}, f)
        session.modified = True
        save_session(user_id, session)

        logging.debug(f'Authorization URL: {authorization_url}')
        return redirect(authorization_url)
    except ValueError as e:
        logging.error(f'Error in authorization for user {user_id}: {e}')
        return jsonify({'error': 'An error occurred during authorization.', 'details': str(e)}), 500
    except Exception as e:
        logging.error(f'Unexpected error in authorization for user {user_id}: {e}')
        return jsonify({'error': 'An unexpected error occurred during authorization.'}), 500

@app.route('/oauth2callback')
def oauth2callback():
    try:
        state = request.args.get('state')
        logging.debug(f'In oauth2callback with state: {state}')
        if not state:
            return jsonify({'error': 'State parameter is missing from the request.'}), 400

        state_file_path = os.path.join(STORAGE_DIR, state)
        if not os.path.exists(state_file_path):
            return jsonify({'error': 'Invalid state parameter.'}), 400

        with open(state_file_path, 'r') as f:
            data = json.load(f)

        user_id = data.get('user_id')
        email_id = data.get('email_id')
        logging.debug(f'Session data: {data}')
        if not user_id or not email_id:
            return jsonify({'error': 'User ID or Email ID is missing from the session data.'}), 400

        gmail_credentials = get_gmail_credentials(email_id)
        with open('client_secret_temp.json', 'w') as temp_file:
            json.dump(gmail_credentials, temp_file)

        flow = InstalledAppFlow.from_client_secrets_file(
            'client_secret_temp.json', SCOPES, state=state)
        flow.redirect_uri = url_for('oauth2callback', _external=True)
        authorization_response = request.url
        flow.fetch_token(authorization_response=authorization_response)

        creds = flow.credentials
        token_data = {
            'token': creds.token,
            'refresh_token': creds.refresh_token,
            'token_uri': creds.token_uri,
            'client_id': creds.client_id,
            'client_secret': creds.client_secret,
            'scopes': creds.scopes
        }
        save_token(user_id, email_id, token_data)
        os.remove('client_secret_temp.json')

        return jsonify({'message': 'Authorization successful. You can now check your emails.'})
    except ValueError as e:
        logging.error(f'Error in oauth2callback for user {user_id}: {e}')
        return jsonify({'error': 'An error occurred during the OAuth callback.', 'details': str(e)}), 500
    except Exception as e:
        logging.error(f'Unexpected error in oauth2callback for user {user_id}: {e}')
        return jsonify({'error': 'An unexpected error occurred during the OAuth callback.'}), 500

@app.route('/check_emails/<user_id>/<email_id>')
def check_emails(user_id, email_id):
    logging.debug(f'Checking emails for user: {user_id}, email: {email_id}')
    try:
        token_data = load_token(user_id, email_id)
        if not token_data:
            return jsonify({'error': 'No token found for the user.'}), 404

        creds = Credentials(
            token=token_data['token'],
            refresh_token=token_data['refresh_token'],
            token_uri=token_data['token_uri'],
            client_id=token_data['client_id'],
            client_secret=token_data['client_secret'],
            scopes=token_data['scopes']
        )

        user = {'number': user_id}
        last_processed_time = datetime.utcnow() - timedelta(days=1)
        new_emails = check_new_emails(user, creds, last_processed_time)
        return jsonify(new_emails)
    except Exception as e:
        logging.error(f'Error in check_emails: {e}\n{traceback.format_exc()}')
        return jsonify({'error': 'An error occurred while checking emails.', 'details': str(e)}), 500

def check_new_emails(user, creds, last_processed_time):
    try:
        service = build('gmail', 'v1', credentials=creds)
        query = f'after:{int(last_processed_time.timestamp())}'
        logging.debug(f'Querying emails with query: {query}')
        results = service.users().messages().list(userId='me', q=query).execute()
        messages = results.get('messages', [])
        new_emails = []

        for msg in messages:
            msg_id = msg['id']
            msg_data = service.users().messages().get(userId='me', id=msg_id).execute()
            msg_date = datetime.fromtimestamp(int(msg_data['internalDate']) / 1000)
            if msg_date > last_processed_time:
                snippet = msg_data['snippet']
                new_emails.append({
                    'id': msg_id,
                    'snippet': snippet,
                    'timestamp': msg_date.isoformat()
                })
        return new_emails
    except HttpError as error:
        logging.error(f'An error occurred: {error}')
        return {'error': str(error)}

if __name__ == '__main__':
    ssl_cert_path = "/etc/letsencrypt/live/auth.moealsir.tech/fullchain.pem"
    ssl_key_path = "/etc/letsencrypt/live/auth.moealsir.tech/privkey.pem"

    app.run(host='0.0.0.0', port=5001, ssl_context=(ssl_cert_path, ssl_key_path))
