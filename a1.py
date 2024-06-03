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

# Set up logging
logging.basicConfig(level=logging.DEBUG, handlers=[
    logging.FileHandler("app.log"),
    logging.StreamHandler()
])

with open(CREDENTIALS_FILE, 'r') as f:
    credentials_data = json.load(f)

SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']

class DateTimeEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, datetime):
            return obj.isoformat()
        return json.JSONEncoder.default(self, obj)

def get_gmail_credentials(user_id):
    try:
        for user in credentials_data['users']:
            if user['number'] == user_id:
                return {
                    "web": user['gmail_credentials']
                }
        raise ValueError("User ID not found in credentials file")
    except Exception as e:
        logging.error(f'Error loading credentials: {e}\n{traceback.format_exc()}')
        raise

def create_user_directory(user_id):
    user_directory = os.path.join(STORAGE_DIR, user_id)
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

def save_token(user_id, token_data):
    user_directory = create_user_directory(user_id)
    token_file = os.path.join(user_directory, 'token.json')
    with open(token_file, 'w') as token:
        json.dump(token_data, token)

def load_token(user_id):
    user_directory = create_user_directory(user_id)
    token_file = os.path.join(user_directory, 'token.json')
    if os.path.exists(token_file):
        with open(token_file, 'r') as token:
            return json.load(token)
    return None

@app.route('/')
def index():
    logging.debug('In index')
    return 'Welcome to the Gmail OAuth App'

@app.route('/authorize/<user_id>')
def authorize(user_id):
    logging.debug(f'In authorize for user: {user_id}')
    try:
        existing_token = load_token(user_id)
        if existing_token:
            return redirect(url_for('check_emails', user_id=user_id))

        gmail_credentials = get_gmail_credentials(user_id)
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
        save_session(user_id, session)

        return redirect(authorization_url)
    except Exception as e:
        logging.error(f'Error in authorization: {e}\n{traceback.format_exc()}')
        return f'An error occurred: {e}', 500

@app.route('/oauth2callback')
def oauth2callback():
    try:
        state = request.args.get('state')
        user_id = session.get('user_id')

        if not state or not user_id:
            return 'State or user_id is missing from the session.', 400

        gmail_credentials = get_gmail_credentials(user_id)
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
        save_token(user_id, token_data)
        os.remove('client_secret_temp.json')

        return redirect(url_for('check_emails', user_id=user_id))
    except Exception as e:
        logging.error(f'Error in oauth2callback: {e}\n{traceback.format_exc()}')
        return f'An error occurred: {e}', 500

@app.route('/check_emails/<user_id>')
def check_emails(user_id):
    logging.debug(f'Checking emails for user: {user_id}')
    try:
        token_data = load_token(user_id)
        if not token_data:
            return f'No token found for user: {user_id}', 404

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
        return f'An error occurred: {e}', 500

def check_new_emails(user, creds, last_processed_time):
    try:
        service = build('gmail', 'v1', credentials=creds)
        query = f'after:{int(last_processed_time.timestamp())}'
        results = service.users().messages().list(userId='me', q=query).execute()
        messages = results.get('messages', [])

        if not messages:
            return []

        new_emails = []
        for message in messages:
            msg = service.users().messages().get(userId='me', id=message['id']).execute()
            msg_data = msg['payload']['headers']

            sender_name = ''
            sender_email = ''
            subject = ''
            body = ''
            for header in msg_data:
                if (name := header['name']) == 'From':
                    sender = header['value']
                    sender_name, sender_email = parse_sender(sender)
                elif name == 'Subject':
                    subject = header['value']

            if 'parts' in msg['payload']:
                for part in msg['payload']['parts']:
                    if part['mimeType'] == 'text/plain':
                        body = base64.urlsafe_b64decode(part['body']['data']).decode('utf-8')
                        break
            else:
                if 'body' in msg['payload']:
                    body = base64.urlsafe_b64decode(msg['payload']['body']['data']).decode('utf-8')

            email_time = datetime.fromtimestamp(int(msg['internalDate']) / 1000)
            new_emails.append((email_time, sender_name, sender_email, subject, body))

        email_file = os.path.join(STORAGE_DIR, user["number"], f'{user["number"]}_emails.json')

        if not new_emails:
            with open(email_file, 'w') as f:
                json.dump([], f)
        else:
            with open(email_file, 'w') as f:
                json.dump(new_emails, f, cls=DateTimeEncoder, indent=4)

        return new_emails

    except HttpError as error:
        logging.error(f'An error occurred while fetching emails: {error}\n{traceback.format_exc()}')
        return []

def parse_sender(sender):
    sender = sender.split('<')
    if len(sender) > 1:
        sender_name = sender[0].strip()
        sender_email = sender[1].replace('>', '').strip()
    else:
        sender_name = ''
        sender_email = sender[0].strip()
    return sender_name, sender_email

if __name__ == '__main__':
    # Paths to Let's Encrypt SSL/TLS certificate files
    ssl_cert_path = "/etc/letsencrypt/live/auth.moealsir.tech/fullchain.pem"
    ssl_key_path = "/etc/letsencrypt/live/auth.moealsir.tech/privkey.pem"

    app.run(host='0.0.0.0', port=5000, ssl_context=(ssl_cert_path, ssl_key_path))
