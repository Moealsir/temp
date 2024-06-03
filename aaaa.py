import os
import json
import base64
import pickle
from datetime import datetime, timedelta
from flask import Flask, request, redirect, session, url_for, jsonify
from flask_session import Session
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from google.auth.transport.requests import Request
import logging
import secrets
import traceback
from apscheduler.schedulers.background import BackgroundScheduler

# Generate a random secret key for Flask
flask_secret_key = secrets.token_urlsafe(32)

# Set up logging
logging.basicConfig(level=logging.DEBUG, handlers=[
    logging.FileHandler("app.log"),
    logging.StreamHandler()
])

app = Flask(__name__)
app.secret_key = flask_secret_key

# Configure Flask-Session
app.config['SESSION_TYPE'] = 'filesystem'
app.config['SESSION_FILE_DIR'] = './flask_session/'
app.config['SESSION_PERMANENT'] = False
app.config['SESSION_USE_SIGNER'] = True
app.config['SESSION_KEY_PREFIX'] = 'session:'
app.config['SESSION_FILE_THRESHOLD'] = 100
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_DOMAIN'] = '.moealsir.tech'

# Initialize the Flask-Session extension
Session(app)

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

def load_credentials(user):
    creds = None
    token_folder = os.path.join('users', user["number"], 'tokens')
    token_path = os.path.join(token_folder, 'token.pickle')
    if os.path.exists(token_path):
        with open(token_path, 'rb') as token:
            creds = pickle.load(token)
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_config(
                {"installed": user["gmail_credentials"]}, SCOPES,
                redirect_uri=f'https://auth.moealsir.tech/oauth2callback')
            creds = flow.run_local_server(port=user["port"])
        if not os.path.exists(token_folder):
            os.makedirs(token_folder)
        with open(token_path, 'wb') as token:
            pickle.dump(creds, token)
    return creds

def load_last_processed_time(user):
    last_processed_time_file = os.path.join('users', user["number"], f'{user["number"]}_last_processed_time.json')
    if os.path.exists(last_processed_time_file):
        with open(last_processed_time_file, 'r') as f:
            return datetime.fromisoformat(json.load(f))
    else:
        return datetime.utcnow() - timedelta(minutes=5)

def save_last_processed_time(user, time):
    last_processed_time_file = os.path.join('users', user["number"], f'{user["number"]}_last_processed_time.json')
    with open(last_processed_time_file, 'w') as f:
        json.dump(time.isoformat(), f)

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
                if header['name'] == 'From':
                    sender = header['value']
                    sender_name, sender_email = parse_sender(sender)

                if header['name'] == 'Subject':
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

        email_file = os.path.join('users', user["number"], f'{user["number"]}_emails.json')

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

def check_emails_periodically():
    try:
        with open(CREDENTIALS_FILE, 'r') as f:
            users = json.load(f)["users"]

        for user in users:
            creds = load_credentials(user)
            last_processed_time = load_last_processed_time(user)
            new_emails = check_new_emails(user, creds, last_processed_time)

            if new_emails:
                for email in new_emails:
                    email_time, sender_name, sender_email, subject, body = email
                    if email_time > last_processed_time:
                        last_processed_time = email_time
                save_last_processed_time(user, last_processed_time)
                logging.info(f"Checked emails for user {user['number']}. New emails: {new_emails}")
            else:
                logging.info(f"No new emails for user {user['number']}.")
    except Exception as e:
        logging.error(f"Error checking emails periodically: {e}\n{traceback.format_exc()}")

def start_scheduler():
    scheduler = BackgroundScheduler()
    scheduler.add_job(check_emails_periodically, 'interval', minutes=1)
    scheduler.start()

@app.route('/')
def index():
    return 'Welcome to the Gmail Authorization App'

@app.route('/authorize/<user_id>')
def authorize(user_id):
    logging.debug(f'Received authorization request for user_id: {user_id}')
    try:
        gmail_credentials = get_gmail_credentials(user_id)
        with open('client_secret_temp.json', 'w') as temp_file:
            json.dump(gmail_credentials, temp_file)

        user = {"number": user_id, "gmail_credentials": gmail_credentials}
        creds = load_credentials(user)
        if creds and creds.valid:
            logging.info(f'Valid credentials found for user {user_id}, skipping reauthorization')
            return 'Already authorized. You can close this window.'

        flow = InstalledAppFlow.from_client_secrets_file(
            'client_secret_temp.json', SCOPES)
        flow.redirect_uri = url_for('oauth2callback', _external=True)
        authorization_url, state = flow.authorization_url(
            access_type='offline',
            include_granted_scopes='true')

        session['state'] = state
        session['user_id'] = user_id
        with open(f'temp.json', 'w') as f:
            json.dump({'state': state, 'user_id': user_id}, f)

        return redirect(authorization_url)
    except Exception as e:
        logging.error(f'Error in authorization: {e}\n{traceback.format_exc()}')
        return f'An error occurred: {e}', 500

@app.route('/oauth2callback')
def oauth2callback():
    try:
        with open(f'temp.json', 'r') as f:
            session_data = json.load(f)
            logging.debug(f'Session data: {session_data}')
        state = session_data['state']

        flow = InstalledAppFlow.from_client_secrets_file(
            'client_secret_temp.json', SCOPES, state=state)
        flow.redirect_uri = url_for('oauth2callback', _external=True)
        authorization_response = request.url
        flow.fetch_token(authorization_response=authorization_response)
        credentials = flow.credentials

        user_id = session_data['user_id']
        token_folder = os.path.join('users', user_id, 'tokens')
        if not os.path.exists(token_folder):
            os.makedirs(token_folder)
        token_path = os.path.join(token_folder, 'token.pickle')
        with open(token_path, 'wb') as token:
            pickle.dump(credentials, token)

        return 'Authorization successful! You can close this window.'
    except Exception as e:
        logging.error(f'Error in OAuth2 callback: {e}\n{traceback.format_exc()}')
        return f'An error occurred: {e}', 500

if __name__ == '__main__':
    if os.getenv('RUN_MAIN') == 'true':
        # Start the scheduler only if this is the main process
        start_scheduler()
    app.run(host='0.0.0.0', port=5001, use_reloader=False)
