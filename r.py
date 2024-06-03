from flask import Flask, redirect, url_for, request, session, jsonify
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import Flow
import os
import json
import pickle
import logging

app = Flask(__name__)
app.secret_key = os.urandom(24)

# Set up logging
logging.basicConfig(level=logging.DEBUG)

with open('credentials.json', 'r') as f:
    credentials_data = json.load(f)

SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']

@app.route('/')
def index():
    return 'Welcome to the Gmail OAuth App'

def create_user_directory(user_id):
    user_directory = os.path.join('users', user_id)
    if not os.path.exists(user_directory):
        os.makedirs(user_directory)
        os.makedirs(os.path.join(user_directory, 'tokens'))
    return user_directory

@app.route('/authorize/<user_id>')
def authorize(user_id):
    logging.debug(f'In authorize for user: {user_id}')
    user_cred = next((user for user in credentials_data['users'] if user['number'] == user_id), None)
    app.logger.debug(f'user_cred: {user_cred}')

    if not user_cred:
        return jsonify({'error': 'User not found'}), 404

    user_path = create_user_directory(user_id)
    token_path = os.path.join(user_path, 'tokens', 'token.pickle')

    if os.path.exists(token_path):
        return f'User {user_id} already authorized, Token already exists'

    user_config = user_cred['gmail_credentials']
    flow = Flow.from_client_config({'web': user_config}, scopes=SCOPES)
    flow.redirect_uri = url_for('oauth2callback', _external=True, _scheme='https')

    authorize_url, state = flow.authorization_url(access_type='offline', include_granted_scopes='true')
    app.logger.debug(f'authorize_url: {authorize_url}')

    session['state'] = state
    session['user_id'] = user_id
    with open('temp.json', 'w') as f:
            json.dump(session, f)

    logging.debug(f'Session: {session}')
    logging.debug('end of authorize')
    return redirect(authorize_url)

@app.route('/oauth2callback')
def oauth2callback():
    logging.debug('In oauth2callback')
    with open('temp.json', 'r') as f:
            session = json.load(f)
    logging.debug(f'Session: {session}')
    state = session.get('state')
    user_id = session.get('user_id')
    logging.debug(f'state: {state}, user_id: {user_id}')

    if not state or not user_id:
        return jsonify({'error': 'Session state or user ID missing'}), 400

    user_cred = next((user for user in credentials_data['users'] if user['number'] == user_id), None)
    if not user_cred:
        return jsonify({'error': 'User not found'}), 404

    user_config = user_cred['gmail_credentials']
    flow = Flow.from_client_config({'web': user_config}, scopes=SCOPES, state=state)
    flow.redirect_uri = url_for('oauth2callback', _external=True, _scheme='https')

    authorization_response = request.url
    flow.fetch_token(authorization_response=authorization_response)

    credentials = flow.credentials

    # Save credentials
    user_path = os.path.join('users', user_id, 'tokens')
    with open(os.path.join(user_path, 'token.pickle'), 'wb') as token_file:
        pickle.dump(credentials, token_file)

    logging.debug('end of oauth2callback')
    return 'Authorization successful, you can close the tab now'

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001, debug=True)