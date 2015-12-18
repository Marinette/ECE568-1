''' Provided '''
import sys, SocketServer 
from bottle import route, run, template, redirect, request
import ece568helper

@route('/hello')
def hello():
    print 'hello invoked'
    return "Hello World!"

''' Implement Here '''

login_scope = 'profile'
email_scope = 'email'

@route('/login.html')
def login():
    return ece568helper.get_login_html(_addr, _port, _cid, login_scope, email_scope)

@route('/auth.html')
def auth():
    return ece568helper.get_auth_html(_cid)

import oauth2client
from oauth2client import client
import json
import apiclient
from apiclient.discovery import build
from apiclient import errors
import httplib2
from apiclient.http import MediaFileUpload

SCOPES = [
	'https://www.googleapis.com/auth/plus.me','https://www.googleapis.com/auth/drive.file'
]

@route('/drive.html')
def drive():
    # Initialize client object to use Google api.
    # You need client_secrets.json downloaded and stored
    # in the current working directory 
    flow = ece568helper.get_client_object(_addr, _port, SCOPES)
	
    auth_code = request.query.code
    error = request.query.error
	
	# handle authorization fail
    if error:
        return template('drive', result=error) 
	
	# request authorization if needed
    if not auth_code:
        auth_uri = flow.step1_get_authorize_url()
        redirect(auth_uri)
    else:
        credentials = flow.step2_exchange(auth_code)
		
		#store credentials
        ece568helper.output_helper('credentials', credentials)
		
        http_auth = credentials.authorize(httplib2.Http())
		
		# build services
        profile_service = build('plus', 'v1', http=http_auth)
        drive_service = build('drive', 'v2', http=http_auth)
		
		# retrieve and save user profile
        profile = profile_service.people().get(userId='me').execute()
        ece568helper.output_helper('profile', profile)
		
		# upload profile to google drive
        media_body = MediaFileUpload('profile.out', mimetype='text/plain', resumable=True)
        body = {
            'title': 'profile.out',
            'description': 'Profile information excluding email address',
            'mimeType': 'text/plain'
        }
		
        try:
            file = drive_service.files().insert(body=body,media_body=media_body).execute()
            return template('drive', result='success')
        except errors.HttpError, error:
            return template('drive', result='fail')
			
			
    return template('drive', result='fail') 


''' Provided '''

try:
    _addr = sys.argv[1]
    _port = sys.argv[2]
    _cid = sys.argv[3]
    run(host=_addr, port=_port, debug=True)
except IndexError:
    print 'Usage: python ece568app.py <IP address> <Port> <Client ID>'
except SocketServer.socket.error:
    print '[Fail] port ' + str(_port) + ' is already in use\n' 

