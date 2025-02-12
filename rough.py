# PingID python module
# compatible with python 2.7
import json
import base64
import arrow
import requests
import jwt
import sys

PROPERTIES_FILE = './pingid.properties'


class PingIDDriver:
    API_VERSION = '4.9.17'

    def __init__(self, properties_file = PROPERTIES_FILE, locale = 'en', verbose = False, verifyTls = True):

        self.locale = locale
        self.verbose = verbose
        self.verifyTls = verifyTls

        with open(properties_file) as f:
            lines = f.readlines()

        self.config = {}
        for line in lines:
            tuple = line.rstrip('\n').split('=', 1)
            if tuple[0] in ('idp_url', 'token', 'org_alias', 'use_base64_key'):
                self.config[tuple[0]] = tuple[1]

        base64_key = self.config.pop('use_base64_key')
        if self.verbose:
            print('{0}Properties{0}\n{1}\n'.format('=' * 20, self.config))

        self.config['key'] = base64.urlsafe_b64decode(base64_key)

        self.jwt_header = {
            'alg': 'HS256',
            'orgAlias': self.config['org_alias'],
            'token': self.config['token']
        }

        self.req_header = {
            'locale': self.locale,
            'orgAlias': self.config['org_alias'],
            'secretKey': self.config['token'],
            'version': self.API_VERSION
        }


    def call(self, end_point, req_body):
        timestamp = arrow.utcnow().format('YYYY-MM-DD HH:mm:ss.SSS')
        self.req_header['timestamp'] = timestamp
        key = self.config['key']

        req_payload = {
            'reqHeader' : self.req_header,
            'reqBody' : req_body
        }

        if self.verbose:
            print('{0}Request{0}\n{1}\n'.format('=' * 20, json.dumps(req_payload, indent=2)))

        url = self.config['idp_url'] + "/" + end_point

        req_jwt = jwt.encode(req_payload, key, algorithm='HS256', headers=self.jwt_header)

        if self.verbose:
            print('{0}Request Payload{0}\n{1}\n'.format('='*20, req_jwt))

        r = requests.post(url, req_jwt, headers={'Content-Type':'application/json'}, verify = self.verifyTls)

        if self.verbose:
            print('Response status: {0}\n'.format(r.status_code))

        if self.verbose:
            print('{0}Response Payload{0}\n{1}\n'.format('='*20, r.content))

        if r.headers['content-type'] == 'application/octet-stream':
            extracted_response = r.text

        else:
            extracted_response = jwt.decode(r.content, key, algorithms=['HS256'])

        if self.verbose:
            print('{0}Response{0}\n{1}\n'.format('='*20, json.dumps(extracted_response, indent=2)))

        return extracted_response

class addUser()

    req_body = {
    'activateUser':sys.argv[1],
    'role':'REGULAR',
    'userName': username,
    }

    pingid = pingid.PingIDDriver(PROPERTIES_FILE, verbose=True)
    response_body = pingid.call('rest/4/adduser/do', req_body)


class getUser()

    req_body = {
    'getSameDeviceUsers':'false',
    'userName': username,
    }

    pingid = pingid.PingIDDriver(PROPERTIES_FILE, verbose=True)
    response_body = pingid.call('rest/4/getuserdetails/do', req_body)

class offlinePairing()

    req_body = {
    'username': username,
    'type':'SMS',
        'pairingData':sms,
    }

    pingid = pingid.PingIDDriver(PROPERTIES_FILE, verbose=True)
    response_body = pingid.call('rest/4/offlinepairing/do', req_body)
    #print(response_body)

