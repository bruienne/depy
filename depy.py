"""
DEPy module by Pepijn Bruienne
(c) 2016 The Regents of the University of Michigan

This module provides a wrapper for the Apple Device Enrollment (DEP) API available to DEP-enrolled customers.

In order to use the API a server token must be obtained through the DEP portal. Instructions on how to obtain the
token can be found here: https://www.afp548.com/2014/03/07/exploring-apples-new-device-enrollment-program/

Once the <MDM server name>_Token_datetimestamp_smime.p7m file is obtained it must be decrypted in order to obtain
the needed consumer_key, consumer_secret, access_token and access_secret information. This can be done as follows:

# Generate public cert:
openssl pkcs12 -in mdm.p12 -clcerts -nokeys -out publicCert.pem

# Generate private key
openssl pkcs12 -in mdm.p12 -nocerts -out privateKey.pem

# Decrypt SMIME message into server token
openssl smime  -decrypt -in <MDM server name>_Token_datetimestamp_smime.p7m  -inkey privateKey.pem | grep "{" > stoken.json

# The output will be a JSON dict that looks something like this:

{"consumer_key":"CK_long_hex_string","consumer_secret":"CS_long_hex_string","access_token":"AT_long_hex_string",
"access_secret":"AS_long_hex_string","access_token_expiry":"date_time_stamp_UTC"}

# The path to this file should be load using the init_stoken() class method:
mydep.init_stoken = '/path/to/your/stoken.json'

After a valid stoken has been loaded the DEPy module will then take care of
requesting and renewing the request token as needed for any DEP API operations.

# Example usage:

    from depy import DEPy

    mydep = DEPy()
    mydep.init_stoken = '/path/to/your/stoken.json'

    accountinfo = mydep.account_info()

    print accountinfo

    Retrieving DEP account info...
    Sending account call via get
    Token expired, updating
    Token generated at 2016-01-11 15:43:58
    Sending account call via get
    {u'facilitator_id': u'facilitator@myorg.com',
     u'org_name': u'My Organization',
     u'org_email': u'depmanager@myorg.com',
     u'server_name': u'My MDM Server'
     u'org_address': u'100 Main Street, Anytown, AA, 12345, United States'
     u'admin_id': u'admin@myorg.com'
     u'org_phone': u'123-456-7890'
     u'server_uuid': u'MYUUID'}

"""

import datetime
import json
import sys

from requests import Request
from requests import Session
from requests_oauthlib import OAuth1Session

class DEPy():

    def __init__(self):
        self.mytoken = None

        # A sample dict for registering a profile
        self.myprofile = dict(org_magic='913FABBB-0032-4E13-9966-D6BBAC900331',
                              is_mandatory=False,
                              url='https://mdm.acmeinc.com/getconfig',
                              is_mdm_removable=False,
                              support_email_address='org-email@example.com',
                              devices=[],
                              support_phone_number='1-555-555-5555',
                              profile_name='Test Profile',
                              allow_pairing=True,
                              department='IT Department',
                              is_supervised=True,
                              await_device_configured=False,
                              skip_setup_items=['Location',
                                                'Restore',
                                                'Android',
                                                'AppleID',
                                                'TOS',
                                                'Siri',
                                                'Diagnostics',
                                                'Biometric',
                                                'Payment',
                                                'Zoom',
                                                'FileVault'])

        # Comment out if testing against depsim instead of production DEP
        self.dep_api_url = "https://mdmenrollment.apple.com/"
        # Uncomment if testing against depsim instead of production DEP
        # self.dep_api_url = "http://localhost:8080/"

        # Setup global auth session token and timestamp
        self.auth_session_token = 'deadbeef'
        self.auth_timestamp = 0

    def init_stoken(self, stoken):
        """
        Loads the required stoken.json file from disk.
        """
        with open(stoken) as data_file:
            self.mytoken = json.load(data_file)

        # Verify that the stoken data is somewhat sane, i.e. has the required
        #   keys and their values start with expected prepends.
        try:
            for k, prefix in (('consumer_secret', 'CS_'),
                              ('access_token', 'AT_'),
                              ('consumer_key', 'CK_'),
                              ('access_secret', 'AS_')):
                if not self.mytoken.get(k).startswith(prefix):
                    print 'Error parsing stoken file: bad value for:\n%s = %s\n' % (k, self.mytoken[k])
                    sys.exit(-1)

        except AttributeError:
            print 'Error parsing stoken file: missing key for:\n%s\n' % (k)
            sys.exit(-1)

        # Set the required OAuth1 keys from the source stoken
        self.oauth = OAuth1Session(client_key=self.mytoken['consumer_key'],
                                   client_secret=self.mytoken['consumer_secret'],
                                   resource_owner_key=self.mytoken['access_token'],
                                   resource_owner_secret=self.mytoken['access_secret'],
                                   realm='ADM')


    def dep_prep(self, query, method, authsession=None, token=None, params=False):
        """
        Sets up common headers for DEP commands using the 'requests' Request
        class to combine our auth token, required headers and other data
        to generate a correct HTTP request to be sent to the DEP API.

        Required parameters:
            - query (The API request to use)
            - method (The HTTP method to use: GET/PUT/POST)
            - token (The auth session token retrieved by get_auth_token())
        Optional parameters:
            - authsession (expects an OAuth1Session instance)
            - params (query string to send instead of JSON data)
        """
        req = Request(method, self.dep_api_url + query)
        prep = None

        # Check whether we're requesting an auth session token or doing a regular
        # API call with DEP.
        if authsession:
            prep = authsession.prepare_request(req)
        # Regular API calls require the X-ADM-Auth-Session header to be set
        elif token:
            prep = req.prepare()
            prep.headers['X-ADM-Auth-Session'] = token
        # If we received no token or token is None we have a problem, halt.
        else:
            print "No token found, we must exit now..."
            sys.exit(-1)

        # Common required headers for DEP API calls, we use v2 as v1 is deprecated
        prep.headers['X-Server-Protocol-Version'] = '2'

        # A few (or just one) calls use a query string instead of JSON so we skip
        # setting the Content-Type header for those.
        if not params:
            prep.headers['Content-Type'] = 'application/json;charset=UTF8'

        return prep


    def get_auth_token(self):
        """
        Retrieves an auth_session_token using DEP server token data prepared as an
        OAuth1Session() instance earlier on.
        """
        # Retrieve session auth token
        get_session = self.dep_prep('session', 'get', authsession=self.oauth)
        response = self.oauth.send(get_session)

        # Extract the auth session token from the JSON reply
        token = response.json()['auth_session_token']

        # The token happens to contain the UNIX timestamp of when it was generated
        # so we save it for later reference.
        timestamp = token[:10]

        # Roll a human-readable timestamp as well.
        ts_readable = datetime.datetime.fromtimestamp(
                      int(timestamp)).strftime(
                      '%Y-%m-%d %H:%M:%S')

        print "Token generated at %s" % ts_readable

        return token, timestamp


    def send_request(self, endpoint, method, jsondata=None, params=None):
        """
        Common function that all individual DEP commands are passed through,
        prepped (via dep_prep()), sent to the DEP API and relays responses back to
        the caller.

        Required parameters:
            - endpoint (The DEP API endpoint for a specific query)
            - method (The HTTP method to use for the query - GET/POST/PUT)

        Optional parameters:
            - jsondata (Any JSON data required for the API query)
            - params (Any URL query parameters required for the API query)
        """
        # We might need to update the auth_session_token and auth_timestamp vars at
        # some point during the interaction with the DEP API so we enable them as
        # globals so that all future calls have access to their updated values.
        # global auth_session_token
        # global auth_timestamp

        s = Session()

        # Check whether we received JSON data as part of the query, in which case
        # we include it in the Session.request() call using the 'json' var.
        if jsondata:
            print "Sending JSON data to %s via %s" % (endpoint, method)
            prepped = self.dep_prep(endpoint, method, token=self.auth_session_token)
            response = s.request(method=prepped.method,
                                 url=prepped.url,
                                 headers=prepped.headers,
                                 json=jsondata)

        # Check whether we received HTTP query data, in which case we need to
        # include it in the Session.request() call using the 'params' var.
        elif params:
            print "Sending query string %s to %s via %s" % (params, endpoint, method)
            prepped = self.dep_prep(endpoint, method, token=self.auth_session_token, params=True)
            response = s.request(method=prepped.method,
                                 url=prepped.url,
                                 headers=prepped.headers,
                                 params=params)

        # If we got neither JSON or query parameters we can use the less involved
        # Session.send() method instead.
        else:
            print "Sending %s call via %s" % (endpoint, method)
            prepped = self.dep_prep(endpoint, method, token=self.auth_session_token)
            response = s.send(prepped)

        # Check the status code returned in the response, if it's 401 or 403 our
        # auth session expired or wasn't accepted so we request a new one and retry
        # the same HTTP request again. Otherwise we move on.
        if response.status_code == 401 or response.status_code == 403:
            print "Token expired, updating"
            self.auth_session_token, self.auth_timestamp = self.get_auth_token()
            return self.send_request(endpoint, method, jsondata=jsondata, params=params)
        else:
            # Try to parse the response as JSON since the majority of responses are
            # formatted as JSON. If that fails we return the raw content.
            # The caller will have to implement doing something useful with the
            # returned content in either case.
            try:
                return response.json()
            except ValueError:
                return response.content


    def account_info(self):
        """
        Retrieve DEP account info.
        Returns a dict.

        Example dict:
        {
         'server_name' : 'My Server',
         'server_uuid' : '8d515859-83db-479a-bdbf-a02b08ec35b4',
         'admin_id' : 'admin@myorg.com',
         'facilitator_id' : 'facilitator@myorg.com',
         'org_name' : 'My Organization',
         'org_phone' : '555-123-4567',
         'org_email' : 'orgadmin@myorg.com',
         'org_address': '100 Main Street, Anytown, AK, 12345'
         }
        """

        print "Retrieving DEP account info..."
        return self.send_request('account', 'get')


    def get_devices(self, cursor=None, limit=None):
        """
        Retrieves all registered devices.
        Returns a dict.
        Optional parameters:
            - cursor (Hex string indicating starting point for the request)
            - limit (Limits returned devices in query to the provided number (100-1000))

        Example dict:
        {
            'cursor': 'cmxkd2lkZSBEZXZlbG9wZXIgUmVsYXRpb25zMUQwQgYDVQQDDDtBcHBsZSBXb3Jsadf',
            'more_to_follow': False,
            'fetched_until': '2015-12-17T20:30:34Z',
            'devices': [
                        {
                         'device_assigned_date': '2015-12-15T16:14:33Z',
                         'description': 'MBAIR 13.3 CTO',
                         'color': 'SILVER',
                         'device_family': 'Mac',
                         'device_assigned_by': 'admin@myorg.com',
                         'serial_number': 'C02AB12CDEFG',
                         'model': 'MacBook Air',
                         'os': 'OSX',
                         'profile_status': 'empty'
                        },
                        {
                         'device_assigned_date': '2015-12-15T16:25:22Z',
                         'description': 'MAC PRO 3.5-6C/D500/16GB/256GB-USA',
                         'color': 'BLACK',
                         'device_family': 'Mac',
                         'device_assigned_by': 'admin@myorg.com',
                         'serial_number': 'F5ABC0DEF123',
                         'model': 'MAC PRO 3.5-6C/D500/16GB/256GB-USA',
                         'os': 'OSX',
                         'profile_status': 'empty'
                        }
                    ]
        }
        """

        print "Retrieving devices..."
        return self.send_request('server/devices', 'post')


    def get_device_info(self, devices):
        """
        Calls /devices API endpoint to retrieve info on specific devices.
        Requires a dict with a 'devices' key containing a list of serial numbers.
        Returns a dict.

        Example query data:
            {'devices': ['C8TJ500QF1MN', 'B7CJ500QF1MA']}
        """
        if type(devices) is not dict:
            if type(devices) is str:
                devices = {'devices': [ devices ]}
            elif type(devices) is list:
                devices = {'devices': devices}
            else:
                print 'Provided device info is neither dict, list or string, aborting.'
                sys.exit(-1)

        result = self.send_request('devices', 'post', jsondata=devices)

        return result


    def sync_devices(self, scope):
        """
        Calls /devices API endpoint to sync registered devices starting at a
        specific point in the DEP database via the cursor key. The cursor key is
        sent with the results of the get_devices() call and should be saved to
        allow for syncing devices since the last time a full list was obtained.
        An optional 'limit' key may be provided to chunk sync results if many
        devices are expected to be returned, saving the cursor position inbetween
        calls.
        Returns a dict.

        Requires a dict with the required 'cursor' (string) and optional 'limit'
        (int) keys.

        Example scope query dict:
            {'cursor': 'MDowOjE0NTI1NjIxMDczOTQ6MTQ1MjU2MjEwN',
             'limit': 100}
        """
        result = self.send_request('devices/sync', 'post', jsondata=scope)

        return result


    def get_profile(self, profileuuid):
        """
        Retrieve profile by UUID.
        Required parameters (as dict key(s)):
            - profile_uuid
        Returns a dict.

        Example profile query dict:
        {
         'profile_uuid': '7805ed84b70463b572301dff80aa867f',
         'profile_name': 'My Org Profile',
         'url':'https://mdm.myorg.com/myconfig',
         'is_supervised':false,
         'allow_pairing':true,
         'is_mandatory':false,
         'await_device_configured':false,
         'is_mdm_removable':false,
         'department': 'My Org IT Department',
         'org_magic': 'B6E16EE4-EC99-46B7-B8A5-FD1E573FCBCE',
         'support_phone_number': '1-555-123-4567',
         'support_email_address': 'support@myorg.com',
         'anchor_certs':[
            'nIKHpcGZO7iXNfkGJ5GhY8y4hCOs4gOa+eLieCts+vtwbNao45poSYG3msdz6jCC...'
         ],
         'supervising_host_certs:[
              'Ai4GCSqGSIb3DQEHATAdBglghkgBZQMEAQIEEKZenLwPdH3IzEoWplB+36CAggIA...'
          ],
         'skip_setup_items':[
                                'Location',
                                'AppleID',
                                'TOS',
                                'Diagnostics',
                                'Zoom',
                                'FileVault'
                            ]
        }
        """

        return self.send_request('profile', 'get', params={'profile_uuid': profileuuid})


    def add_profile(self, profile):
        """
        Registers a new profile with the DEP service.
        Takes a dict as parameter.
        Returns a dict.

        Required dict keys are:
        - profile_name
        - url
        - org_magic

        Example query add_profile dict:
        myprofile = {
                    'org_magic': '913FABBB-0032-4E13-9966-D6BBAC900331',
                    'is_mandatory': False,
                    'url': 'https://mdm.acmeinc.com/getconfig',
                    'is_mdm_removable': False,
                    'support_email_address': 'org-email@example.com',
                    'devices': [],
                    'support_phone_number': '1-555-555-5555',
                    'profile_name': 'Test Profile',
                    'allow_pairing': True,
                    'department': 'IT Department',
                    'is_supervised': True,
                    'await_device_configured': False,
                    'skip_setup_items': ['Location',
                                         'Restore',
                                         'Android',
                                         'AppleID',
                                         'TOS',
                                         'Siri',
                                         'Diagnostics',
                                         'Biometric',
                                         'Payment',
                                         'Zoom',
                                         'FileVault']}
            """
        result = self.send_request('profile', 'post', jsondata=profile)

        return result


    def remove_profile(self, devices):
        """
        Calls /devices API endpoint to remove profile assignments for specific
        devices.
        Returns a dict.

        Requires a dict with a 'devices' key containing a list of serial numbers
        as query data.

        Example query data:
            {'devices': ['C8TJ500QF1MN', 'B7CJ500QF1MA']}
        """
        result = self.send_request('profile/devices', 'delete', jsondata=devices)

        return result


    def assign_profile(self, profileassignment):
        """
        Calls /profile/devices API endpoint to assign a profile to devices.
        Requires a dict with a 'devices' key that has a list of devices to assign to
        and a 'profile_uuid' key containing the UUID assigned to the profile
        when registering it through the /profile endpoint.
        Returns a dict.

        Example assign_profile dict:
            {'devices': ['C8TJ500QF1MN', 'B7CJ500QF1MA'],
             'profile_uuid': '88fc4e378fea4021a94b2d7268fbf767'}
        """
        result = self.send_request('profile/devices',
                              'post',
                              jsondata=profileassignment)

        return result
