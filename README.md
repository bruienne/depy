# depy
Apple DEP module for Python

## Using the module

The most common use of the **DEPy** module is as an import with other code, allowing easy access to DEP requests and replies. The only requirement is that your organization has enrolled with the DEP service either for [business](http://www.apple.com/business/dep/) or for [Education](http://www.apple.com/education/it/dep/). Once completed, the developer wishing to interact with DEP will need to obtain the required server token either by adding a new MDM service or by getting one for an existing registered MDM server. This can be done by asking to be added as a DEP administrator or by having an authorized user obtain the server token file for you. You will also need access to the private P12 cert used to register the MDM server you obtained the server token for. [An in-depth description of this process](https://jamfnation.jamfsoftware.com/article.html?id=359) can be gotten from our good friends at JAMF Software who require the same file to enable DEP with their popular Casper suite. Once obtained, the `smime.p7m` file needs to be processed to obtain the plaintext JSON dictionary for use with the OAuth session token process:

```
# Generate public cert from our private MDM cert
$ openssl pkcs12 -in mdm.p12 -clcerts -nokeys -out publicCert.pem

# Generate private key from our private MDM cert
$ openssl pkcs12 -in mdm.p12 -nocerts -out privateKey.pem

# Decrypt SMIME message into server token using the extracted private key
$ openssl smime  -decrypt -in <MDM server name>_Token_datetimestamp_smime.p7m  -inkey privateKey.pem | grep "{" > stoken.json

# The output will be a JSON dict
$ cat stoken.json

{"consumer_key":"CK_long_hex_string","consumer_secret":"CS_long_hex_string","access_token":"AT_long_hex_string",
"access_secret":"AS_long_hex_string","access_token_expiry":"date_time_stamp_UTC"}
```

Another option for those who have access to the MDM documentation is to use the included `depsim` binary (available for OS X, Linux and Windows) which can be manually configured with OAuth credentials and thus negates the need for access to the DEP portal. All the instructions for configuring and running the DEP simulator service are included with the MDM documentation.

With a valid `stoken.json` file on hand (either for use with the DEP production service or a local `depsim` service) we can now start querying the DEP API by importing the module and loading the JSON file:

```
from depy import DEPy
import sys
import os

# Instantiate a new DEP class
mydep = DEPy()

# Verify we were given a stoken.json file to load
try:
    stoken = sys.argv[1]
except IndexError:
    print 'No path to stoken.json given, aborting.'
    sys.exit(-1)

if not os.path.exists(stoken):
    print 'Path to stoken at %s not found, aborting.' % stoken
    sys.exit(-1)

# Init our DEP connection with data from the stoken file
mydep.init_stoken(stoken)

# Now we can make some queries, let's get our account information
myinfo = mydep.account_info()
# Also get a list of all registered devices
mydevices = mydep.get_devices()

# Print what we got so far
print 'My account info:\n%s' % myinfo
print 'My devices:\n%s' % mydevices

# The 'more_to_follow' key indicates more devices to follow
devicelistcomplete = mydevices.get('more_to_follow')

# The 'cursor' key is used to fetch more devices if needed
devicelistcursor = mydevices.get('cursor')

print 'More devices to follow: %s' % devicelistcomplete
print 'Current cursor index: %s' % devicelistcursor

# Get device info for a single device, by serial number
deviceinfo = mydep.get_device_info('C02SOMESERIAL')

# Print the device info
print 'My device info:\n%s' % deviceinfo

---

Retrieving DEP account info...

Sending account call via get

Token expired, updating
Token generated at 2016-01-11 15:43:58

Sending account call via get

My account info:
{u'facilitator_id': u'facilitator@myorg.com',
 u'org_name': u'My Organization',
 u'org_email': u'depmanager@myorg.com',
 u'server_name': u'My MDM Server'
 u'org_address': u'100 Main Street, Anytown, AA, 12345, United States'
 u'admin_id': u'admin@myorg.com'
 u'org_phone': u'123-456-7890'
 u'server_uuid': u'MYUUID'}

My device list:
{u'cursor': u'MDowOjE0NTI2NTk5Njc3MTQ6MTQ1',
 u'more_to_follow': False,
 u'fetched_until': u'2016-01-13T04:39:27Z',
 u'devices': [{u'device_assigned_date': u'2015-12-15T16:14:33Z',
               u'description': u'MBAIR 13.3 CTO',
               u'color': u'SILVER',
               u'device_family': u'Mac',
               u'device_assigned_by': u'depadmin@myorg.com',
               u'serial_number': u'C02DEADBEEF1',
               u'model': u'MacBook Air',
               u'os': u'OSX',
               u'profile_status': u'empty'}]}

More devices to follow: False

Current cursor index: MDowOjE0NTI2NTk5Njc3MTQ6MTQ1

Sending JSON data to devices via post

My device info:
{u'devices': {u'C02SOMESERIAL': {u'response_status': u'NOT_ACCESSIBLE'}}}

```

As is clear, obtaining data from the DEP API is easy and processing it for use with other systems should be straightforward. The list of implemented commands is:

- account_info
- get_devices
- get_device_info
- sync_devices
- get_profile
- add_profile
- assign_profile
- remove_profile

Full documentation for each DEP command can be found in the `depy.py` code itself. One command that was not implemented due to its destructive and irreversible nature is the `disown` command which permanently and irrevocably removes a device from DEP. Apple recommends that disowning a device is only done through the DEP portal and not programmatically. This seems like a sane approach which is why it is not implemented in DEPy.
