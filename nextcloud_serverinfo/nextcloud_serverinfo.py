import json
import re
import sys
from base64 import b64encode
from optparse import OptionParser

import requests


class BasicAuthToken(requests.auth.AuthBase):

    """
    Requests natively supports basic auth with user-pass params only,
    not with tokens. Uses this class to have token based basic authentication.
    https://stackoverflow.com/a/57497523
    """

    def __init__(self, token: str) -> None:
        self.token = token

    def __call__(self, r):
        authstr = 'Basic ' + \
            b64encode(self.token.encode('utf-8')).decode('utf-8')
        r.headers['Authorization'] = authstr

        return r


parser = OptionParser(
    usage='%prog -u USERNAME -p PASSWORD -H HOSTNAME -s SCOPE')

parser.add_option('-u', dest='user', type='string',
                  help='Username with administrative permissions on the'
                  ' nextcloud server.')
parser.add_option('-p', dest='password', type='string',
                  help='User password')
parser.add_option('-H', dest='hostname', type='string',
                  help='Nextcloud hostname or address (make sure that the'
                  ' server is a trusted domain in the config.php)')
parser.add_option('-P', dest='protocol', choices=['https', 'http'],
                  default='https', help='Protocol (http/https) to use.'
                  ' Default: https')
parser.add_option('-s', dest='scope', choices=[
                  'full', 'system', 'storage', 'shares', 'webserver', 'php',
                  'database', 'activeUsers'],
                  help='Scopes to check: full, system, storage, shares,'
                  ' webserver, php, database, activeUsers')
parser.add_option('-a', dest='api_url', type='string',
                  default='/ocs/v2.php/apps/serverinfo/api/v1/info',
                  help='URL for api. Default:'
                  ' /ocs/v2.php/apps/serverinfo/api/v1/info')

(options, args) = parser.parse_args()

if not options.user:
    parser.error('Username is required, use parameter -u.')
    sys.exit(2)
if not options.password:
    parser.error('Password is required, use parameter -p.')
    sys.exit(2)
if not options.hostname:
    parser.error('Hostname is required, use parameter -H')
    sys.exit(2)
if not options.scope:
    parser.error('Scope is required, use parameter -s.')
    sys.exit(2)

# Validate the hostname given by the user (make sure they do not
# entered a "https://", "http://" or "/")
url_strip = re.compile(r'https?://')
hostname = url_strip.sub('', options.hostname).split('/')[0]

# Validate the api_url
if options.api_url.startswith('/'):
    api_url = options.api_url
else:
    api_url = f'/{options.api_url}'

url = f'{options.protocol}://{hostname}{api_url}?format=json'

response = requests.get(url, auth=BasicAuthToken(
    options.user + ':' + options.password))
json_response = response.json()

try:
    if options.scope == 'full':
        print(json.dumps(json_response, indent=4))
    elif options.scope == 'system':
        print(json.dumps(json_response['ocs']['data']
                         ['nextcloud']['system'], indent=4))
    elif options.scope == 'storage':
        print(json.dumps(json_response['ocs']['data']
                         ['nextcloud']['storage'], indent=4))
    elif options.scope == 'shares':
        print(json.dumps(json_response['ocs']['data']
                         ['nextcloud']['shares'], indent=4))
    elif options.scope == 'webserver':
        print(json.dumps(json_response['ocs']['data']
                         ['server']['webserver'], indent=4))
    elif options.scope == 'php':
        print(json.dumps(json_response['ocs']['data']
                         ['server']['php'], indent=4))
    elif options.scope == 'database':
        print(json.dumps(json_response['ocs']['data']
                         ['server']['database'], indent=4))
    elif options.scope == 'activeUsers':
        print(json.dumps(json_response['ocs']['data']
                         ['activeUsers'], indent=4))
except KeyError:
    print(f'error: JSON response does not contain attribute {options.scope}')
    sys.exit(2)
