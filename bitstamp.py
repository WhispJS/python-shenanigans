import hashlib
import hmac
import time
import requests
import uuid
import sys
import click
if sys.version_info.major >= 3:
    from urllib.parse import urlencode
else:
    from urllib import urlencode

@click.command()
@click.option('--client', help='id of client')
@click.option('--key', help='API key found in user settings')
@click.option('--secret', help='API key secret to confirm authentication')
def get_transactions(client, key, secret):
    encoded_secret = secret.encode();
    timestamp = str(int(round(time.time() * 1000)))
    nonce = str(uuid.uuid4())
    content_type = 'application/x-www-form-urlencoded'
    payload = {'offset': '1'}
    payload_string = urlencode(payload)

    # '' (empty string) in message represents any query parameters or an empty string in case there are none
    message = 'BITSTAMP ' + key + \
        'POST' + \
        'www.bitstamp.net' + \
        '/api/v2/user_transactions/' + \
        '' + \
        content_type + \
        nonce + \
        timestamp + \
        'v2' + \
        payload_string
    message = message.encode('utf-8')
    signature = hmac.new(encoded_secret, msg=message, digestmod=hashlib.sha256).hexdigest()
    headers = {
        'X-Auth': 'BITSTAMP ' +key,
        'X-Auth-Signature': signature,
        'X-Auth-Nonce': nonce,
        'X-Auth-Timestamp': timestamp,
        'X-Auth-Version': 'v2',
        'Content-Type': content_type
    }
    r = requests.post(
        'https://www.bitstamp.net/api/v2/user_transactions/',
        headers=headers,
        data=payload_string
        )
    if not r.status_code == 200:
        raise Exception('Status code not 200')
    string_to_sign = (nonce + timestamp + r.headers.get('Content-Type')).encode('utf-8') + r.content
    signature_check = hmac.new(encoded_secret, msg=string_to_sign, digestmod=hashlib.sha256).hexdigest()
    if not r.headers.get('X-Server-Auth-Signature') == signature_check:
        raise Exception('Signatures do not match')
    return r.content

if __name__ == '__main__':
    try:
        response = get_transactions()
        print(response)
    except Exception as exception:
        print('An error occured that prevented excecution of request. Reason: ' + str(exception))
