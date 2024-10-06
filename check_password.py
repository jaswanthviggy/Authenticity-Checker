import json
import requests
import hashlib

def handler(event, context):
    body = json.loads(event['body'])
    password = body['password']
    
    # Hashing and API call logic
    sha1password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    first5_char, tail = sha1password[:5], sha1password[5:]
    
    url = f'https://api.pwnedpasswords.com/range/{first5_char}'
    res = requests.get(url)
    count = sum(1 for line in res.text.splitlines() if line.startswith(tail))
    
    return {
        'statusCode': 200,
        'body': json.dumps({'count': count})
    }
