import json
from urllib.request import Request, urlopen

def post(url, payload):
    data = json.dumps(payload).encode('utf-8')
    req = Request(url, data=data, headers={'Content-Type': 'application/json'})
    try:
        resp = urlopen(req, timeout=10)
        body = resp.read().decode('utf-8')
        print('REQUEST:', payload)
        print('RESPONSE:', body)
    except Exception as e:
        print('REQUEST:', payload)
        print('ERROR:', e)

if __name__ == '__main__':
    # CT02
    post('http://127.0.0.1:8000/analyze-contact', {'sender': '+15559876543', 'body': 'Hello, are you available?', 'is_saved_contact': False})

    # CT03
    post('http://127.0.0.1:8000/analyze-contact', {'sender': '++1-800-SECURE', 'body': 'Verify your identity', 'is_saved_contact': False})

    # CT04
    post('http://127.0.0.1:8000/analyze-contact', {'sender': 'MyBank', 'body': 'Your account ending 1234 has a notification', 'is_saved_contact': False})

    # CT05
    post('http://127.0.0.1:8000/analyze-contact', {'sender': '+19990001111', 'body': 'Bank of Example: Your account is locked. Visit https://bank.example/verify', 'is_saved_contact': False})

    # CT06 - build suspicious history
    for i in range(3):
        post('http://127.0.0.1:8000/analyze-contact', {'sender': '+15550000001', 'body': 'You won a prize! Click https://scam.example', 'is_saved_contact': False})
    post('http://127.0.0.1:8000/analyze-contact', {'sender': '+15550000001', 'body': 'You won again! Click https://scam.example', 'is_saved_contact': False})

    # CT07 - normal saved contact many messages
    for msg in ['Are you home?','Did you eat?','Call me.','Where are you?','Come downstairs.']:
        post('http://127.0.0.1:8000/analyze-contact', {'sender': '+15551234567', 'body': msg, 'is_saved_contact': True, 'contact_name': 'Alice'})
