import json, sys
from urllib.request import Request, urlopen


def post_json(url, payload):
    data = json.dumps(payload).encode('utf-8')
    req = Request(url, data=data, headers={'Content-Type': 'application/json'})
    try:
        with urlopen(req, timeout=10) as resp:
            body = resp.read().decode('utf-8')
            print(body)
            return json.loads(body)
    except Exception as e:
        print('ERROR', e)
        return None

if __name__ == '__main__':
    if len(sys.argv) < 3:
        print('Usage: python post_file.py <url> <json_file>')
        sys.exit(1)
    url = sys.argv[1]
    path = sys.argv[2]
    with open(path, 'r', encoding='utf-8-sig') as f:
        payload = json.load(f)
    post_json(url, payload)
