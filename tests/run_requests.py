import json
import sys
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
    # Simple interactive helper: reads a JSON object from argv[1] and posts to argv[2]
    if len(sys.argv) < 3:
        print('Usage: python run_requests.py <url> <json_payload_string>')
        sys.exit(1)
    url = sys.argv[1]
    payload = json.loads(sys.argv[2])
    post_json(url, payload)
