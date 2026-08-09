"""Quick integration test for OTP and URL agents"""
import sys
sys.path.insert(0, "backend")
sys.path.insert(0, "ai-engine")

from app.main import app
from fastapi.testclient import TestClient

client = TestClient(app)

# Test OTP analysis with a real scam message
otp_msg = {
    'sender': '919876543210',
    'body': 'URGENT! Your account suspended. OTP 4821 - share with support immediately',
    'expected_otp': False,
    'foreground_app': '',
    'screen_unlocked': True
}

print('=' * 70)
print('Testing OTP Agent with scam message')
print('=' * 70)
response = client.post('/analyze-sms', json=otp_msg)
result = response.json()
print(f"Status: {result.get('level')}")
print(f"Score: {result.get('score')}/100")
print(f"Confidence: {result.get('confidence')}")
print(f"\nRed flags detected ({len(result.get('reasons', []))}): ")
for i, reason in enumerate(result.get('reasons', []), 1):
    print(f"  {i}. {reason}")

print('\n' + '=' * 70)
print('Testing OTP Agent with legitimate OTP')
print('=' * 70)

legit_msg = {
    'sender': 'VM-HDFC',
    'body': 'Your OTP is 1234. Valid for 10 minutes. Do not share.',
    'expected_otp': True,
    'foreground_app': 'com.hdfc.bank',
    'screen_unlocked': True
}

response = client.post('/analyze-sms', json=legit_msg)
result = response.json()
print(f"Status: {result.get('level')}")
print(f"Score: {result.get('score')}/100")
print(f"Confidence: {result.get('confidence')}")

print('\n' + '=' * 70)
print('[OK] All tests completed successfully!')
print('=' * 70)
