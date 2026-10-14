"""
evaluate_precision_recall.py  (EXPANDED DATASET VERSION)

Precision/recall/accuracy evaluation of the FULL pipeline
(POST /analyze-sms -> LangGraph coordinator's final risk_score/status)
against a large labeled set of SMS messages.

WHAT CHANGED vs. THE 22-MESSAGE VERSION
---------------------------------------
* ~160 labeled messages instead of 22, grouped into scenario GROUPS
  (OTP, URL phishing, impersonation, financial scams, Indian-specific
  scams, Hinglish/Hindi, edge cases, adversarial, legit transactional,
  legit personal, legit promo, ...).
* Senders marked "@MOBILE" get a fresh random Indian mobile number per
  request, so per-sender reputation stored in MongoDB from earlier runs
  does not bleed into later results.
* Extra metrics: accuracy, precision, recall, specificity, F1, MCC,
  false-positive rate, false-negative rate, ROC-AUC (threshold-free),
  per-GROUP breakdown, per-status breakdown, threshold sweep (0-100),
  and a full list of every misclassification.
* Optional --repeat N to run the whole set N times (averages out LLM
  randomness), --shuffle to randomize order, --group to run one group,
  --delay to avoid Groq rate limits.

HOW TO RUN
----------
    1. start backend:   uvicorn app.main:app --reload
    2. python evaluate_precision_recall.py
       python evaluate_precision_recall.py --repeat 3 --delay 0.5
       python evaluate_precision_recall.py --group indian_scams
       python evaluate_precision_recall.py --base-url http://host:8000

IMPORTANT NOTE ABOUT THE SEMANTIC FAST-PATH
-------------------------------------------
Your semantic gate learns scam patterns. After a scam template is seen
5+ times it becomes CONFIRMED_SPAM and the pipeline short-circuits.
Running --repeat several times therefore tests the fast-path too, but
the scores of repeated scams may differ from the first run. For a clean
"first-time" measurement, clear the spam_patterns / pattern_events
collections in MongoDB before each run.
"""

import argparse
import csv
import os
import random
import string
import sys
import time
from collections import defaultdict
from pathlib import Path

import requests

DEFAULT_BASE_URL = os.environ.get("SCAMSHIELD_BASE_URL", "http://127.0.0.1:8000")
ANALYZE_URL_PATH = "/analyze-sms"
REQUEST_TIMEOUT = 60
CURRENT_THRESHOLD = 35  # risk_score >= this counts as "predicted scam"

HERE = Path(__file__).resolve().parent
OUT_CSV = HERE / "precision_recall_results.csv"
OUT_GROUP_CSV = HERE / "precision_recall_by_group.csv"


def _random_indian_mobile():
    first = random.choice("6789")
    rest = "".join(random.choices(string.digits, k=9))
    return "+91" + first + rest


# ============================================================================
# DATASET BUILDERS
# S(...) = scam (is_scam=True), L(...) = legitimate (is_scam=False)
# sender "@MOBILE" -> replaced by a fresh random mobile number at runtime
# ============================================================================

TEST_CASES = []


def _add(group, category, is_scam, sender, body, saved=False, name=None):
    TEST_CASES.append({
        "group": group,
        "category": category,
        "is_scam": is_scam,
        "sender": sender,
        "body": body,
        "is_saved_contact": saved,
        "contact_name": name,
    })


def S(group, category, sender, body, saved=False, name=None):
    _add(group, category, True, sender, body, saved, name)


def L(group, category, sender, body, saved=False, name=None):
    _add(group, category, False, sender, body, saved, name)


# ----------------------------------------------------------------------------
# 1. OTP SCAMS  (scam)
# ----------------------------------------------------------------------------
G = "otp_scam"
S(G, "otp_sharing_request", "@MOBILE", "Your OTP is 482913. Please share it with our bank representative to complete verification.")
S(G, "otp_threat", "@MOBILE", "URGENT! Your account will be permanently blocked. Give the OTP 592014 to our representative immediately.")
S(G, "otp_customer_care", "@MOBILE", "Customer care here regarding your refund. Please provide OTP 738291 to process it.")
S(G, "otp_kyc", "@MOBILE", "Your KYC is expiring today. Share the OTP 118820 you just received to avoid account freeze.")
S(G, "otp_wrong_transfer", "@MOBILE", "Sorry sir, I sent Rs 5000 to your number by mistake. Please send me the OTP 664201 so I can reverse it.")
S(G, "otp_sim_swap", "@MOBILE", "To upgrade your SIM to 5G, reply with the OTP 905512 sent to your number.")
S(G, "otp_electricity", "@MOBILE", "Your electricity will be cut tonight. Call our officer and share OTP 337718 to update bill.")
S(G, "otp_prize", "@MOBILE", "Congratulations, you won a gift. Tell us the OTP 441907 to claim it now.")
S(G, "otp_card_block", "@MOBILE", "Your debit card is blocked. Send OTP 201938 to unblock immediately.")
S(G, "otp_refund_upi", "@MOBILE", "Refund of Rs 2,499 pending. Share the 6 digit code 772310 received on your phone to get money back.")
S(G, "otp_insurance", "@MOBILE", "Your insurance policy bonus is ready. Provide verification code 590312 to our agent now.")
S(G, "otp_job", "@MOBILE", "Job interview confirmed. Share OTP 128904 with HR to book your slot.")
S(G, "otp_hinglish", "@MOBILE", "Sir aapka account block ho jayega. Abhi OTP 556231 humein bataiye verification ke liye.")
S(G, "otp_hinglish_2", "@MOBILE", "Aapke account mein refund aaya hai, OTP 310045 share karein turant.")
S(G, "otp_phishing_device", "SECURITY", "Your account was accessed from a new device. Enter OTP 882190 at our secure portal to protect it.")
S(G, "otp_delivery", "@MOBILE", "Courier agent here. Share the delivery OTP 421900 over phone before parcel is returned.")

# ----------------------------------------------------------------------------
# 2. LEGIT OTPs (safe)
# ----------------------------------------------------------------------------
G = "otp_legit"
L(G, "normal_otp", "HDFCBK", "Your OTP is 482913. Valid for 10 minutes. Do not share this OTP with anyone.")
L(G, "normal_otp", "AMAZON", "Your Amazon verification code is 118273. Never share this code with anyone.")
L(G, "normal_otp", "SBIINB", "OTP for your SBI net banking login is 774120. Do not disclose to anyone, including bank staff.")
L(G, "normal_otp", "ICICIB", "123456 is your ICICI Bank OTP for transaction of Rs 1,200. Valid 5 mins. Never share.")
L(G, "normal_otp", "AXISBK", "Use 908172 as your Axis Bank login OTP. Do not share it with anyone.")
L(G, "normal_otp", "PAYTM", "909090 is your Paytm verification code. Do not share it with anyone.")
L(G, "normal_otp", "GOOGLE", "G-501923 is your Google verification code.")
L(G, "normal_otp", "SWIGGY", "Your Swiggy login OTP is 7421. It is valid for 10 minutes.")
L(G, "normal_otp", "UBERIN", "Your Uber code is 4521. Never share this code. Reply STOP to opt out.")
L(G, "normal_otp", "JIOCRE", "Your Jio OTP is 667412. It expires in 10 minutes. Jio never asks for OTP on calls.")
L(G, "normal_otp", "IRCTC", "OTP for IRCTC login is 390481. Do not share with anyone.")
L(G, "normal_otp", "ZOMATO", "Your Zomato verification code is 238841. Valid for 5 minutes.")
L(G, "normal_otp", "UIDAI", "Your Aadhaar OTP is 458102. Valid for 10 minutes. Do not share it with anyone.")
L(G, "normal_otp_hinglish", "HDFCBK", "Aapka OTP 392011 hai. Kisi ke saath share na karein. 10 minute tak valid.")

# ----------------------------------------------------------------------------
# 3. URL PHISHING (scam)
# ----------------------------------------------------------------------------
G = "url_phishing"
S(G, "phishing_bank", "@MOBILE", "Alert - HDFC Bank: Your account will be suspended due to KYC issue. Verify now: http://hdfc-kyc-verify.example/login")
S(G, "phishing_bank_sbi", "@MOBILE", "SBI YONO: Your account is blocked. Update PAN immediately: http://sbi-yono-update.example/pan")
S(G, "phishing_bank_icici", "@MOBILE", "ICICI Bank: Your credit card reward points of Rs 8,640 expire today. Redeem: http://icici-rewards-claim.example/")
S(G, "phishing_bank_axis", "@MOBILE", "Dear Axis customer, your netbanking will be deactivated. Re-verify here: http://axis-secure-login.example/")
S(G, "phishing_delivery", "@MOBILE", "Your parcel is held at customs. Pay the pending fee to release delivery: http://customs-fee-pay.example/")
S(G, "phishing_delivery_2", "@MOBILE", "India Post: Package undelivered due to incomplete address. Update details within 24h: http://indiapost-redeliver.example/")
S(G, "phishing_delivery_3", "@MOBILE", "FedEx: Your shipment is on hold, pay Rs 49 reshipment fee: http://fedex-pay-fee.example/")
S(G, "phishing_prize", "@MOBILE", "Congratulations! You've won a lucky draw prize of Rs 5,00,000. Claim now: http://bit.ly/luckyclaim99")
S(G, "phishing_tax", "@MOBILE", "Income Tax Dept: Refund of Rs 15,320 approved. Submit bank details: http://incometax-refund-claim.example/")
S(G, "phishing_electricity", "@MOBILE", "Dear consumer, your electricity connection will be disconnected tonight 9:30pm. Pay pending bill: http://bses-bill-pay.example/")
S(G, "phishing_fastag", "@MOBILE", "Your FASTag is deactivated. Recharge immediately to avoid penalty: http://fastag-recharge-now.example/")
S(G, "phishing_aadhaar", "@MOBILE", "Your Aadhaar is suspended. Link with PAN now: http://aadhaar-pan-link.example/")
S(G, "phishing_upi", "@MOBILE", "Rs 2,000 received on PhonePe. To accept, enter your UPI PIN here: http://phonepe-receive.example/")
S(G, "phishing_netflix", "@MOBILE", "Netflix: Your payment failed. Update billing within 24 hours or account will be closed: http://netflix-billing-update.example/")
S(G, "phishing_amazon", "@MOBILE", "Amazon: Suspicious order of iPhone 15 placed from your account. Cancel here: http://amazon-order-cancel.example/")
S(G, "phishing_whatsapp", "@MOBILE", "WhatsApp Gold subscription expired. Renew now: http://whatsapp-gold-renew.example/")
S(G, "phishing_shortlink", "@MOBILE", "Your account has a pending notice. Check: http://tinyurl.com/acc-notice-91")
S(G, "phishing_cowin", "@MOBILE", "Govt scheme: Rs 3,000 subsidy credited soon. Register with bank details: http://pm-subsidy-register.example/")
S(G, "phishing_telecom", "@MOBILE", "Airtel: Your SIM will be disconnected in 2 hours due to incomplete KYC. Update: http://airtel-kyc-update.example/")
S(G, "phishing_loan_app", "@MOBILE", "Pre-approved loan of Rs 3,00,000 at 0% interest. Submit Aadhaar & PAN: http://instant-loan-approve.example/apply")
S(G, "phishing_traffic_challan", "@MOBILE", "E-challan of Rs 1,000 issued on your vehicle. Pay within 24h to avoid court notice: http://echallan-pay.example/")
S(G, "phishing_ip_ssl", "@MOBILE", "Your account will be locked. Login at http://192.168.44.12/secure to verify.")

# ----------------------------------------------------------------------------
# 4. LEGIT MESSAGES WITH URLs (safe)
# ----------------------------------------------------------------------------
G = "url_legit"
L(G, "legit_delivery", "AMZN", "Your package is out for delivery and should arrive today. Track it: https://www.amazon.in/track/1234567890")
L(G, "legit_delivery_2", "BLUEDT", "Your Blue Dart shipment is out for delivery. Track: https://www.bluedart.com/tracking")
L(G, "legit_flight", "INDIGO", "Your IndiGo web check-in is open for flight 6E-204. Check in: https://www.goindigo.in/web-check-in.html")
L(G, "legit_ecom_order", "FLIPKT", "Your Flipkart order has shipped. Details: https://www.flipkart.com/account/orders")
L(G, "legit_bank_netbanking", "HDFCBK", "Your HDFC Bank statement is ready. Login at https://netbanking.hdfcbank.com to view.")
L(G, "legit_govt_dl", "DGLOCK", "Your driving licence is available in DigiLocker. View: https://www.digilocker.gov.in")
L(G, "legit_github", "GITHUB", "Sign in to GitHub at https://github.com/login")
L(G, "legit_google_acct", "GOOGLE", "Manage your Google account at https://accounts.google.com/")
L(G, "legit_paypal", "PAYPAL", "Visit PayPal securely at https://www.paypal.com/signin")
L(G, "legit_microsoft", "MSFT", "Your Microsoft 365 subscription renews on 5 Nov. Manage at https://account.microsoft.com")
L(G, "legit_apple", "APPLE", "Your Apple ID receipt is available at https://support.apple.com")
L(G, "legit_railway", "IRCTCI", "PNR 4521896723 confirmed. Check status: https://www.indianrail.gov.in/enquiry/PNR")
L(G, "legit_zoom", "@MOBILE", "Join my Zoom meeting at 4pm: https://zoom.us/j/9876543210", saved=True, name="Anita")
L(G, "legit_friend_link", "@MOBILE", "Check out this article: https://www.thehindu.com/news/national/", saved=True, name="Rohan")
L(G, "legit_swiggy", "SWIGGY", "Your Swiggy order is on the way! Track live: https://www.swiggy.com/track")
L(G, "legit_uber", "UBERIN", "Your Uber receipt for Rs 245 is available: https://www.uber.com/in/en/")

# ----------------------------------------------------------------------------
# 5. IMPERSONATION / CONTACT-BASED SCAMS (scam)
# ----------------------------------------------------------------------------
G = "impersonation"
S(G, "impersonation_bank", "@MOBILE", "SBI: Your account will be blocked. Send your card number and CVV immediately to avoid penalty.")
S(G, "impersonation_hdfc", "@MOBILE", "HDFC Bank: Account suspended due to KYC. Send card number, expiry and CVV now.")
S(G, "impersonation_rbi", "@MOBILE", "RBI notice: Your account is under investigation. Transfer funds to the safe account 4455667788 immediately.")
S(G, "impersonation_police", "@MOBILE", "This is Cyber Crime Police. A case is registered on your Aadhaar. Pay Rs 25,000 now to avoid arrest.")
S(G, "impersonation_courier_drugs", "@MOBILE", "FedEx: A parcel in your name contains illegal items. Contact CBI officer immediately, do not tell anyone.")
S(G, "impersonation_ceo", "@MOBILE", "Hi, this is your CEO. I am in a meeting, buy 5 Amazon gift cards of Rs 5,000 and send me the codes urgently.")
S(G, "impersonation_tech_support", "@MOBILE", "Microsoft Support: Your computer is infected. Call 1800-xxx-9981 immediately and install AnyDesk.")
S(G, "impersonation_trai", "@MOBILE", "TRAI: Your number will be disconnected in 2 hours due to illegal activity. Press 9 to talk to officer.")
S(G, "impersonation_electric_board", "@MOBILE", "Electricity Board: Previous bill unpaid. Connection disconnects tonight. Call 98xxxxxx12 officer now.")
S(G, "impersonation_customs", "@MOBILE", "Customs Dept: Your gift from abroad is held. Pay Rs 18,000 clearance fee via UPI to release.")

# ----------------------------------------------------------------------------
# 6. FINANCIAL / MONEY-REQUEST SCAMS (scam)
# ----------------------------------------------------------------------------
G = "financial_scam"
S(G, "financial_scam", "@MOBILE", "URGENT! Send Rs 20,000 to this UPI ID immediately or face legal action.")
S(G, "prize_secrecy", "@MOBILE", "You have won a prize. Don't tell anyone about this, just transfer the small processing fee now.")
S(G, "emergency_money", "@MOBILE", "I've had an accident, send 20000 rupees urgently, don't call me right now.", saved=True, name="Rahul")
S(G, "emergency_money_2", "@MOBILE", "Mom this is my new number, phone is broken. Need Rs 15,000 urgently for hospital, send to this account.")
S(G, "emergency_money_3", "@MOBILE", "Bro stuck at airport, wallet lost. Please send 8000 on GPay right now, will return tonight. Don't tell Dad.", saved=True, name="Vikas")
S(G, "investment_crypto", "@MOBILE", "Earn Rs 50,000 daily with our crypto trading signals. 100% guaranteed returns. Join now: http://bit.ly/cryptoprofit7")
S(G, "investment_stock", "@MOBILE", "Join our VIP stock tips group. Invest Rs 10,000 and get Rs 1 lakh in 7 days. Guaranteed profit.")
S(G, "task_scam", "@MOBILE", "Earn Rs 3,000 per day by liking YouTube videos. Part-time work from home. Message HR on Telegram now.")
S(G, "job_fee", "@MOBILE", "You are selected for a job at Amazon. Pay Rs 2,500 registration fee to confirm your offer letter.")
S(G, "loan_advance_fee", "@MOBILE", "Your loan of Rs 5 lakh is approved. Pay Rs 4,999 insurance fee first to release the amount.")
S(G, "romance_scam", "@MOBILE", "Hi dear, I am Dr. Sarah from UK. I want to send you a gift parcel, just pay Rs 12,000 customs charges.")
S(G, "sim_card_charge", "@MOBILE", "Pay Rs 10 to this UPI ID to activate your free recharge of Rs 599. Valid today only.")
S(G, "inheritance", "@MOBILE", "Dear beneficiary, you are entitled to USD 4.5 million inheritance. Send your bank details and Rs 20,000 fee.")
S(G, "digital_arrest", "@MOBILE", "You are under digital arrest. Stay on video call and do not inform anyone. Transfer Rs 1,50,000 to RBI verification account.")
S(G, "kbc_lottery", "@MOBILE", "KBC Lottery: Your number won Rs 25 lakh. Contact manager on WhatsApp and pay processing fee to claim.")

# ----------------------------------------------------------------------------
# 7. SPAM (risky but not targeted)  (scam / flagged)
# ----------------------------------------------------------------------------
G = "spam"
S(G, "spam_loan", "@MOBILE", "Get instant personal loan up to 5 lakhs with zero documentation! Apply now: http://bit.ly/instaloan")
S(G, "spam_lottery", "@MOBILE", "CONGRATS! Your number has won our lucky draw. Claim your gift now: http://bit.ly/luckydraw2")
S(G, "spam_casino", "@MOBILE", "Play teen patti and win Rs 10,000 today! Sign up bonus Rs 500: http://bit.ly/teenwin")
S(G, "spam_betting", "@MOBILE", "IPL betting tips 100% sure. Join our paid group and win big daily: http://bit.ly/iplsure")
S(G, "spam_adult", "@MOBILE", "Hot singles in your area waiting to chat with you. Click now: http://bit.ly/hotchat18")
S(G, "spam_pharma", "@MOBILE", "Buy medicines without prescription at 80% off. Order now: http://bit.ly/cheaprx")
S(G, "spam_followers", "@MOBILE", "Get 10,000 Instagram followers for just Rs 99. Limited offer: http://bit.ly/getfollow")
S(G, "spam_credit_card", "@MOBILE", "Pre-approved credit card, no income proof needed. Reply YES to get it today.")

# ----------------------------------------------------------------------------
# 8. HINGLISH / HINDI SCAMS (scam)
# ----------------------------------------------------------------------------
G = "hinglish_scam"
S(G, "hinglish_kyc", "@MOBILE", "Dear customer aapka KYC pending hai, account aaj band ho jayega. Abhi update karein: http://bit.ly/kycnow")
S(G, "hinglish_lottery", "@MOBILE", "Badhai ho! Aapne 5 lakh ka inaam jeeta hai. Claim karne ke liye turant click karein: http://bit.ly/inaam5")
S(G, "hinglish_police", "@MOBILE", "Aapke naam par case darj hua hai. Turant 20000 rupaye bhejiye warna giraftari hogi.")
S(G, "hinglish_job", "@MOBILE", "Ghar baithe 5000 rupaye daily kamayein. Abhi registration fees 500 UPI par bhejein.")
S(G, "hinglish_electric", "@MOBILE", "Aapka bijli connection aaj raat kat jayega. Turant is number par call karein aur bill update karein.")
S(G, "hindi_script_kyc", "@MOBILE", "प्रिय ग्राहक, आपका बैंक खाता आज बंद हो जाएगा। तुरंत KYC अपडेट करें: http://bit.ly/kyc-hindi")
S(G, "hindi_script_prize", "@MOBILE", "बधाई हो! आपने 10 लाख रुपये का इनाम जीता है। अभी क्लेम करें: http://bit.ly/inaam10")

# ----------------------------------------------------------------------------
# 9. LEGIT TRANSACTIONAL / BANK / UTILITY (safe)
# ----------------------------------------------------------------------------
G = "legit_transactional"
L(G, "legit_bank_notice", "HDFCBK", "Your HDFC Bank account balance as of today is Rs 12,500.")
L(G, "bank_debit", "SBIINB", "Rs 1,250.00 debited from A/c XX4521 on 10-Oct-26 at AMAZON. Avl bal Rs 22,340.")
L(G, "bank_credit", "ICICIB", "Rs 45,000.00 credited to your A/c XX7712 on 05-Oct-26. Salary credit. Avl bal Rs 61,200.")
L(G, "bank_upi", "AXISBK", "Rs 350 paid via UPI to SWIGGY. UPI Ref 4123987612. If not you, call 1800-xxx-xxxx.")
L(G, "bank_emi", "HDFCBK", "Your EMI of Rs 8,450 for loan A/c XX9021 is due on 05-Nov. Please maintain sufficient balance.")
L(G, "bank_fraud_warning", "SBIINB", "SBI never asks for your PIN, OTP, or card details over call or SMS. Report fraud at 1930.")
L(G, "bank_cc_statement", "ICICIB", "Your ICICI credit card statement of Rs 14,320 is generated. Due date 25-Oct. Pay via the iMobile app.")
L(G, "legit_reminder", "@MOBILE", "Reminder: your electricity bill of Rs 1,240 is due on the 5th.")
L(G, "legit_utility_paid", "BSESDL", "Your electricity bill payment of Rs 1,240 was received. Thank you.")
L(G, "legit_gas", "INDGAS", "Your LPG cylinder booking is confirmed. Delivery expected within 2 days.")
L(G, "legit_recharge", "AIRTEL", "Recharge of Rs 299 successful. Validity 28 days. Thank you for choosing Airtel.")
L(G, "legit_data_usage", "JIOCRE", "You have used 80% of your daily data quota. Visit MyJio app for more.")
L(G, "legit_insurance", "LICIND", "Your LIC premium of Rs 6,200 is due on 15-Nov. Pay via the LIC Customer Portal or nearest branch.")
L(G, "legit_flight", "INDIGO", "Your flight 6E-204 on 14 Oct departs at 06:15 from Mumbai T2. Web check-in is open.")
L(G, "legit_train", "IRCTCI", "Your ticket PNR 4521896723 is confirmed. Coach B2 seat 34. Happy journey.")
L(G, "legit_appointment", "@MOBILE", "Your appointment is confirmed for tomorrow at 10am.")
L(G, "legit_hospital", "APOLLO", "Reminder: your appointment with Dr. Mehta is on 14-Oct at 11:30 AM at Apollo Clinic.")
L(G, "legit_school", "SCHOOL", "Parent-teacher meeting is scheduled on Saturday 10am. Kindly attend.")
L(G, "legit_delivery_otp", "AMAZON", "Your delivery OTP is 4821. Share it with the delivery agent only when he hands over your package.")
L(G, "legit_swiggy_delivered", "SWIGGY", "Your Swiggy order has been delivered. Enjoy your meal!")
L(G, "legit_cab", "OLACAB", "Your driver Ramesh (MH02AB1234) will arrive in 3 mins. Share OTP 4417 to start the ride.")

# ----------------------------------------------------------------------------
# 10. LEGIT PERSONAL / SAVED CONTACT (safe)
# ----------------------------------------------------------------------------
G = "legit_personal"
L(G, "legit_saved_contact", "@MOBILE", "Hey, are we still meeting at 6?", saved=True, name="Priya")
L(G, "legit_casual", "@MOBILE", "Good morning! Hope you have a great day.", saved=True, name="Mom")
L(G, "legit_family", "@MOBILE", "Mom, I'll be home a bit late tonight, don't wait up for dinner.", saved=True, name="Mom")
L(G, "legit_friend_plan", "@MOBILE", "Movie at 8 tonight? I'll book the tickets.", saved=True, name="Arjun")
L(G, "legit_friend_money", "@MOBILE", "Thanks for lunch yesterday! I'll send you my share of Rs 450 on GPay in the evening.", saved=True, name="Neha")
L(G, "legit_colleague", "@MOBILE", "Meeting moved to 3pm, conference room B. Please bring the Q3 report.", saved=True, name="Sandeep")
L(G, "legit_birthday", "@MOBILE", "Happy birthday!! Party at my place on Saturday, don't be late!", saved=True, name="Kavya")
L(G, "legit_unknown_hello", "@MOBILE", "Hi, this is Suresh from the society office. The water supply will be off tomorrow 10am-2pm.")
L(G, "legit_unknown_courier", "@MOBILE", "Hello sir, I'm outside your gate with your parcel. Please come down.")
L(G, "legit_landlord", "@MOBILE", "Hi, rent for October is due. Please transfer to the usual account whenever convenient.", saved=True, name="Landlord")
L(G, "legit_hinglish_friend", "@MOBILE", "Bhai kal ka match dekhne chalein? Main snacks le aata hoon.", saved=True, name="Aman")
L(G, "legit_hinglish_family", "@MOBILE", "Beta khana kha liya? Aaj jaldi ghar aa jana.", saved=True, name="Papa")
L(G, "legit_hindi_script", "@MOBILE", "शुभ प्रभात! आज शाम को घर आ रहे हो ना?", saved=True, name="Bhaiya")
L(G, "legit_emoji", "@MOBILE", "Congrats on the new job! 🎉🎉 Let's celebrate this weekend 🍕", saved=True, name="Pooja")
L(G, "legit_short", "@MOBILE", "ok", saved=True, name="Rahul")
L(G, "legit_short_2", "@MOBILE", "Call me when free.", saved=True, name="Rahul")

# ----------------------------------------------------------------------------
# 11. LEGIT PROMOTIONAL (safe, false-positive stress test)
# ----------------------------------------------------------------------------
G = "legit_promo"
L(G, "legit_promo", "MYNTRA", "Flat 40% off on your favorite brands this weekend only. Shop now on the Myntra app.")
L(G, "legit_promo_2", "AMAZON", "Great Indian Festival starts tomorrow! Up to 70% off on electronics. Shop on the Amazon app.")
L(G, "legit_promo_3", "ZOMATO", "Hungry? Get 50% off up to Rs 100 on your next order with code WELCOME50.")
L(G, "legit_promo_4", "NYKAAA", "Your Nykaa wishlist item is back in stock! Grab it before it's gone.")
L(G, "legit_promo_bank", "HDFCBK", "Pre-approved personal loan offer for you. Visit your nearest HDFC Bank branch or login to NetBanking to know more. T&C apply.")
L(G, "legit_promo_telecom", "AIRTEL", "Recharge with Rs 399 and get unlimited calls with 2GB/day for 28 days. Recharge on the Airtel Thanks app.")
L(G, "legit_promo_cc", "ICICIB", "Enjoy 5% cashback on your ICICI Credit Card this festive season on select merchants. T&C apply.")
L(G, "legit_promo_urgent_words", "BIGBSK", "Hurry! Last day of our sale. Offer ends tonight at midnight. Visit your nearest BigBasket store.")

# ----------------------------------------------------------------------------
# 12. ADVERSARIAL / HARD LEGIT (safe but contain scary words)
# ----------------------------------------------------------------------------
G = "adversarial_legit"
L(G, "legit_urgent_wording", "HDFCBK", "Urgent: your credit card payment of Rs 14,320 is due tomorrow. Pay via the HDFC app to avoid late fee.")
L(G, "legit_account_blocked_real", "SBIINB", "Your SBI debit card has been blocked as per your request. Visit your nearest branch to get a new card.")
L(G, "legit_kyc_branch", "HDFCBK", "Your KYC documents are due for periodic update. Please visit your nearest branch with ID proof. Do not click on links shared by unknown persons.")
L(G, "legit_prize_real", "FLIPKT", "Congratulations! You won a Rs 100 Flipkart gift voucher in our contest. Voucher auto-applied to your account.")
L(G, "legit_security_alert", "GOOGLE", "Security alert: new sign-in on Pixel 8. If this was you, no action needed.")
L(G, "legit_police_real", "MUMPOL", "Traffic Police Mumbai: Reminder to renew your PUC certificate. Details at https://mahatransport.gov.in")
L(G, "legit_refund_real", "AMAZON", "Your refund of Rs 799 for order #402-123 has been initiated and will reflect in 3-5 business days.")
L(G, "legit_loan_real", "BAJAJF", "Your loan application is under review. Our representative will contact you within 2 working days.")
L(G, "legit_otp_warning", "AXISBK", "Never share your OTP, PIN, or CVV with anyone. Axis Bank will never ask for these.")
L(G, "legit_account_suspend_real", "NETFLX", "Your Netflix plan renews tomorrow. Make sure your payment method is up to date in Account settings.")

# ----------------------------------------------------------------------------
# 13. EDGE CASES / OBFUSCATION
# ----------------------------------------------------------------------------
G = "edge_cases"
S(G, "obfuscated_spacing", "@MOBILE", "Y0ur acc0unt wi11 be bl0cked. Upd@te KYC n0w: http://kyc-upd8.example/")
S(G, "uppercase_scam", "@MOBILE", "URGENT!!! YOUR BANK ACCOUNT IS BLOCKED. CLICK HERE TO VERIFY: http://bank-verify-now.example/")
S(G, "mixed_emoji_scam", "@MOBILE", "🎁🎁 You have WON iPhone 15 🎉 Claim FREE here 👉 http://bit.ly/freeiphone15")
S(G, "long_scam", "@MOBILE", "Dear valued customer, we regret to inform you that due to incomplete KYC verification as mandated by the RBI, your account will be permanently deactivated within 24 hours. To avoid inconvenience, kindly complete your KYC verification immediately by clicking the link below and entering your net banking credentials, debit card number, expiry date and CVV. Failure to comply will result in permanent account closure. http://rbi-kyc-compliance.example/verify")
S(G, "multiple_urls_scam", "@MOBILE", "Congratulations! Claim your prize at http://bit.ly/prize88 or http://tinyurl.com/prize88b before it expires.")
S(G, "scam_no_url_short", "@MOBILE", "Send OTP now or account blocked.")
S(G, "ip_url_scam", "@MOBILE", "Verify your bank account now: http://103.45.22.9/login.php")
S(G, "number_only_scam", "@MOBILE", "Call 9XXXXXXX21 now to claim your lottery prize of Rs 10 lakh.")
L(G, "legit_long", "@MOBILE", "Hi team, sharing the agenda for tomorrow's review: 1) Sprint demo 2) Q4 roadmap 3) Hiring updates 4) Budget discussion. Please come prepared with your updates. The meeting will be in conference room B at 3pm and will run for about an hour. Let me know if anything needs to change.", saved=True, name="Manager")
L(G, "legit_uppercase", "@MOBILE", "HAPPY DIWALI TO YOU AND YOUR FAMILY!!!", saved=True, name="Uncle")
L(G, "legit_emoji_only", "@MOBILE", "👍👍", saved=True, name="Friend")
L(G, "legit_numbers", "@MOBILE", "Flight 6E204, gate 14, boarding 5:40pm.", saved=True, name="Husband")
L(G, "legit_special_chars", "@MOBILE", "Bill: Rs 1,240 (50% off!) -> total Rs 620 [paid]", saved=True, name="Friend")
L(G, "legit_wrong_number", "@MOBILE", "Sorry, wrong number. Please ignore my previous message.")


# ============================================================================
# REQUEST / RESPONSE
# ============================================================================

def build_request(case):
    sender = case["sender"]
    if sender == "@MOBILE":
        sender = _random_indian_mobile()
    return {
        "sender": sender,
        "body": case["body"],
        "timestamp": int(time.time() * 1000),
        "source": "precision_recall_eval",
        "expected_otp": False,
        "foreground_app": "",
        "screen_unlocked": True,
        "is_saved_contact": case.get("is_saved_contact", False),
        "contact_name": case.get("contact_name"),
    }


def run_case(base_url, case):
    payload = build_request(case)
    t0 = time.perf_counter()
    try:
        resp = requests.post(base_url + ANALYZE_URL_PATH, json=payload, timeout=REQUEST_TIMEOUT)
        resp.raise_for_status()
        data = resp.json()
    except Exception as exc:
        return {"error": str(exc), "score": None, "status": None, "latency_ms": None}
    latency_ms = round((time.perf_counter() - t0) * 1000.0, 1)

    analysis = data.get("analysis", {}) or {}
    score = analysis.get("score", analysis.get("risk_score"))
    status = analysis.get("status")
    return {"error": None, "score": score, "status": status, "latency_ms": latency_ms}


# ============================================================================
# METRICS
# ============================================================================

def confusion_at_threshold(rows, threshold):
    tp = fp = tn = fn = 0
    for r in rows:
        if r["score"] is None:
            continue
        predicted_scam = r["score"] >= threshold
        actual_scam = r["is_scam"]
        if predicted_scam and actual_scam:
            tp += 1
        elif predicted_scam and not actual_scam:
            fp += 1
        elif not predicted_scam and actual_scam:
            fn += 1
        else:
            tn += 1
    n = tp + fp + tn + fn
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    specificity = tn / (tn + fp) if (tn + fp) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    accuracy = (tp + tn) / n if n else 0.0
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    fnr = fn / (fn + tp) if (fn + tp) else 0.0
    denom = ((tp + fp) * (tp + fn) * (tn + fp) * (tn + fn)) ** 0.5
    mcc = ((tp * tn) - (fp * fn)) / denom if denom else 0.0
    return {"tp": tp, "fp": fp, "tn": tn, "fn": fn, "n": n,
            "precision": precision, "recall": recall, "specificity": specificity,
            "f1": f1, "accuracy": accuracy, "fpr": fpr, "fnr": fnr, "mcc": mcc}


def roc_auc(rows):
    """Threshold-free AUC = P(score of random scam > score of random safe)."""
    pos = [r["score"] for r in rows if r["is_scam"] and r["score"] is not None]
    neg = [r["score"] for r in rows if not r["is_scam"] and r["score"] is not None]
    if not pos or not neg:
        return float("nan")
    wins = 0.0
    for p in pos:
        for n in neg:
            if p > n:
                wins += 1.0
            elif p == n:
                wins += 0.5
    return wins / (len(pos) * len(neg))


def print_confusion(m, threshold):
    print(f"\nThreshold: risk_score >= {threshold} counts as predicted SCAM   (n={m['n']})")
    print(f"{'':>18}{'Predicted SCAM':>18}{'Predicted SAFE':>18}")
    print(f"{'Actual SCAM':>18}{m['tp']:>18}{m['fn']:>18}")
    print(f"{'Actual SAFE':>18}{m['fp']:>18}{m['tn']:>18}")
    print(f"\nAccuracy   : {m['accuracy']:.3f}")
    print(f"Precision  : {m['precision']:.3f}")
    print(f"Recall     : {m['recall']:.3f}   (a.k.a. sensitivity / true-positive rate)")
    print(f"Specificity: {m['specificity']:.3f}   (true-negative rate)")
    print(f"F1 score   : {m['f1']:.3f}")
    print(f"MCC        : {m['mcc']:.3f}   (balanced metric, -1..1)")
    print(f"FP rate    : {m['fpr']:.3f}   FN rate: {m['fnr']:.3f}")
    if m["fp"] > 0:
        print(f"-> {m['fp']} legitimate message(s) wrongly flagged as scam (false positives).")
    if m["fn"] > 0:
        print(f"-> {m['fn']} actual scam message(s) missed (false negatives) - the more")
        print("   dangerous error type for a security product.")


def group_report(rows, threshold):
    groups = defaultdict(list)
    for r in rows:
        groups[r["group"]].append(r)

    print(f"\n{'group':<22}{'n':>5}{'scam':>6}{'safe':>6}{'acc':>8}{'prec':>8}{'rec':>8}{'FP':>5}{'FN':>5}")
    print("-" * 73)
    out = []
    for g in sorted(groups):
        gm = confusion_at_threshold(groups[g], threshold)
        n_scam = sum(1 for r in groups[g] if r["is_scam"])
        n_safe = len(groups[g]) - n_scam
        print(f"{g:<22}{gm['n']:>5}{n_scam:>6}{n_safe:>6}{gm['accuracy']:>8.3f}"
              f"{gm['precision']:>8.3f}{gm['recall']:>8.3f}{gm['fp']:>5}{gm['fn']:>5}")
        out.append({"group": g, "n": gm["n"], "scam": n_scam, "safe": n_safe,
                    "accuracy": round(gm["accuracy"], 4), "precision": round(gm["precision"], 4),
                    "recall": round(gm["recall"], 4), "tp": gm["tp"], "fp": gm["fp"],
                    "tn": gm["tn"], "fn": gm["fn"]})
    return out


def status_report(rows):
    buckets = defaultdict(lambda: [0, 0])  # status -> [scam_count, safe_count]
    for r in rows:
        key = r.get("status") or "?"
        buckets[key][0 if r["is_scam"] else 1] += 1
    print(f"\n{'status':<12}{'actual SCAM':>14}{'actual SAFE':>14}")
    print("-" * 40)
    for k in sorted(buckets):
        print(f"{k:<12}{buckets[k][0]:>14}{buckets[k][1]:>14}")


def main():
    parser = argparse.ArgumentParser(description="Precision/recall evaluation of /analyze-sms")
    parser.add_argument("--base-url", default=DEFAULT_BASE_URL)
    parser.add_argument("--repeat", type=int, default=1, help="run the whole dataset N times")
    parser.add_argument("--delay", type=float, default=0.0, help="seconds to sleep between requests")
    parser.add_argument("--shuffle", action="store_true", help="randomize order")
    parser.add_argument("--group", default=None, help="only run one group (e.g. indian_scams)")
    parser.add_argument("--threshold", type=int, default=CURRENT_THRESHOLD)
    args = parser.parse_args()
    base_url = args.base_url.rstrip("/")
    threshold = args.threshold

    cases = [c for c in TEST_CASES if (args.group is None or c["group"] == args.group)]
    if not cases:
        groups = sorted({c["group"] for c in TEST_CASES})
        print(f"No cases for group '{args.group}'. Available groups: {', '.join(groups)}")
        sys.exit(1)

    n_scam = sum(1 for c in cases if c["is_scam"])
    print("=" * 78)
    print("PRECISION / RECALL EVALUATION - full pipeline (/analyze-sms)")
    print("=" * 78)
    print(f"Target        : {base_url}{ANALYZE_URL_PATH}")
    print(f"Test messages : {len(cases)}  (scam={n_scam}, safe={len(cases) - n_scam})  x repeat={args.repeat}")
    print(f"Threshold     : risk_score >= {threshold}\n")

    rows = []
    for run_idx in range(args.repeat):
        run_cases = list(cases)
        if args.shuffle:
            random.shuffle(run_cases)
        if args.repeat > 1:
            print(f"--- run {run_idx + 1}/{args.repeat} ---")
        for case in run_cases:
            result = run_case(base_url, case)
            row = {**case, **result, "run": run_idx + 1}
            rows.append(row)

            if result["error"]:
                print(f"[ERROR]  {case['group']:<18}{case['category']:<26} {result['error']}")
            else:
                predicted_scam = (result["score"] or 0) >= threshold
                correct = predicted_scam == case["is_scam"]
                mark = "OK  " if correct else "MISS"
                print(f"[{mark}] {case['group']:<18}{case['category']:<26} "
                      f"true={'SCAM' if case['is_scam'] else 'SAFE':<4} "
                      f"score={str(result['score']):<5} status={result['status']}")
            if args.delay:
                time.sleep(args.delay)

    usable_rows = [r for r in rows if r["score"] is not None]
    errors = len(rows) - len(usable_rows)
    if not usable_rows:
        print("\nNo successful responses were received - is the backend running?")
        sys.exit(1)
    if errors:
        print(f"\n[!] {errors} request(s) failed and are excluded from the metrics.")

    # ---- overall ----
    print("\n" + "-" * 78)
    print(f"OVERALL METRICS AT THRESHOLD = {threshold}")
    print("-" * 78)
    m = confusion_at_threshold(usable_rows, threshold)
    print_confusion(m, threshold)
    print(f"\nROC-AUC (threshold-independent): {roc_auc(usable_rows):.3f}")

    # ---- per group ----
    print("\n" + "-" * 78)
    print("PER-GROUP BREAKDOWN")
    print("-" * 78)
    group_rows = group_report(usable_rows, threshold)

    # ---- per status ----
    print("\n" + "-" * 78)
    print("STATUS DISTRIBUTION (what the system labelled each message)")
    print("-" * 78)
    status_report(usable_rows)

    # ---- latency ----
    lats = [r["latency_ms"] for r in usable_rows if r.get("latency_ms") is not None]
    if lats:
        lats_sorted = sorted(lats)
        p95 = lats_sorted[int(0.95 * (len(lats_sorted) - 1))]
        print(f"\nClient-side latency: avg {sum(lats) / len(lats):.0f} ms, "
              f"median {lats_sorted[len(lats_sorted) // 2]:.0f} ms, p95 {p95:.0f} ms")

    # ---- threshold sweep ----
    print("\n" + "-" * 78)
    print("THRESHOLD SWEEP (0-100)")
    print("-" * 78)
    print(f"{'threshold':>10}{'accuracy':>11}{'precision':>11}{'recall':>9}{'f1':>8}{'FP':>5}{'FN':>5}")
    best = (None, -1.0)
    for t in range(0, 101, 5):
        sm = confusion_at_threshold(usable_rows, t)
        marker = "  <- current" if t == threshold else ""
        print(f"{t:>10}{sm['accuracy']:>11.3f}{sm['precision']:>11.3f}{sm['recall']:>9.3f}"
              f"{sm['f1']:>8.3f}{sm['fp']:>5}{sm['fn']:>5}{marker}")
        if sm["f1"] > best[1]:
            best = (t, sm["f1"])
    print(f"\nBest F1 on this test set: threshold={best[0]} (F1={best[1]:.3f})")

    # ---- misclassifications ----
    misses = [r for r in usable_rows if (r["score"] >= threshold) != r["is_scam"]]
    if misses:
        print("\n" + "-" * 78)
        print(f"MISCLASSIFIED AT THRESHOLD {threshold} ({len(misses)})")
        print("-" * 78)
        for r in misses:
            actual = "SCAM" if r["is_scam"] else "SAFE"
            predicted = "SCAM" if r["score"] >= threshold else "SAFE"
            print(f"  [{r['group']}/{r['category']}] actual={actual} predicted={predicted} "
                  f"score={r['score']} status={r['status']}")
            print(f"    \"{r['body'][:100]}\"")

    # ---- save CSVs ----
    with OUT_CSV.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=[
            "run", "group", "category", "is_scam", "sender", "body", "score", "status",
            "predicted_scam_at_current_threshold", "correct", "latency_ms",
        ])
        writer.writeheader()
        for r in rows:
            predicted = (r["score"] >= threshold) if r.get("score") is not None else None
            writer.writerow({
                "run": r["run"],
                "group": r["group"],
                "category": r["category"],
                "is_scam": r["is_scam"],
                "sender": r["sender"],
                "body": r["body"],
                "score": r.get("score"),
                "status": r.get("status"),
                "predicted_scam_at_current_threshold": predicted,
                "correct": (predicted == r["is_scam"]) if predicted is not None else None,
                "latency_ms": r.get("latency_ms"),
            })
    with OUT_GROUP_CSV.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(group_rows[0].keys()))
        writer.writeheader()
        writer.writerows(group_rows)
    print(f"\nFull results saved to : {OUT_CSV}")
    print(f"Per-group metrics in  : {OUT_GROUP_CSV}")


if __name__ == "__main__":
    main()