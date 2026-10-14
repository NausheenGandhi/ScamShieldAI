"""
evaluate_embedding_quality.py   (EXPANDED DATASET VERSION)

Answers: "is the semantic embedding actually good at its job?"

Its job (per app/services/semantic_spam_service.py) is: given a new SMS,
decide whether it's a reworded copy of a scam pattern already seen, using
cosine similarity between MiniLM embeddings, at
SEMANTIC_SIMILARITY_THRESHOLD (default 0.70).

TEST SET (expanded)
-------------------
* 18 scam FAMILIES x 6 paraphrases each (English, Hinglish, Hindi script,
  shouty/obfuscated variants, with/without links)       = 108 scam messages
* LEGIT      : 45 ordinary messages (personal, bank alerts, OTPs, promos,
               utilities, travel...)
* LEGIT_HARD : 20 legitimate messages that SHARE VOCABULARY with scams
               (real KYC notices, real OTPs, real refunds, real delivery
               updates). These are the dangerous false-match cases.

PAIR TYPES
----------
    SAME-FAMILY  : two wordings of the same scam      -> should MATCH
    CROSS-FAMILY : two different scam templates       -> should NOT match
    LEGIT vs any : legit/hard-legit vs anything        -> should NOT match

METRICS
-------
 1. Real model vs SHA-256 fallback check
 2. Average cosine similarity per pair type (+ min / max / std)
 3. Separation margin
 4. Precision / recall / F1 / accuracy at the CURRENT threshold
 5. ROC-AUC (threshold-free: how often a same-family pair scores higher
    than a non-matching pair)
 6. Threshold sweep 0.50 - 0.95 with best-F1 threshold
 7. Nearest-neighbour retrieval accuracy: for each scam message, is its
    single most similar OTHER message from the same family? (this mirrors
    how production looks up the best pattern)
 8. Per-family table: within-family avg, best other-family avg, recall
    of paraphrase matching at the current threshold
 9. Hard-legit risk: for each LEGIT_HARD message, the highest similarity
    to any scam message and whether it crosses the threshold
10. Full pairwise CSV (compatible with plot_family_heatmap.py)
11. Optional heatmap PNG (family-averaged, readable at this size)

WHERE TO PUT IT:   backend/evaluate_embedding_quality.py
HOW TO RUN:        cd backend
                   python evaluate_embedding_quality.py
"""

import csv
import itertools
import statistics
import sys
from collections import defaultdict
from pathlib import Path

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

try:
    from dotenv import load_dotenv
    for candidate in (HERE / ".env", HERE / "app" / ".env"):
        if candidate.exists():
            load_dotenv(candidate)
except ImportError:
    pass

from app.services.embedding_service import generate_embedding, load_embedding_model
from app.services.semantic_spam_service import _normalize_for_embedding

DEFAULT_SIMILARITY_THRESHOLD = 0.53

OUT_CSV = HERE / "embedding_similarity_matrix.csv"
OUT_FAMILY_CSV = HERE / "embedding_family_summary.csv"
OUT_PNG = HERE / "embedding_similarity_heatmap.png"

# ============================================================================
# TEST SET:  (family, text)
# Families starting with "LEGIT" are non-scam. Everything else is a scam family.
# ============================================================================

TEST_MESSAGES = [
    # ---------------- 1. bank_kyc ----------------
    ("bank_kyc", "Dear customer, your bank account will be blocked today. Complete your KYC immediately: http://bit.ly/kyc123"),
    ("bank_kyc", "URGENT: Your account will be suspended within 24 hours. Update your KYC now at http://verify-kyc.example/link"),
    ("bank_kyc", "Your a/c will be deactivated due to pending KYC. Click here to update: http://kyc-update.example/x"),
    ("bank_kyc", "Alert! KYC verification pending, account block hoga aaj. Verify now: http://bit.ly/kycnow"),
    ("bank_kyc", "HDFC Bank: KYC expired. Your account is frozen until you re-verify PAN and Aadhaar here: http://hdfc-kyc-verify.example/"),
    ("bank_kyc", "प्रिय ग्राहक, आपका बैंक खाता आज बंद हो जाएगा। तुरंत KYC अपडेट करें: http://bit.ly/kyc-hindi"),

    # ---------------- 2. lottery_prize ----------------
    ("lottery_prize", "Congratulations! You have won a lucky draw prize of Rs 5,00,000. Claim now: http://bit.ly/claimprize"),
    ("lottery_prize", "You are today's lucky winner! Claim your reward of 5 lakh rupees here: http://prize-claim.example/win"),
    ("lottery_prize", "CONGRATS! Your mobile number has won our lucky draw. Claim your gift now: http://bit.ly/luckydraw2"),
    ("lottery_prize", "You've been selected as a lucky winner of a cash prize! Click to claim your reward: http://win-now.example/"),
    ("lottery_prize", "KBC Lottery: Your number won Rs 25 lakh. Contact the manager on WhatsApp to claim your prize money."),
    ("lottery_prize", "Badhai ho! Aapne 10 lakh ka inaam jeeta hai. Claim karne ke liye abhi click karein: http://bit.ly/inaam10"),

    # ---------------- 3. delivery_fee ----------------
    ("delivery_fee", "Your parcel is on hold due to unpaid customs duty. Pay Rs 199 now to release delivery: http://bit.ly/custfee"),
    ("delivery_fee", "Package could not be delivered - outstanding customs fee required. Pay now: http://delivery-fee.example/pay"),
    ("delivery_fee", "Your courier is held at the warehouse, pending customs charges. Settle payment here: http://bit.ly/pkgfee"),
    ("delivery_fee", "India Post: Delivery failed due to incomplete address. Update details and pay Rs 25 redelivery fee: http://indiapost-redeliver.example/"),
    ("delivery_fee", "FedEx: Your shipment is on hold. Pay the small reshipment fee within 24h or it will be returned: http://fedex-pay.example/"),
    ("delivery_fee", "Aapka parcel customs mein ruka hai. Delivery ke liye abhi Rs 150 fee pay karein: http://bit.ly/parcelfee"),

    # ---------------- 4. otp_phish ----------------
    ("otp_phish", "Your account was accessed from a new device. Enter the OTP sent to you to secure your account immediately: http://sec-check.example/"),
    ("otp_phish", "Unusual login detected on your account. Verify with the OTP you received to prevent unauthorized access: http://verify-login.example/"),
    ("otp_phish", "Security alert: confirm it's you. Use the OTP just sent to validate your identity now: http://bit.ly/confirmid"),
    ("otp_phish", "Your account is compromised! Share the OTP you just received with our security team to lock it."),
    ("otp_phish", "Suspicious sign-in blocked. To restore access, reply with the 6 digit code sent to your phone."),
    ("otp_phish", "Sir aapke account mein unauthorized login hua hai. Security ke liye abhi OTP bataiye."),

    # ---------------- 5. upi_refund ----------------
    ("upi_refund", "Refund of Rs 2,499 is pending. Enter your UPI PIN here to receive the money back: http://refund-upi.example/"),
    ("upi_refund", "Rs 2,000 received on PhonePe. To accept, enter your UPI PIN at http://phonepe-receive.example/"),
    ("upi_refund", "Your cashback of Rs 999 is ready. Scan this QR and enter UPI PIN to collect it."),
    ("upi_refund", "Money sent to you by mistake. Please approve the collect request on GPay to get your refund."),
    ("upi_refund", "Order refund initiated. Verify your UPI ID and PIN to credit Rs 1,850 instantly: http://bit.ly/upirefund"),
    ("upi_refund", "Aapka refund aane wala hai, sirf UPI PIN daalein is link par: http://bit.ly/refundnow"),

    # ---------------- 6. electricity_disconnect ----------------
    ("electricity_disconnect", "Dear consumer, your electricity connection will be disconnected tonight 9:30pm. Pay pending bill: http://bses-bill-pay.example/"),
    ("electricity_disconnect", "Previous month bill unpaid. Power will be cut today. Call our officer on 98xxxxxx12 and update bill now."),
    ("electricity_disconnect", "Electricity Board: Your supply will be disconnected in 2 hours due to non-payment. Update now: http://bit.ly/powerbill"),
    ("electricity_disconnect", "Your meter will be removed tomorrow because of pending dues. Contact officer immediately to avoid disconnection."),
    ("electricity_disconnect", "Aapka bijli connection aaj raat kat jayega. Turant is number par call karein aur bill update karein."),
    ("electricity_disconnect", "URGENT: Last notice before power disconnection. Pay Rs 1,980 pending amount: http://electric-pay-now.example/"),

    # ---------------- 7. tax_refund ----------------
    ("tax_refund", "Income Tax Dept: Refund of Rs 15,320 approved. Submit your bank details to receive it: http://incometax-refund.example/"),
    ("tax_refund", "You are eligible for an income tax refund. Click here to claim before it expires: http://bit.ly/taxrefund"),
    ("tax_refund", "ITR processed. Rs 24,780 will be credited. Verify your account number and IFSC here: http://itr-credit.example/"),
    ("tax_refund", "Tax refund pending for your PAN. Update your bank account now to avoid cancellation."),
    ("tax_refund", "Government of India: GST refund of Rs 9,400 is ready. Verify details to claim: http://gst-refund-claim.example/"),
    ("tax_refund", "Aapka income tax refund approve ho gaya hai. Paise lene ke liye bank details bharein: http://bit.ly/itrrefund"),

    # ---------------- 8. job_fee ----------------
    ("job_fee", "You are selected for a job at Amazon. Pay Rs 2,500 registration fee to confirm your offer letter."),
    ("job_fee", "Work from home! Earn Rs 5,000 daily. Pay Rs 500 registration fee on UPI to start today."),
    ("job_fee", "Congratulations, your resume is shortlisted. Deposit Rs 1,999 as security to receive your joining letter."),
    ("job_fee", "Part-time job: like YouTube videos and earn Rs 3,000 per day. Message HR on Telegram to begin."),
    ("job_fee", "Data entry job offer, no experience needed. Pay refundable training fee of Rs 1,200 to get started."),
    ("job_fee", "Ghar baithe 5000 rupaye daily kamayein. Abhi registration fees 500 UPI par bhejein."),

    # ---------------- 9. loan_offer ----------------
    ("loan_offer", "Get instant personal loan up to 5 lakhs with zero documentation! Apply now: http://bit.ly/instaloan"),
    ("loan_offer", "Pre-approved loan of Rs 3,00,000 at 0% interest. Submit Aadhaar & PAN: http://instant-loan-approve.example/apply"),
    ("loan_offer", "Your loan of Rs 5 lakh is approved. Pay Rs 4,999 insurance fee first to release the amount."),
    ("loan_offer", "Urgent cash needed? Instant loan in 5 minutes, no CIBIL check, no income proof. Install our app now."),
    ("loan_offer", "Loan approved without documents! Just pay processing fee Rs 2,000 and get money in your account today."),
    ("loan_offer", "Aapka loan approve ho gaya hai bina documents ke. Processing fee bhejein aur paise paayein."),

    # ---------------- 10. investment_crypto ----------------
    ("investment_crypto", "Earn Rs 50,000 daily with our crypto trading signals. 100% guaranteed returns. Join now: http://bit.ly/cryptoprofit7"),
    ("investment_crypto", "Join our VIP stock tips group. Invest Rs 10,000 and get Rs 1 lakh in 7 days. Guaranteed profit."),
    ("investment_crypto", "Double your money in 30 days with our Bitcoin scheme. Limited slots, deposit now: http://btc-double.example/"),
    ("investment_crypto", "Insider IPO allotment tips. Pay Rs 5,000 for sure-shot 300% returns. Guaranteed by our SEBI expert."),
    ("investment_crypto", "Invest in our forex AI bot and earn daily profit of 5%. Withdraw anytime. Register: http://forex-ai-profit.example/"),
    ("investment_crypto", "Paise double karein sirf 15 din mein. Crypto trading group join karein, 100% guarantee."),

    # ---------------- 11. emergency_family ----------------
    ("emergency_family", "Mom this is my new number, phone is broken. Need Rs 15,000 urgently for hospital, send to this account."),
    ("emergency_family", "I've had an accident, send 20000 rupees urgently, don't call me right now."),
    ("emergency_family", "Bro stuck at airport, wallet lost. Please send 8000 on GPay right now, will return tonight. Don't tell Dad."),
    ("emergency_family", "Hi dad, I'm in trouble. Need money urgently, please transfer Rs 25,000, I'll explain later. Don't call."),
    ("emergency_family", "This is my new WhatsApp number. Urgent, I need you to pay a bill for me today, I'll refund you tonight."),
    ("emergency_family", "Beta mera phone kharab hai, naye number se likh raha hoon. Abhi 10000 bhej do, bahut zaroori hai."),

    # ---------------- 12. police_digital_arrest ----------------
    ("police_digital_arrest", "This is Cyber Crime Police. A case is registered on your Aadhaar. Pay Rs 25,000 now to avoid arrest."),
    ("police_digital_arrest", "You are under digital arrest. Stay on video call and do not inform anyone. Transfer money to the RBI verification account."),
    ("police_digital_arrest", "FedEx: A parcel in your name contains illegal items. Contact CBI officer immediately, do not tell anyone."),
    ("police_digital_arrest", "Narcotics Bureau notice: your SIM is linked to money laundering. Call this number to avoid immediate arrest."),
    ("police_digital_arrest", "Supreme Court warrant issued against you. Pay the settlement amount today to cancel the arrest warrant."),
    ("police_digital_arrest", "Aapke naam par case darj hua hai. Turant 20000 rupaye bhejiye warna giraftari hogi."),

    # ---------------- 13. tech_support ----------------
    ("tech_support", "Microsoft Support: Your computer is infected. Call 1800-xxx-9981 immediately and install AnyDesk."),
    ("tech_support", "Your device has been hacked! Call our certified technician now to remove the virus and secure your data."),
    ("tech_support", "Windows Defender alert: 5 viruses detected. Do not shut down. Call toll-free support right now."),
    ("tech_support", "Your Google account is compromised. Call Google Support at this number to recover it immediately."),
    ("tech_support", "Apple ID locked due to suspicious activity. Contact Apple Support urgently on this number to unlock."),
    ("tech_support", "Aapka computer virus se infected hai. Turant support number par call karein."),

    # ---------------- 14. sim_telecom_kyc ----------------
    ("sim_telecom_kyc", "Airtel: Your SIM will be disconnected in 2 hours due to incomplete KYC. Update: http://airtel-kyc-update.example/"),
    ("sim_telecom_kyc", "TRAI: Your number will be blocked today for illegal activity. Press 9 to talk to officer."),
    ("sim_telecom_kyc", "Jio: Upgrade your SIM to 5G free. Reply with the OTP sent to your number to activate."),
    ("sim_telecom_kyc", "Your mobile number will be permanently deactivated in 24 hours. Complete re-verification now: http://bit.ly/simverify"),
    ("sim_telecom_kyc", "Vi: SIM KYC expired. Number barred from tonight. Click to update documents: http://vi-sim-kyc.example/"),
    ("sim_telecom_kyc", "Aapka SIM aaj raat band ho jayega. KYC update karne ke liye abhi click karein."),

    # ---------------- 15. traffic_challan ----------------
    ("traffic_challan", "E-challan of Rs 1,000 issued on your vehicle. Pay within 24h to avoid court notice: http://echallan-pay.example/"),
    ("traffic_challan", "Traffic violation detected on your vehicle MH02AB1234. Pay fine now to avoid license suspension: http://bit.ly/challanpay"),
    ("traffic_challan", "Your FASTag is deactivated. Recharge immediately to avoid penalty: http://fastag-recharge-now.example/"),
    ("traffic_challan", "Pending challan Rs 500 on your RC. Settle online today or face legal action: http://parivahan-pay.example/"),
    ("traffic_challan", "Speed camera notice: pay Rs 2,000 fine within 48 hours to avoid additional penalty. Pay: http://traffic-fine.example/"),
    ("traffic_challan", "Aapki gaadi par challan kata hai. Abhi fine bharein warna court notice aayega: http://bit.ly/challan"),

    # ---------------- 16. gift_card_boss ----------------
    ("gift_card_boss", "Hi, this is your CEO. I am in a meeting, buy 5 Amazon gift cards of Rs 5,000 and send me the codes urgently."),
    ("gift_card_boss", "Are you available? I need a quick favour. Purchase Google Play gift cards and send me the codes. Don't call, I'm in a meeting."),
    ("gift_card_boss", "This is your manager on my personal number. Need you to buy 10 iTunes vouchers right away, will reimburse today."),
    ("gift_card_boss", "Urgent task from the director: buy gift cards worth Rs 20,000 and share the scratch codes here. Keep this confidential."),
    ("gift_card_boss", "Hello, I'm travelling and can't call. Please buy Amazon Pay cards for a client gift and message me the codes."),
    ("gift_card_boss", "Sir meeting mein hoon, jaldi se 5 gift card kharid kar codes bhej do, abhi zaroori hai."),

    # ---------------- 17. aadhaar_pan ----------------
    ("aadhaar_pan", "Your Aadhaar is suspended. Link with PAN now: http://aadhaar-pan-link.example/"),
    ("aadhaar_pan", "PAN card blocked! Update your PAN details immediately to avoid penalty of Rs 10,000: http://pan-update.example/"),
    ("aadhaar_pan", "Your PAN and Aadhaar are not linked. Account will be frozen today. Link now: http://bit.ly/panlink"),
    ("aadhaar_pan", "Please share your Aadhaar number and date of birth to continue processing your pending benefit."),
    ("aadhaar_pan", "UIDAI notice: Aadhaar verification failed. Re-upload your documents here to avoid cancellation: http://uidai-verify.example/"),
    ("aadhaar_pan", "Aapka Aadhaar band hone wala hai. PAN se link karne ke liye abhi click karein."),

    # ---------------- 18. credit_card_rewards ----------------
    ("credit_card_rewards", "ICICI Bank: Your credit card reward points of Rs 8,640 expire today. Redeem now: http://icici-rewards-claim.example/"),
    ("credit_card_rewards", "Your SBI card reward points are expiring. Click to redeem them for cash: http://sbi-redeem.example/"),
    ("credit_card_rewards", "Dear cardholder, 12,500 reward points will lapse tonight. Convert to cash here: http://bit.ly/redeempts"),
    ("credit_card_rewards", "HDFC Bank: Redeem your pending points worth Rs 7,200 by downloading our rewards app: http://hdfc-rewards-app.example/"),
    ("credit_card_rewards", "Axis Bank: Your points of Rs 9,100 will expire in 2 hours. Redeem immediately: http://axis-points.example/"),
    ("credit_card_rewards", "Aapke credit card ke reward points aaj expire ho rahe hain. Abhi redeem karein: http://bit.ly/rewardnow"),

    # ======================= LEGIT (ordinary) =======================
    ("LEGIT", "Hey, are we still meeting for lunch at 1pm today?"),
    ("LEGIT", "Your Swiggy order has been delivered. Enjoy your meal!"),
    ("LEGIT", "Reminder: your dentist appointment is tomorrow at 10am."),
    ("LEGIT", "Mom, I'll be home a bit late tonight, don't wait up for dinner."),
    ("LEGIT", "Your electricity bill of Rs 1,240 for this month is now available to view in the app."),
    ("LEGIT", "Good morning! Hope you have a great day."),
    ("LEGIT", "Meeting moved to 3pm, conference room B. Please bring the Q3 report."),
    ("LEGIT", "Happy birthday!! Party at my place on Saturday, don't be late!"),
    ("LEGIT", "Movie at 8 tonight? I'll book the tickets."),
    ("LEGIT", "Thanks for lunch yesterday! I'll send you my share on GPay in the evening."),
    ("LEGIT", "Your Uber driver Ramesh will arrive in 3 minutes. Share the ride PIN to start."),
    ("LEGIT", "Your flight 6E-204 on 14 Oct departs at 06:15 from Mumbai T2. Web check-in is open."),
    ("LEGIT", "PNR 4521896723 confirmed. Coach B2 seat 34. Happy journey."),
    ("LEGIT", "Recharge of Rs 299 successful. Validity 28 days. Thank you for choosing Airtel."),
    ("LEGIT", "You have used 80% of your daily data quota. Visit the MyJio app for more."),
    ("LEGIT", "Flat 40% off on your favorite brands this weekend only. Shop now on the Myntra app."),
    ("LEGIT", "Great Indian Festival starts tomorrow! Up to 70% off on electronics."),
    ("LEGIT", "Your Amazon package is out for delivery and should arrive today."),
    ("LEGIT", "Your appointment is confirmed for tomorrow at 10am."),
    ("LEGIT", "Parent-teacher meeting is scheduled on Saturday 10am. Kindly attend."),
    ("LEGIT", "Rs 1,250.00 debited from A/c XX4521 on 10-Oct at AMAZON. Avl bal Rs 22,340."),
    ("LEGIT", "Rs 45,000.00 credited to your A/c XX7712. Salary credit. Avl bal Rs 61,200."),
    ("LEGIT", "Rs 350 paid via UPI to SWIGGY. UPI Ref 4123987612."),
    ("LEGIT", "Your HDFC Bank account balance as of today is Rs 12,500."),
    ("LEGIT", "Your EMI of Rs 8,450 is due on 05-Nov. Please maintain sufficient balance."),
    ("LEGIT", "Your LIC premium of Rs 6,200 is due on 15-Nov. Pay via the LIC portal or branch."),
    ("LEGIT", "Your LPG cylinder booking is confirmed. Delivery expected within 2 days."),
    ("LEGIT", "Bhai kal ka match dekhne chalein? Main snacks le aata hoon."),
    ("LEGIT", "Beta khana kha liya? Aaj jaldi ghar aa jana."),
    ("LEGIT", "शुभ प्रभात! आज शाम को घर आ रहे हो ना?"),
    ("LEGIT", "Congrats on the new job! Let's celebrate this weekend."),
    ("LEGIT", "Call me when free."),
    ("LEGIT", "Sorry, wrong number. Please ignore my previous message."),
    ("LEGIT", "Hi, this is Suresh from the society office. The water supply will be off tomorrow 10am-2pm."),
    ("LEGIT", "Hello sir, I'm outside your gate with your parcel. Please come down."),
    ("LEGIT", "Hi team, sharing the agenda for tomorrow's review: sprint demo, Q4 roadmap, hiring updates."),
    ("LEGIT", "HAPPY DIWALI TO YOU AND YOUR FAMILY!!!"),
    ("LEGIT", "Rent for October is due. Please transfer to the usual account whenever convenient."),
    ("LEGIT", "Your Zomato order is on the way. Track it live in the app."),
    ("LEGIT", "Your Netflix plan renews tomorrow. Make sure your payment method is up to date."),
    ("LEGIT", "Your table for 4 is booked at 8pm tonight. See you there!"),
    ("LEGIT", "Your library book is due for return on Friday."),
    ("LEGIT", "Water supply will be interrupted tomorrow for maintenance between 10am and 2pm."),
    ("LEGIT", "Your car service is scheduled for Saturday 11am at the service centre."),
    ("LEGIT", "Package delivered to your front door. Thanks for shopping with us."),

    # =========== LEGIT_HARD (legit, but share vocabulary with scams) ===========
    ("LEGIT_HARD", "Your KYC documents are due for periodic update. Please visit your nearest branch with ID proof. Do not click on links from unknown persons."),
    ("LEGIT_HARD", "Your SBI debit card has been blocked as per your request. Visit your nearest branch to get a new card."),
    ("LEGIT_HARD", "Your OTP is 482913. Valid for 10 minutes. Do not share this OTP with anyone."),
    ("LEGIT_HARD", "Your Amazon verification code is 118273. Never share this code with anyone."),
    ("LEGIT_HARD", "Your refund of Rs 799 for order #402-123 has been initiated and will reflect in 3-5 business days."),
    ("LEGIT_HARD", "Congratulations! You won a Rs 100 Flipkart gift voucher in our contest. Voucher auto-applied to your account."),
    ("LEGIT_HARD", "Security alert: new sign-in on Pixel 8. If this was you, no action needed."),
    ("LEGIT_HARD", "Urgent: your credit card payment of Rs 14,320 is due tomorrow. Pay via the HDFC app to avoid late fee."),
    ("LEGIT_HARD", "SBI never asks for your PIN, OTP, or card details over call or SMS. Report fraud at 1930."),
    ("LEGIT_HARD", "Never share your OTP, PIN, or CVV with anyone. Axis Bank will never ask for these."),
    ("LEGIT_HARD", "Your Blue Dart shipment is out for delivery. Track: https://www.bluedart.com/tracking"),
    ("LEGIT_HARD", "Your loan application is under review. Our representative will contact you within 2 working days."),
    ("LEGIT_HARD", "Traffic Police: Reminder to renew your PUC certificate. Details at https://mahatransport.gov.in"),
    ("LEGIT_HARD", "Your income tax return has been processed. Refund, if any, will be credited to your pre-validated bank account. View at incometax.gov.in"),
    ("LEGIT_HARD", "Your electricity bill payment of Rs 1,240 was received. Thank you for paying on time."),
    ("LEGIT_HARD", "Your Aadhaar OTP is 458102. Valid for 10 minutes. Do not share it with anyone."),
    ("LEGIT_HARD", "Your IRCTC ticket refund of Rs 340 has been processed to your original payment method."),
    ("LEGIT_HARD", "Pre-approved personal loan offer for you. Visit your nearest HDFC Bank branch to know more. T&C apply."),
    ("LEGIT_HARD", "Your Airtel number KYC is complete. No further action is required. Thank you."),
    ("LEGIT_HARD", "Your FASTag balance is low. Recharge via the official FASTag app or your bank's net banking."),
]


def is_legit(family):
    return family.startswith("LEGIT")


def cosine(a, b):
    dot = sum(x * y for x, y in zip(a, b))
    na = sum(x * x for x in a) ** 0.5
    nb = sum(x * x for x in b) ** 0.5
    if na == 0.0 or nb == 0.0:
        return 0.0
    return dot / (na * nb)


def check_model_is_real():
    model = load_embedding_model()
    is_fallback = type(model).__name__ == "_FallbackModel"
    return is_fallback, type(model).__name__


def _stats(values):
    if not values:
        return "n/a"
    sd = statistics.pstdev(values) if len(values) > 1 else 0.0
    return (f"avg={statistics.mean(values):.4f}  min={min(values):.4f}  "
            f"max={max(values):.4f}  std={sd:.4f}")


def main():
    print("=" * 78)
    print("EMBEDDING QUALITY EVALUATION")
    print("=" * 78)

    is_fallback, model_class = check_model_is_real()
    if is_fallback:
        print("\n*** WARNING: sentence-transformers is NOT active. ***")
        print(f"Model in use: {model_class} (a hash-based stand-in, not a real")
        print("semantic embedding). Every similarity number below will be")
        print("close to random and this evaluation is not meaningful until")
        print("you `pip install sentence-transformers` and restart.\n")
    else:
        print(f"\nModel in use: {model_class}  (real semantic embedding - good)\n")

    fam_counts = defaultdict(int)
    for fam, _ in TEST_MESSAGES:
        fam_counts[fam] += 1
    n_scam_fams = sum(1 for f in fam_counts if not is_legit(f))
    n_scam = sum(c for f, c in fam_counts.items() if not is_legit(f))
    print(f"Embedding {len(TEST_MESSAGES)} test messages "
          f"({n_scam} scam in {n_scam_fams} families, "
          f"{fam_counts.get('LEGIT', 0)} legit, {fam_counts.get('LEGIT_HARD', 0)} hard-legit)...")

    records = []
    for family, text in TEST_MESSAGES:
        cleaned = _normalize_for_embedding(text)
        vec = [float(v) for v in generate_embedding(cleaned)]
        records.append({"family": family, "text": text, "cleaned": cleaned, "vec": vec})

    # ---- pairwise similarity ----
    pairs = []
    for a, b in itertools.combinations(records, 2):
        sim = cosine(a["vec"], b["vec"])
        same_family = (a["family"] == b["family"]) and not is_legit(a["family"])
        involves_legit = is_legit(a["family"]) or is_legit(b["family"])
        pairs.append({
            "text_a": a["text"], "family_a": a["family"],
            "text_b": b["text"], "family_b": b["family"],
            "similarity": round(sim, 4),
            "same_family": same_family,
            "involves_legit": involves_legit,
        })
    print(f"Computed {len(pairs)} pairwise similarities.")

    same_family_sims = [p["similarity"] for p in pairs if p["same_family"]]
    cross_family_sims = [p["similarity"] for p in pairs
                         if not p["same_family"] and not p["involves_legit"]]
    legit_sims = [p["similarity"] for p in pairs if p["involves_legit"]]
    hard_vs_scam = [p["similarity"] for p in pairs
                    if p["involves_legit"]
                    and ("LEGIT_HARD" in (p["family_a"], p["family_b"]))
                    and not (is_legit(p["family_a"]) and is_legit(p["family_b"]))]

    def avg(v):
        return sum(v) / len(v) if v else 0.0

    print("\n" + "-" * 78)
    print("SEPARATION (higher same-family avg, lower everything-else avg = better)")
    print("-" * 78)
    print(f"Same scam family, reworded (n={len(same_family_sims):>5}): {_stats(same_family_sims)}")
    print(f"Different scam families    (n={len(cross_family_sims):>5}): {_stats(cross_family_sims)}")
    print(f"Legit vs anything          (n={len(legit_sims):>5}): {_stats(legit_sims)}")
    print(f"Hard-legit vs scam         (n={len(hard_vs_scam):>5}): {_stats(hard_vs_scam)}")

    worst_other = max(avg(cross_family_sims), avg(legit_sims))
    margin = avg(same_family_sims) - worst_other
    print(f"\nSeparation margin (same-family avg minus worst other-group avg): {margin:+.4f}")
    if margin > 0.15:
        print("  -> Good separation: paraphrases cluster well above unrelated text.")
    elif margin > 0.05:
        print("  -> Weak separation: the model distinguishes paraphrases only a little.")
    else:
        print("  -> Poor/no separation: the embedding is not reliably telling paraphrases")
        print("     of the same scam apart from unrelated messages.")

    # ---- current threshold performance ----
    threshold = DEFAULT_SIMILARITY_THRESHOLD
    print("\n" + "-" * 78)
    print(f"CURRENT THRESHOLD PERFORMANCE (SEMANTIC_SIMILARITY_THRESHOLD = {threshold})")
    print("-" * 78)
    _report_threshold(pairs, threshold)

    # ---- ROC-AUC ----
    print(f"\nROC-AUC (threshold-free, same-family vs rest): {_auc(pairs):.4f}")

    # ---- threshold sweep ----
    print("\n" + "-" * 78)
    print("THRESHOLD SWEEP (which cutoff best separates same-family from the rest)")
    print("-" * 78)
    print(f"{'threshold':>10}{'precision':>12}{'recall':>10}{'f1':>10}{'FP':>8}{'FN':>8}")
    best = (None, -1.0)
    for t in [round(0.50 + 0.025 * i, 3) for i in range(19)]:
        p, r, f1, tp, fp, tn, fn = _prf(pairs, t)
        marker = "  <- current" if abs(t - threshold) < 0.0126 else ""
        print(f"{t:>10.3f}{p:>12.3f}{r:>10.3f}{f1:>10.3f}{fp:>8}{fn:>8}{marker}")
        if f1 > best[1]:
            best = (t, f1)
    print(f"\nBest F1 on this test set: threshold={best[0]} (F1={best[1]:.3f})")

    # ---- nearest-neighbour retrieval ----
    print("\n" + "-" * 78)
    print("NEAREST-NEIGHBOUR RETRIEVAL (mirrors production best-pattern lookup)")
    print("-" * 78)
    _nearest_neighbour_report(records, threshold)

    # ---- per-family ----
    print("\n" + "-" * 78)
    print("PER-FAMILY BREAKDOWN")
    print("-" * 78)
    fam_rows = _family_report(records, threshold)

    # ---- hard legit risk ----
    print("\n" + "-" * 78)
    print("HARD-LEGIT RISK (legit messages most similar to a scam)")
    print("-" * 78)
    _hard_legit_report(records, threshold)

    # ---- save matrices ----
    with OUT_CSV.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=[
            "family_a", "text_a", "family_b", "text_b", "similarity", "same_family", "involves_legit"
        ])
        writer.writeheader()
        for p in sorted(pairs, key=lambda x: -x["similarity"]):
            writer.writerow(p)
    print(f"\nFull pairwise similarity matrix saved to: {OUT_CSV}")

    with OUT_FAMILY_CSV.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(fam_rows[0].keys()))
        writer.writeheader()
        writer.writerows(fam_rows)
    print(f"Per-family summary saved to: {OUT_FAMILY_CSV}")

    _maybe_plot_heatmap(records)


# ----------------------------------------------------------------------------
# metrics helpers
# ----------------------------------------------------------------------------

def _classify(sim, threshold):
    # Mirrors semantic_spam_service's primary cosine-threshold decision
    # (the token-overlap fallback-match rescue depends on the full corpus,
    # not just a pair, so it is not modeled at the pair level here).
    return sim >= threshold


def _prf(pairs, threshold):
    tp = fp = tn = fn = 0
    for p in pairs:
        predicted_match = _classify(p["similarity"], threshold)
        actual_match = p["same_family"]
        if predicted_match and actual_match:
            tp += 1
        elif predicted_match and not actual_match:
            fp += 1
        elif not predicted_match and actual_match:
            fn += 1
        else:
            tn += 1
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    return precision, recall, f1, tp, fp, tn, fn


def _auc(pairs):
    pos = sorted(p["similarity"] for p in pairs if p["same_family"])
    neg = sorted(p["similarity"] for p in pairs if not p["same_family"])
    if not pos or not neg:
        return float("nan")
    # rank-based AUC (Mann-Whitney U), O(n log n)
    import bisect
    wins = 0.0
    for s in pos:
        lo = bisect.bisect_left(neg, s)
        hi = bisect.bisect_right(neg, s)
        wins += lo + 0.5 * (hi - lo)
    return wins / (len(pos) * len(neg))


def _report_threshold(pairs, threshold):
    precision, recall, f1, tp, fp, tn, fn = _prf(pairs, threshold)
    total = tp + fp + tn + fn
    print(f"True positives  (correctly matched paraphrases)      : {tp}")
    print(f"False positives (unrelated pairs wrongly matched)     : {fp}")
    print(f"True negatives  (correctly kept apart)                : {tn}")
    print(f"False negatives (paraphrases wrongly kept apart)      : {fn}")
    print(f"Accuracy: {(tp + tn) / total:.3f}   Precision: {precision:.3f}   "
          f"Recall: {recall:.3f}   F1: {f1:.3f}")
    if fp > 0:
        print(f"-> {fp} unrelated message pair(s) would incorrectly be treated as the")
        print("   same scam pattern at this threshold - risk of over-grouping.")
    if fn > 0:
        print(f"-> {fn} true paraphrase pair(s) would be missed as a match at this")
        print("   threshold - risk of the same scam being tracked as separate patterns.")


def _nearest_neighbour_report(records, threshold):
    scam_idx = [i for i, r in enumerate(records) if not is_legit(r["family"])]
    correct = 0
    correct_and_above = 0
    wrong_examples = []
    for i in scam_idx:
        best_j, best_sim = None, -1.0
        for j, other in enumerate(records):
            if j == i:
                continue
            s = cosine(records[i]["vec"], other["vec"])
            if s > best_sim:
                best_j, best_sim = j, s
        same = records[best_j]["family"] == records[i]["family"]
        if same:
            correct += 1
            if best_sim >= threshold:
                correct_and_above += 1
        else:
            wrong_examples.append((records[i], records[best_j], best_sim))
    n = len(scam_idx)
    print(f"Top-1 neighbour is from the SAME scam family : {correct}/{n} ({correct / n:.1%})")
    print(f"... and its similarity >= {threshold}          : {correct_and_above}/{n} ({correct_and_above / n:.1%})")
    if wrong_examples:
        print(f"\nScam messages whose nearest neighbour was a DIFFERENT family ({len(wrong_examples)}):")
        for rec, nb, s in wrong_examples[:10]:
            print(f"  [{rec['family']}] -> nearest [{nb['family']}] sim={s:.3f}")
            print(f"     \"{rec['text'][:80]}\"")
        if len(wrong_examples) > 10:
            print(f"  ... and {len(wrong_examples) - 10} more")


def _family_report(records, threshold):
    by_family = defaultdict(list)
    for i, r in enumerate(records):
        by_family[r["family"]].append(i)

    rows = []
    print(f"{'family':<24}{'n':>3}{'within':>9}{'other-scam':>12}{'legit':>8}{'recall@thr':>12}")
    print("-" * 68)
    for fam in sorted(by_family, key=lambda f: (is_legit(f), f)):
        if is_legit(fam):
            continue
        idx = by_family[fam]
        within, other_scam, legit = [], [], []
        for i in idx:
            for j, r in enumerate(records):
                if j == i:
                    continue
                s = cosine(records[i]["vec"], r["vec"])
                if r["family"] == fam:
                    within.append(s)
                elif is_legit(r["family"]):
                    legit.append(s)
                else:
                    other_scam.append(s)
        # each unordered within-family pair counted twice - harmless for the average
        recall = sum(1 for s in within if s >= threshold) / len(within) if within else 0.0
        row = {
            "family": fam, "n": len(idx),
            "within_avg": round(avg_list(within), 4),
            "other_scam_avg": round(avg_list(other_scam), 4),
            "legit_avg": round(avg_list(legit), 4),
            "paraphrase_recall_at_threshold": round(recall, 4),
        }
        rows.append(row)
        print(f"{fam:<24}{len(idx):>3}{row['within_avg']:>9.3f}{row['other_scam_avg']:>12.3f}"
              f"{row['legit_avg']:>8.3f}{recall:>12.3f}")
    weakest = sorted(rows, key=lambda r: r["paraphrase_recall_at_threshold"])[:3]
    print("\nWeakest families (lowest paraphrase recall): " +
          ", ".join(f"{r['family']} ({r['paraphrase_recall_at_threshold']:.2f})" for r in weakest))
    return rows


def avg_list(v):
    return sum(v) / len(v) if v else 0.0


def _hard_legit_report(records, threshold):
    scams = [r for r in records if not is_legit(r["family"])]
    hard = [r for r in records if r["family"] == "LEGIT_HARD"]
    flagged = 0
    results = []
    for h in hard:
        best_s, best_r = -1.0, None
        for s in scams:
            sim = cosine(h["vec"], s["vec"])
            if sim > best_s:
                best_s, best_r = sim, s
        results.append((best_s, h, best_r))
        if best_s >= threshold:
            flagged += 1
    results.sort(key=lambda x: -x[0])
    print(f"Hard-legit messages whose best scam match >= {threshold}: {flagged}/{len(hard)}")
    print("(these would be wrongly treated as a known scam pattern by the semantic gate)\n")
    for sim, h, s in results[:8]:
        flag = "  <-- FALSE MATCH RISK" if sim >= threshold else ""
        print(f"  sim={sim:.3f}  legit: \"{h['text'][:60]}\"{flag}")
        print(f"             closest scam [{s['family']}]: \"{s['text'][:60]}\"")


def _maybe_plot_heatmap(records):
    """Plot a family-averaged heatmap (a 190x190 message-level grid is unreadable)."""
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        import numpy as np
    except ImportError:
        print("\n(matplotlib not installed - skipping heatmap image; CSVs have the full data)")
        return

    fams = sorted({r["family"] for r in records}, key=lambda f: (is_legit(f), f))
    idx = {f: [i for i, r in enumerate(records) if r["family"] == f] for f in fams}
    n = len(fams)
    m = np.zeros((n, n))
    for a, fa in enumerate(fams):
        for b, fb in enumerate(fams):
            vals = [cosine(records[i]["vec"], records[j]["vec"])
                    for i in idx[fa] for j in idx[fb] if i != j]
            m[a, b] = sum(vals) / len(vals) if vals else 0.0

    fig, ax = plt.subplots(figsize=(11, 9))
    im = ax.imshow(m, vmin=0, vmax=1, cmap="viridis")
    ax.set_xticks(range(n))
    ax.set_yticks(range(n))
    ax.set_xticklabels(fams, rotation=60, ha="right", fontsize=8)
    ax.set_yticklabels(fams, fontsize=8)
    fig.colorbar(im, label="avg cosine similarity")
    ax.set_title("Average embedding similarity by family\n(bright diagonal + dark off-diagonal = good separation)")
    fig.tight_layout()
    fig.savefig(OUT_PNG, dpi=150)
    print(f"\nFamily-level similarity heatmap saved to: {OUT_PNG}")


if __name__ == "__main__":
    main()