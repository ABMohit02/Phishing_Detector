import socket, whois, pickle, pandas as pd
from datetime import datetime, timezone
from urllib.parse import urlparse
from detector import extract_features

model = pickle.load(open("model.pkl", "rb"))
feature_names = pickle.load(open("feature_names.pkl", "rb"))

url = "http://xyz.com"
hostname = urlparse(url).hostname

# DNS Check
try:
    socket.setdefaulttimeout(5)
    socket.gethostbyname(hostname)
    resolves = True
except Exception:
    resolves = False

# WHOIS Check
age_days = None
try:
    w = whois.whois(hostname)
    cd = w.creation_date
    if isinstance(cd, list):
        cd = cd[0]
    if cd:
        now = datetime.now(timezone.utc) if cd.tzinfo else datetime.now()
        age_days = (now - cd).days
        print(f"WHOIS creation_date : {cd}")
        print(f"WHOIS age           : {age_days} days ({age_days // 365} years)")
        print(f"WHOIS registrar     : {w.registrar}")
    else:
        print("WHOIS creation_date : None")
except Exception as e:
    print(f"WHOIS error         : {e}")

# ML Check
features = extract_features(url)
features_df = pd.DataFrame([features])[feature_names]
probas = model.predict_proba(features_df)[0]
prob_dict = dict(zip(model.classes_, probas))
legit = prob_dict.get("legitimate", 0)
phish = prob_dict.get("phishing", 0)

print(f"DNS resolves        : {resolves}")
print(f"dns_record feature  : {features['dns_record']}")
print(f"ML legitimate       : {legit * 100:.1f}%")
print(f"ML phishing         : {phish * 100:.1f}%")
print()

# Final decision
if not resolves:
    result, reason = "PHISHING", "DNS failed"
elif age_days is None:
    result = "LEGITIMATE" if legit >= 0.75 else "PHISHING"
    reason = "WHOIS unknown, fell back to ML"
elif age_days < 365:
    result, reason = "PHISHING", f"Domain only {age_days} days old"
else:
    result = "LEGITIMATE" if legit >= 0.75 else "PHISHING"
    reason = f"Old domain ({age_days} days), ML={legit*100:.1f}%"

print(f"FINAL RESULT => {result}  ({reason})")
