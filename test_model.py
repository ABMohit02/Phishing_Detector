import socket, whois, pickle, pandas as pd
from datetime import datetime, timezone
from urllib.parse import urlparse
from detector import extract_features

model = pickle.load(open("model.pkl", "rb"))
feature_names = pickle.load(open("feature_names.pkl", "rb"))

def domain_resolves(url):
    try:
        hostname = urlparse(url).hostname
        if not hostname: return False
        socket.setdefaulttimeout(5)
        socket.gethostbyname(hostname)
        return True
    except: return False

def check_whois(url):
    try:
        hostname = urlparse(url).hostname
        if not hostname: return 'no_exist'
        parts = hostname.split('.')
        root = '.'.join(parts[-2:]) if len(parts) >= 2 else hostname
        w = whois.whois(root)
        if not w or not w.domain_name: return 'no_exist'
        cd = w.creation_date
        if isinstance(cd, list): cd = cd[0]
        if cd is None: return 'unknown'
        now = datetime.now(timezone.utc) if cd.tzinfo else datetime.now()
        age_days = (now - cd).days
        return 'new' if age_days < 365 else 'old'
    except Exception as e:
        err = str(e).lower()
        if 'no match' in err or 'not found' in err or 'no data' in err:
            return 'no_exist'
        return 'unknown'

test_urls = [
    "http://anyname.com",
    "http://fakehello.com",
    "http://google.com",
    "http://xyzabc123fake.com",
    "http://secure-login-paypal.com/verify",
    "http://netflix.com",
]

for url in test_urls:
    resolves = domain_resolves(url)
    if not resolves:
        result = "phishing"
        reason = "DNS failed"
    else:
        ws = check_whois(url)
        if ws == 'no_exist':
            result = "phishing"
            reason = "WHOIS: no record"
        elif ws == 'new':
            result = "phishing"
            reason = "WHOIS: domain < 1 year old"
        else:
            features = extract_features(url)
            features_df = pd.DataFrame([features])[feature_names]
            probas = model.predict_proba(features_df)[0]
            prob_dict = dict(zip(model.classes_, probas))
            legit = prob_dict.get("legitimate", 0)
            result = "legitimate" if legit >= 0.75 else "phishing"
            reason = f"ML: {ws} domain, legit={legit*100:.1f}%"

    print(f"{url}")
    print(f"  => {result.upper()}  ({reason})")
    print()
