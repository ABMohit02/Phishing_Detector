from flask import Flask, request, render_template
import pickle
import pandas as pd
import socket
import whois
from datetime import datetime, timezone
from detector import extract_features
from urllib.parse import urlparse

app = Flask(__name__)
model = pickle.load(open("model.pkl", "rb"))
feature_names = pickle.load(open("feature_names.pkl", "rb"))

# Known legitimate domains - always safe
WHITELIST = [
    "google.com", "youtube.com", "facebook.com", "twitter.com", "instagram.com",
    "microsoft.com", "apple.com", "amazon.com", "wikipedia.org", "reddit.com",
    "linkedin.com", "github.com", "stackoverflow.com", "netflix.com", "spotify.com",
    "whatsapp.com", "telegram.org", "dropbox.com", "gmail.com", "outlook.com",
    "yahoo.com", "bing.com", "adobe.com", "cloudflare.com", "wordpress.com",
    "shopify.com", "paypal.com", "ebay.com", "twitch.tv", "discord.com","railway.app",
]

def is_whitelisted(url):
    try:
        hostname = urlparse(url).hostname or ""
        # Check if hostname ends with any whitelisted domain
        return any(hostname == d or hostname.endswith("." + d) for d in WHITELIST)
    except:
        return False

def domain_resolves(url):
    """Returns True if the domain resolves to a valid IP (i.e., it actually exists)."""
    try:
        hostname = urlparse(url).hostname
        if not hostname:
            return False
        socket.setdefaulttimeout(5)
        socket.gethostbyname(hostname)
        return True
    except (socket.gaierror, socket.timeout):
        return False

def check_whois(url):
    """
    Returns:
      'no_exist'  - domain has no WHOIS record (doesn't exist)
      'new'       - domain registered < 365 days ago
      'old'       - domain is established (>= 365 days old)
      'unknown'   - WHOIS lookup failed for other reasons
    """
    try:
        hostname = urlparse(url).hostname
        if not hostname:
            return 'no_exist'
        # Strip subdomains to get root domain
        parts = hostname.split('.')
        root = '.'.join(parts[-2:]) if len(parts) >= 2 else hostname
        w = whois.whois(root)
        if not w or not w.domain_name:
            return 'no_exist'
        cd = w.creation_date
        if isinstance(cd, list):
            cd = cd[0]
        if cd is None:
            return 'unknown'
        # Fix timezone-aware vs naive comparison
        if cd.tzinfo is not None:
            now = datetime.now(timezone.utc)
        else:
            now = datetime.now()
        age_days = (now - cd).days
        return 'new' if age_days < 365 else 'old'
    except Exception as e:
        err = str(e).lower()
        if 'no match' in err or 'not found' in err or 'no data' in err:
            return 'no_exist'
        return 'unknown'

@app.route("/", methods=["GET", "POST"])
def home():
    if request.method == "POST":
        url = request.form["url"]
        if is_whitelisted(url):
            result = "legitimate"
        else:
            # Step 1: DNS check - must resolve at all
            if not domain_resolves(url):
                result = "phishing"
            else:
                # Step 2: WHOIS check - must exist and not be brand new
                whois_status = check_whois(url)
                if whois_status == 'no_exist':
                    result = "phishing"
                elif whois_status == 'new':
                    result = "phishing"  # Newly registered = suspicious
                else:
                    # Step 3: ML model for established domains
                    features = extract_features(url)
                    features_df = pd.DataFrame([features])[feature_names]
                    probas = model.predict_proba(features_df)[0]
                    classes = model.classes_
                    prob_dict = dict(zip(classes, probas))
                    # Require 75%+ confidence to call a URL legitimate
                    if prob_dict.get("legitimate", 0) >= 0.75:
                        result = "legitimate"
                    else:
                        result = "phishing"
        return render_template("index.html", result=result)
    return render_template("index.html")

if __name__ == "__main__":
    app.run(debug=True)