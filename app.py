from flask import Flask, request, render_template
import socket
import whois
import requests
from datetime import datetime, timezone
from urllib.parse import urlparse

app = Flask(__name__)

# Known legitimate domains - only super major ones
WHITELIST = [
    "google.com", "youtube.com", "facebook.com", "twitter.com", "instagram.com",
    "microsoft.com", "apple.com", "amazon.com", "wikipedia.org", "reddit.com",
]

def is_whitelisted(url):
    try:
        hostname = urlparse(url).hostname or ""
        return any(hostname == d or hostname.endswith("." + d) for d in WHITELIST)
    except:
        return False

def domain_resolves(url):
    """Returns True if the domain resolves to a valid IP."""
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
    """Returns: 'no_exist', 'new', 'old', or 'unknown'"""
    try:
        hostname = urlparse(url).hostname
        if not hostname:
            return 'no_exist'
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

def check_phishtank_live(url):
    """Check if URL is in PhishTank database (LIVE)"""
    try:
        response = requests.get(
            "https://phishtank.com/api/ioc/",
            params={"url": url, "format": "json", "app_token": "phishing_detector_app"},
            timeout=5
        )
        if response.status_code == 200:
            data = response.json()
            if data.get("results") and len(data["results"]) > 0:
                return True  # Found in phishing database
    except:
        pass
    return False

def check_urlhaus_live(url):
    """Check if URL is in URLhaus database (LIVE)"""
    try:
        response = requests.post(
            "https://urlhaus-api.abuse.ch/v1/url/",
            data={"url": url},
            timeout=5
        )
        if response.status_code == 200:
            data = response.json()
            if data.get("query_status") == "ok" and data.get("threat"):
                return True  # Found as malicious
    except:
        pass
    return False

@app.route("/", methods=["GET", "POST"])
def home():
    if request.method == "POST":
        url = request.form["url"]
        print(f"\n🔍 Checking URL: {url}")
        
        detection_steps = []
        
        if is_whitelisted(url):
            print("✓ Whitelisted domain")
            detection_steps.append(("✓ Whitelisted Domain", "This domain is known to be safe"))
            result = "legitimate"
        else:
            detection_steps.append(("⚠ Not on whitelist", "Running full checks..."))
            
            # Step 1: DNS check - if doesn't resolve, it's phishing
            dns_ok = domain_resolves(url)
            if dns_ok:
                print("✓ DNS check passed - domain exists")
                detection_steps.append(("✓ DNS Resolution", "Domain exists and resolves to an IP"))
            else:
                print("❌ DNS check failed - domain doesn't resolve")
                detection_steps.append(("✗ DNS Resolution", "Domain doesn't resolve - likely phishing"))
                result = "phishing"
                return render_template("index.html", result=result, steps=detection_steps)
            
            # Step 2: Check LIVE PhishTank database
            phishtank_check = check_phishtank_live(url)
            if phishtank_check:
                print("❌ Found in PhishTank database")
                detection_steps.append(("✗ PhishTank Database", "URL found in phishing database"))
                result = "phishing"
                return render_template("index.html", result=result, steps=detection_steps)
            else:
                print("✓ Not in PhishTank")
                detection_steps.append(("✓ PhishTank Check", "Not found in phishing database"))
            
            # Step 3: Check LIVE URLhaus database
            urlhaus_check = check_urlhaus_live(url)
            if urlhaus_check:
                print("❌ Found in URLhaus database")
                detection_steps.append(("✗ URLhaus Database", "URL flagged as malicious"))
                result = "phishing"
                return render_template("index.html", result=result, steps=detection_steps)
            else:
                print("✓ Not in URLhaus")
                detection_steps.append(("✓ URLhaus Check", "Not found in malware database"))
            
            # Step 4: Check domain type
            hostname = urlparse(url).hostname or ""
            is_government_domain = any(hostname.endswith(ext) for ext in ['.gov', '.edu', '.org', '.gov.in', '.ac.in', '.nic.in'])
            
            if is_government_domain:
                print(f"✓ Trusted domain type (.gov/.edu/.org)")
                detection_steps.append(("✓ Domain Type", f"Trusted TLD ({hostname.split('.')[-1]})"))
                result = "legitimate"
            else:
                # Step 5: WHOIS age check
                whois_status = check_whois(url)
                print(f"📋 WHOIS status: {whois_status}")
                
                if whois_status == 'new':
                    print(f"❌ Domain is brand new (< 1 year old)")
                    detection_steps.append(("✗ Domain Age", "Domain registered < 1 year ago (suspicious)"))
                    result = "phishing"
                else:
                    print(f"✓ Domain age seems OK")
                    if whois_status == 'old':
                        detection_steps.append(("✓ Domain Age", "Domain is established (1+ years old)"))
                    else:
                        detection_steps.append(("✓ Domain Status", f"Domain status: {whois_status}"))
                    result = "legitimate"
        
        print(f"🎯 Result: {result}\n")
        return render_template("index.html", result=result, steps=detection_steps)
    return render_template("index.html")

if __name__ == "__main__":
    app.run(debug=True)
