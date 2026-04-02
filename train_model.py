import pandas as pd
import socket
from urllib.parse import urlparse
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report
import pickle

# Load dataset
data = pd.read_csv("dataset.csv")

# --- Compute dns_record from URLs in the dataset ---
def resolve_dns(url):
    try:
        hostname = urlparse(str(url)).hostname
        if not hostname:
            return 0
        socket.setdefaulttimeout(3)
        socket.gethostbyname(hostname)
        return 1
    except:
        return 0

# Use the dns_record column from dataset if it exists, otherwise compute it
# (The dataset already has dns_record as 0/1 — 1 = DNS exists, 0 = no DNS record)
# We keep it in training instead of dropping it!
print("dns_record distribution in dataset:")
print(data["dns_record"].value_counts())

# Drop URL, label, and features that require live page inspection
drop_cols = [
    "status", "url",
    # These require live page inspection or external APIs
    "nb_hyperlinks", "ratio_intHyperlinks", "ratio_extHyperlinks",
    "ratio_nullHyperlinks", "nb_extCSS", "ratio_intRedirection",
    "ratio_extRedirection", "ratio_intErrors", "ratio_extErrors",
    "login_form", "external_favicon", "links_in_tags", "submit_email",
    "ratio_intMedia", "ratio_extMedia", "sfh", "iframe", "popup_window",
    "safe_anchor", "onmouseover", "right_clic", "empty_title",
    "domain_in_title", "domain_with_copyright", "whois_registered_domain",
    "domain_registration_length", "domain_age", "web_traffic",
    # KEPT: dns_record  <-- no longer dropped!
    "google_index", "page_rank", "statistical_report",
    "domain_in_brand", "brand_in_subdomain", "brand_in_path"
]

X = data.drop(columns=drop_cols)
y = data["status"]

print("Training on features:", list(X.columns))
print("Total features:", len(X.columns))

# Split data
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Train model
model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train, y_train)

# Evaluate
y_pred = model.predict(X_test)
print(f"Model Accuracy: {accuracy_score(y_test, y_pred) * 100:.2f}%")
print(classification_report(y_test, y_pred))

# Save model and feature names
pickle.dump(model, open("model.pkl", "wb"))
pickle.dump(list(X.columns), open("feature_names.pkl", "wb"))

print("Model trained and saved successfully!")