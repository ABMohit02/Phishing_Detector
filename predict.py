import pickle
import pandas as pd
from detector import extract_features

model = pickle.load(open("model.pkl", "rb"))
feature_names = pickle.load(open("feature_names.pkl", "rb"))

url = input("Enter URL: ")
features = extract_features(url)
features_df = pd.DataFrame([features])[feature_names]

prediction = model.predict(features_df)[0]

if prediction == 1:
    print("⚠️ Phishing Website Detected!")
else:
    print("✅ Safe Website")