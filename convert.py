import requests
import re
import csv
import numpy as np

# === Feature names in the same order as FeatureExtraction produces them ===
FEATURE_NAMES = [
    "UsingIp", "longUrl", "shortUrl", "symbol", "redirecting",
    "prefixSuffix", "SubDomains", "Hppts", "DomainRegLen", "Favicon",
    "NonStdPort", "HTTPSDomainURL", "RequestURL", "AnchorURL",
    "LinksInScriptTags", "ServerFormHandler", "InfoEmail", "AbnormalURL",
    "WebsiteForwarding", "StatusBarCust", "DisableRightClick",
    "UsingPopupWindow", "IframeRedirection", "AgeofDomain", "DNSRecording",
    "WebsiteTraffic", "PageRank", "GoogleIndex", "LinksPointingToPage",
    "StatsReport"
]


def convertion(url, prediction):
    """
    Converts model output and URL into a display-friendly structure for Flask templates.
    Returns: [url, "Safe"/"Not Safe", button_text, optional_flag]
    """
    # Check for shortened links (auto mark as risky)
    if shortlink(url) == -1:
        return [url, "Not Safe", "Still want to Continue"]

    # prediction: 1 = safe, -1 = phishing
    if prediction == 1:
        return [url, "Safe", "Continue", "1"]
    else:
        return [url, "Not Safe", "Still want to Continue"]


def shortlink(url):
    """
    Detect if URL uses a known URL shortener (bit.ly, tinyurl, etc.)
    Return -1 if shortener found, else 1.
    """
    match = re.search(
        r'bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|'
        r'yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|'
        r'short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|'
        r'doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|lnkd\.in|db\.tt|'
        r'qr\.ae|adf\.ly|bitly\.com|cur\.lv|tinyurl\.com|ity\.im|q\.gs|is\.gd|po\.st|bc\.vc|twitthis\.com|'
        r'u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|prettylinkpro\.com|scrnch\.me|filoops\.info|'
        r'vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|tr\.im|link\.zip\.net',
        url, flags=re.IGNORECASE
    )
    return -1 if match else 1


def find_url_in_csv(csv_file, target_url):
    """
    Look up a URL inside a CSV dataset.
    Returns the URL if found, else None.
    """
    try:
        with open(csv_file, 'r', newline='', encoding='utf-8') as file:
            csv_reader = csv.reader(file)
            for row in csv_reader:
                if not row:
                    continue
                url = row[0].strip()
                if url == target_url:
                    return url
    except FileNotFoundError:
        print(f"⚠️ CSV file not found: {csv_file}")
    return None


# ----------------- Explainable AI (XAI) helper -----------------
def explain_decision(url, prediction, feature_list=None, live_info=None, model=None, feature_names=None):
    """
    Generate a short human-readable explanation for why the URL was marked Safe or Phishing.

    Args:
      url: str
      prediction: int (1 = safe, -1 = phishing)
      feature_list: list of numeric values (model input)
      live_info: dict with live scan results (SSL, redirects, etc.)
      model: trained ML model (optional)
      feature_names: list of feature names

    Returns:
      explanation (str), reasons (list)
    """
    reasons = []

    # --- Live scan based explanation ---
    if live_info:
        if live_info.get('hostname_is_ip'):
            reasons.append("Uses IP address instead of domain name (suspicious)")
        if live_info.get('redirects', 0) >= 3:
            reasons.append(f"Too many redirects ({live_info['redirects']})")
        if not live_info.get('uses_https', False):
            reasons.append("No HTTPS detected (insecure site)")
        if not live_info.get('ssl_valid', True):
            reasons.append("SSL certificate is invalid or expired")
        whois_age = live_info.get('whois_age_days')
        if whois_age is not None and whois_age < 90:
            reasons.append(f"Domain age is too new ({whois_age} days old)")

    # --- Model-driven explanation (feature importance) ---
    if model is not None and feature_names is not None and feature_list is not None:
        try:
            importances = None
            if hasattr(model, 'feature_importances_'):
                importances = model.feature_importances_
            elif hasattr(model, 'coef_'):
                importances = np.abs(model.coef_).ravel()

            if importances is not None:
                top_idx = np.argsort(importances)[::-1][:5]
                for idx in top_idx:
                    fname = feature_names[idx] if idx < len(feature_names) else f"Feature {idx}"
                    fval = feature_list[idx] if idx < len(feature_list) else None
                    reasons.append(f"Model found '{fname}' important (value={fval})")
        except Exception as e:
            print("⚠️ Could not extract model feature importance:", e)

    # --- Fallback explanation ---
    if not reasons:
        if prediction == 1:
            explanation = "✅ This website is likely safe based on model prediction and live checks."
        else:
            explanation = "⚠️ The model flagged this website as potentially unsafe based on its features."
    else:
        explanation = "⚠️ This website was flagged because: " + " | ".join(reasons)

    return explanation, reasons
