# --- Imports ---
from flask import Flask, request, render_template
from convert import convertion, explain_decision, FEATURE_NAMES
import numpy as np
import warnings
import pickle
from feature import FeatureExtraction
import requests
import socket
import ssl
import whois
from datetime import datetime
from urllib.parse import urlparse
import concurrent.futures

warnings.filterwarnings('ignore')

# --- Load Model ---
with open("newmodel.pkl", "rb") as f:
    gbc = pickle.load(f)

app = Flask(__name__)

# --- Helper Function: Live Threat Scan ---
def live_threat_scan(url):
    data = {
        "final_url": None,
        "redirects": 0,
        "uses_https": False,
        "ssl_valid": None,
        "ssl_expiry": None,
        "whois_age_days": None,
        "hostname_is_ip": None
    }

    try:
        # Ensure proper scheme
        if not url.startswith(("http://", "https://")):
            url = "http://" + url

        # Fast HTTP request with short timeout (2 seconds)
        resp = requests.get(url, timeout=2, allow_redirects=True)
        data["final_url"] = resp.url
        data["redirects"] = len(resp.history)
        data["uses_https"] = resp.url.startswith("https")

        parsed = urlparse(resp.url)
        hostname = parsed.hostname

        # Check if hostname is an IP
        try:
            socket.inet_aton(hostname)
            data["hostname_is_ip"] = True
        except Exception:
            data["hostname_is_ip"] = False

        # SSL certificate details (quick check, 1.5s timeout)
        if data["uses_https"]:
            try:
                ctx = ssl.create_default_context()
                with ctx.wrap_socket(socket.socket(), server_hostname=hostname) as s:
                    s.settimeout(1.5)
                    s.connect((hostname, 443))
                    cert = s.getpeercert()
                    not_after = datetime.strptime(cert['notAfter'], "%b %d %H:%M:%S %Y %Z")
                    data["ssl_expiry"] = not_after.strftime("%Y-%m-%d")
                    data["ssl_valid"] = not_after > datetime.utcnow()
            except Exception as e:
                print(f"[SSL] SSL check failed for {hostname}: {e}")
                data["ssl_valid"] = False

        # WHOIS domain age — run in background with timeout, support multiple backends
        def _fetch_creation(h):
            try:
                # Try whois.whois() first
                try:
                    info = whois.whois(h)
                    if isinstance(info, dict):
                        return info.get('creation_date')
                    if hasattr(info, 'creation_date'):
                        return info.creation_date
                except Exception as e1:
                    print(f"[WHOIS] whois.whois() failed for {h}: {e1}")
                
                # Try whois.query() as fallback
                try:
                    if hasattr(whois, 'query'):
                        info = whois.query(h)
                        if hasattr(info, 'creation_date'):
                            return info.creation_date
                except Exception as e2:
                    print(f"[WHOIS] whois.query() failed for {h}: {e2}")
                
                print(f"[WHOIS] No backend method available for {h}")
            except Exception as e:
                print(f"[WHOIS] Unexpected error in _fetch_creation for {h}: {e}")
            return None

        try:
            created = None
            if hostname:
                with concurrent.futures.ThreadPoolExecutor(max_workers=1) as exe:
                    fut = exe.submit(_fetch_creation, hostname)
                    try:
                        created = fut.result(timeout=2)
                        print(f"[WHOIS] Got result for {hostname}: {created} (type: {type(created)})")
                    except concurrent.futures.TimeoutError:
                        print(f"[WHOIS] Timeout for {hostname}")
                        created = None

            # Handle list (sometimes whois returns a list of values)
            if isinstance(created, list) and len(created) > 0:
                created = created[0]
                print(f"[WHOIS] Extracted from list: {created}")

            # Parse string dates
            if isinstance(created, str):
                try:
                    from dateutil import parser as _parser
                    created = _parser.parse(created)
                    print(f"[WHOIS] Parsed string to datetime: {created}")
                except Exception as e:
                    print(f"[WHOIS] Failed to parse string '{created}': {e}")
                    created = None

            # Calculate age if we have a datetime
            if isinstance(created, datetime):
                try:
                    age_days = (datetime.now() - created).days
                    data["whois_age_days"] = age_days
                    print(f"[WHOIS] Domain age: {age_days} days for {hostname}")
                except Exception as e:
                    print(f"[WHOIS] Failed to calculate age: {e}")
                    data["whois_age_days"] = None
            else:
                print(f"[WHOIS] created is not datetime: {type(created)} = {created}")
                data["whois_age_days"] = None
        except Exception as e:
            print(f"[WHOIS] Failed for {hostname}: {e}")
            data["whois_age_days"] = None

    except Exception as e:
        print(f"[!] Live scan failed for {url}: {e}")

    return data


# --- Helper Function: Explainable Reason ---
def explain_prediction(prob, features):
    if prob > 0.8:
        return "✅ This website looks legitimate. SSL and WHOIS data appear valid."
    elif prob > 0.5:
        return "⚠️ This site is probably safe but has a few suspicious signals."
    elif prob > 0.2:
        return "🚨 Multiple red flags detected — unverified SSL or recent domain registration."
    else:
        return "❌ This URL strongly resembles known phishing patterns. Avoid it."


# --- Home Route ---
@app.route("/")
def home():
    return render_template("index.html")


# --- Usecases Route ---
@app.route("/usecases")
def usecases():
    return render_template("usecases.html")


# --- Result Route (Main logic) ---
@app.route("/result", methods=["POST"])
def result():
    url = request.form.get("url") or request.form.get("name") or request.form.get("link")
    if not url:
        return render_template("index.html", error="Please enter a URL and submit the form.")

    # Normalize URL
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    # Extract features using feature.py logic
    try:
        obj = FeatureExtraction(url)
        features = obj.getFeaturesList()
    except Exception as e:
        print(f"[FeatureExtraction] Failed for {url}: {e}")
        return render_template("index.html", error=f"Feature extraction failed: {e}")

    # Live scan with timeout so model prediction isn't blocked
    live_info = {}
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as exe:
            fut = exe.submit(live_threat_scan, url)
            try:
                live_info = fut.result(timeout=5)
                print(f"[LiveScan] Completed: domain_age={live_info.get('whois_age_days')}")
            except concurrent.futures.TimeoutError:
                print(f"[LiveScan] Timeout for {url} - returning results immediately")
    except Exception as e:
        print(f"[!] Live scan error: {e}")

    # Model Prediction
    try:
        x = np.array(features).reshape(1, -1)
        y_pred = int(gbc.predict(x)[0])
        prob = float(gbc.predict_proba(x)[0][1])  # phishing probability
    except Exception as e:
        print(f"[!] Prediction error: {e}")
        return render_template("index.html", error=f"Prediction failed: {e}")

    # Explainable reason (AI explainability)
    try:
        explanation, reasons = explain_decision(
            url,
            y_pred,
            feature_list=features,
            live_info=live_info,
            model=gbc,
            feature_names=FEATURE_NAMES
        )
    except Exception as e:
        print(f"[Explain] Fallback reason used: {e}")
        explanation = explain_prediction(prob, features)
        reasons = []

    # Readable output name (Safe / Phishing)
    name = convertion(url, y_pred)

    # Log final output in console (optional)
    print(f"\n--- RESULT ---")
    print(f"URL: {url}")
    print(f"Prediction: {name} | Probability: {prob:.3f}")
    print(f"Live Data: {live_info}")
    print(f"Explanation: {explanation}")
    print("-----------------\n")

    # Send everything to front-end
    return render_template(
        "index.html",
        name=name,
        live=live_info,
        explanation=explanation,
        reasons=reasons
    )


# --- Main Entry ---
if __name__ == "__main__":
    app.run(debug=True)
