import ipaddress
import ssl
import re
import urllib.request
from bs4 import BeautifulSoup
import socket
import requests
from googlesearch import search
import whois
from datetime import date, datetime
from dateutil.parser import parse as date_parse
from urllib.parse import urlparse


class FeatureExtraction:
    def __init__(self, url):
        self.url = url
        self.domain = ""
        self.whois_response = ""
        self.urlparse = ""
        self.response = None
        self.soup = None

        try:
            self.response = requests.get(url, timeout=8)
            self.soup = BeautifulSoup(self.response.text, 'html.parser')
        except Exception:
            pass

        try:
            self.urlparse = urlparse(url)
            self.domain = self.urlparse.netloc
        except Exception:
            pass

        try:
            self.whois_response = whois.whois(self.domain)
        except Exception:
            pass

    # ---------------- FEATURE FUNCTIONS ----------------

    def UsingIp(self):
        try:
            ipaddress.ip_address(self.url)
            return -1
        except Exception:
            return 1

    def longUrl(self):
        if len(self.url) < 54:
            return 1
        elif len(self.url) <= 75:
            return 0
        return -1

    def shortUrl(self):
        match = re.search(
            r'bit\.ly|goo\.gl|shorte\.st|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|'
            r'url4\.eu|su\.pr|snipurl\.com|bit\.do|lnkd\.in|db\.tt|qr\.ae|adf\.ly|ity\.im|'
            r'u\.to|j\.mp|cutt\.us|v\.gd|link\.zip\.net',
            self.url
        )
        return -1 if match else 1

    def symbol(self):
        return -1 if "@" in self.url else 1

    def redirecting(self):
        return -1 if self.url.rfind('//') > 6 else 1

    def prefixSuffix(self):
        return -1 if '-' in self.domain else 1

    def SubDomains(self):
        count = self.url.count('.')
        if count == 1:
            return 1
        elif count == 2:
            return 0
        return -1

    def Hppts(self):
        try:
            return 1 if self.urlparse.scheme == "https" else -1
        except Exception:
            return 1

    def DomainRegLen(self):
        try:
            exp = self.whois_response.expiration_date
            crt = self.whois_response.creation_date
            if isinstance(exp, list): exp = exp[0]
            if isinstance(crt, list): crt = crt[0]
            age = (exp.year - crt.year) * 12 + (exp.month - crt.month)
            return 1 if age >= 12 else -1
        except Exception:
            return -1

    def Favicon(self):
        try:
            for head in self.soup.find_all('head'):
                for link in head.find_all('link', href=True):
                    if self.domain in link['href'] or self.url in link['href']:
                        return 1
            return -1
        except Exception:
            return -1

    def NonStdPort(self):
        return -1 if ":" in self.domain else 1

    def HTTPSDomainURL(self):
        return -1 if 'https' in self.domain else 1

    def RequestURL(self):
        try:
            total, valid = 0, 0
            for tag in ['img', 'audio', 'embed', 'iframe']:
                for item in self.soup.find_all(tag, src=True):
                    total += 1
                    if self.domain in item['src'] or self.url in item['src']:
                        valid += 1
            if total == 0:
                return 0
            percent = valid / total * 100
            if percent < 22:
                return 1
            elif percent < 61:
                return 0
            else:
                return -1
        except Exception:
            return -1

    def AnchorURL(self):
        try:
            total, unsafe = 0, 0
            for a in self.soup.find_all('a', href=True):
                href = a['href'].lower()
                total += 1
                if '#' in href or 'javascript' in href or 'mailto' in href or not (
                    self.domain in href or self.url in href
                ):
                    unsafe += 1
            if total == 0:
                return 0
            percent = unsafe / total * 100
            if percent < 31:
                return 1
            elif percent < 67:
                return 0
            else:
                return -1
        except Exception:
            return -1

    def LinksInScriptTags(self):
        try:
            total, valid = 0, 0
            for tag in ['link', 'script']:
                for item in self.soup.find_all(tag, src=True):
                    total += 1
                    if self.domain in item['src'] or self.url in item['src']:
                        valid += 1
            if total == 0:
                return 0
            percent = valid / total * 100
            if percent < 17:
                return 1
            elif percent < 81:
                return 0
            else:
                return -1
        except Exception:
            return -1

    def ServerFormHandler(self):
        try:
            forms = self.soup.find_all('form', action=True)
            if len(forms) == 0:
                return 1
            for f in forms:
                action = f['action']
                if action == "" or action == "about:blank":
                    return -1
                elif self.domain not in action and self.url not in action:
                    return 0
            return 1
        except Exception:
            return -1

    def InfoEmail(self):
        try:
            if re.findall(r"mailto:", str(self.soup)):
                return -1
            return 1
        except Exception:
            return -1

    def AbnormalURL(self):
        try:
            return 1 if self.response and self.domain in self.response.url else -1
        except Exception:
            return -1

    def WebsiteForwarding(self):
        try:
            count = len(self.response.history)
            if count <= 1:
                return 1
            elif count <= 4:
                return 0
            else:
                return -1
        except Exception:
            return -1

    def StatusBarCust(self):
        try:
            return -1 if re.findall("<script>.+onmouseover.+</script>", self.response.text) else 1
        except Exception:
            return -1

    def DisableRightClick(self):
        try:
            return -1 if re.findall(r"event.button ?== ?2", self.response.text) else 1
        except Exception:
            return -1

    def UsingPopupWindow(self):
        try:
            return -1 if re.findall(r"alert\(", self.response.text) else 1
        except Exception:
            return -1

    def IframeRedirection(self):
        try:
            return -1 if re.findall(r"<iframe", self.response.text) else 1
        except Exception:
            return -1

    def AgeofDomain(self):
        try:
            crt = self.whois_response.creation_date
            if isinstance(crt, list): crt = crt[0]
            age = (date.today().year - crt.year) * 12 + (date.today().month - crt.month)
            return 1 if age >= 6 else -1
        except Exception:
            return -1

    def DNSRecording(self):
        return self.AgeofDomain()

    def WebsiteTraffic(self):
        try:
            xml = urllib.request.urlopen(f"http://data.alexa.com/data?cli=10&dat=s&url={self.domain}").read()
            rank = BeautifulSoup(xml, "xml").find("REACH")["RANK"]
            return 1 if int(rank) < 100000 else 0
        except Exception:
            return -1

    def PageRank(self):
        try:
            r = requests.post("https://www.checkpagerank.net/index.php", {"name": self.domain})
            m = re.search(r"Global Rank: ([0-9]+)", r.text)
            if m:
                return 1 if int(m.group(1)) < 100000 else -1
            return -1
        except Exception:
            return -1

    def GoogleIndex(self):
        try:
            return 1 if list(search(self.url, num_results=3)) else -1
        except Exception:
            return 1

    def LinksPointingToPage(self):
        try:
            links = re.findall(r"<a href=", self.response.text)
            count = len(links)
            if count == 0:
                return 1
            elif count <= 2:
                return 0
            return -1
        except Exception:
            return -1

    def StatsReport(self):
        try:
            bad_domains = re.search(r'at\.ua|usa\.cc|baltazarpresentes|pe\.hu|hol\.es', self.url)
            ip = socket.gethostbyname(self.domain)
            bad_ips = re.search(r'146\.112\.61\.108|213\.174\.157\.151', ip)
            return -1 if bad_domains or bad_ips else 1
        except Exception:
            return 1

    # ---------------- LIVE SCAN HELPERS ----------------
    def _get_hostname(self):
        try:
            return urlparse(self.url).hostname
        except Exception:
            return None

    def _is_ip_hostname(self, hostname):
        try:
            ipaddress.ip_address(hostname)
            return True
        except Exception:
            return False

    def _get_redirect_chain(self, timeout=8):
        try:
            r = requests.get(self.url, allow_redirects=True, timeout=timeout)
            return r.url, [resp.url for resp in r.history]
        except Exception:
            return self.url, []

    def _get_ssl_info(self, hostname, port=443, timeout=8):
        if not hostname:
            return False, False, None
        uses_https = urlparse(self.url).scheme.lower() == "https"
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((hostname, port), timeout=timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    notAfter = cert.get('notAfter')
                    if notAfter:
                        expiry = date_parse(notAfter)
                        valid = expiry > datetime.utcnow()
                        return uses_https, valid, expiry
            return uses_https, True, None
        except Exception:
            return uses_https, False, None

    def _get_whois_info(self, hostname):
        try:
            w = whois.whois(hostname)
            created, exp = w.creation_date, w.expiration_date
            if isinstance(created, list): created = created[0]
            if isinstance(exp, list): exp = exp[0]
            age = (datetime.utcnow() - created).days if created else None
            return age, exp, w
        except Exception:
            return None, None, None

    def live_scan(self, timeout=8):
        try:
            host = self._get_hostname() or self.domain
            final, hist = self._get_redirect_chain(timeout)
            uses_https = urlparse(final).scheme.lower() == "https"
            host_final = urlparse(final).hostname or host
            ssl_present, ssl_valid, ssl_exp = self._get_ssl_info(host_final, timeout=timeout)
            whois_age, whois_exp, whois_raw = self._get_whois_info(host_final)
            return {
                'final_url': final,
                'redirects': len(hist),
                'history': hist,
                'uses_https': uses_https,
                'ssl_present': ssl_present,
                'ssl_valid': ssl_valid,
                'ssl_expiry': ssl_exp,
                'whois_age_days': whois_age,
                'whois_expires': whois_exp,
                'whois_raw': whois_raw,
                'hostname_is_ip': self._is_ip_hostname(host_final),
            }
        except Exception:
            return {
                'final_url': self.url,
                'redirects': 0,
                'history': [],
                'uses_https': False,
                'ssl_present': False,
                'ssl_valid': False,
                'ssl_expiry': None,
                'whois_age_days': None,
                'whois_expires': None,
                'whois_raw': None,
                'hostname_is_ip': False,
            }

    # ---------------- MAIN CALL ----------------
    def getFeaturesList(self):
        self.features = [
            self.UsingIp(), self.longUrl(), self.shortUrl(), self.symbol(), self.redirecting(),
            self.prefixSuffix(), self.SubDomains(), self.Hppts(), self.DomainRegLen(), self.Favicon(),
            self.NonStdPort(), self.HTTPSDomainURL(), self.RequestURL(), self.AnchorURL(),
            self.LinksInScriptTags(), self.ServerFormHandler(), self.InfoEmail(), self.AbnormalURL(),
            self.WebsiteForwarding(), self.StatusBarCust(), self.DisableRightClick(),
            self.UsingPopupWindow(), self.IframeRedirection(), self.AgeofDomain(), self.DNSRecording(),
            self.WebsiteTraffic(), self.PageRank(), self.GoogleIndex(), self.LinksPointingToPage(),
            self.StatsReport()
        ]
        return self.features
