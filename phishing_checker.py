import re
import json
import ssl
import socket
import requests
import whois
import dns.resolver
import dns.dnssec
import dns.name
import dns.query
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from datetime import datetime
from difflib import SequenceMatcher


class AdvancedURLSecurityScanner:
    TRUSTED_DOMAINS = [
        "paypal.com",
        "google.com",
        "facebook.com",
        "apple.com",
        "microsoft.com",
        "amazon.com",
        "linkedin.com",
        "instagram.com",
        "twitter.com",
        "github.com",
        "dropbox.com",
        "bankofamerica.com",
        "chase.com",
        "wellsfargo.com",
        "citibank.com",
        "paypal.co.uk",
    ]
    SUSPICIOUS_TLDS = [
        "zip",
        "country",
        "kim",
        "cricket",
        "science",
        "work",
        "gq",
        "tk",
        "ml",
        "cf",
        "ga",
        "xyz",
        "top",
        "click",
    ]
    URL_SHORTENERS = [
        "bit.ly",
        "tinyurl.com",
        "goo.gl",
        "ow.ly",
        "t.co",
        "is.gd",
        "buff.ly",
        "adf.ly",
        "bit.do",
        "cutt.ly",
    ]
    BLACKLIST_KEYWORDS = [
        "login",
        "signin",
        "bank",
        "secure",
        "account",
        "update",
        "verify",
        "password",
        "confirm",
        "ebayisapi",
        "webscr",
    ]
    CHAR_SUBSTITUTIONS = {
        "a": ["@", "4", "а"],
        "e": ["3", "е"],
        "i": ["1", "l", "і"],
        "o": ["0", "о"],
        "s": ["5", "$"],
        "b": ["6", "b"],
        "g": ["9"],
        "l": ["1", "i"],
        "c": ["с"],
        "u": ["v"],
        "y": ["у"],
        "d": ["cl"],
    }
    COMMON_TWO_PART_TLDS = [
        "co.uk",
        "gov.uk",
        "ac.uk",
        "com.au",
        "net.au",
        "org.au",
        "co.nz",
        "gov.nz",
        "ac.nz",
    ]

    def __init__(self, url):
        if not url.startswith("http://") and not url.startswith("https://"):
            url = self.determine_protocol(url)
        self.url = url
        self.hostname = self.get_hostname(url)
        self.registered_domain = self.get_registered_domain(self.hostname)
        self.report = {
            "url": url,
            "heuristics": [],
            "final_risk_score": 0,
            "final_risk_level": "LOW",
        }


    def get_hostname(self, url):
        match = re.search(r"https?://([^/:?#]+)", url)
        return match.group(1).lower() if match else ""
    
    def determine_protocol(self, domain):
        domain = domain.strip().lower().replace("http://", "").replace("https://", "").rstrip('/')
        https_url = f"https://{domain}"
        http_url = f"http://{domain}"

        try:
            requests.get(https_url, timeout=5)
            return f"https://{domain}"
        except requests.exceptions.SSLError:
            return f"http://{domain}"
        except requests.exceptions.RequestException:
            try:
                requests.get(http_url, timeout=5)
                return f"http://{domain}"
            except requests.exceptions.RequestException:
                return f"http://{domain}"
    def get_registered_domain(self, hostname):
        if not hostname:
            return ""
        if re.match(r"^(\d{1,3}\.){3}\d{1,3}$", hostname):
            return hostname
        parts = hostname.split(".")
        if len(parts) < 2:
            return hostname
        if len(parts) >= 3:
            two_part_tld = f"{parts[-2]}.{parts[-1]}"
            if two_part_tld in self.COMMON_TWO_PART_TLDS:
                return f"{parts[-3]}.{two_part_tld}"
        return f"{parts[-2]}.{parts[-1]}"

    def normalize_for_comparison(self, text):
        normalized = text.lower()
        for original, substitutes in self.CHAR_SUBSTITUTIONS.items():
            for substitute in substitutes:
                normalized = normalized.replace(substitute, original)
        return normalized

    def is_character_substitution_attack(self, threshold=0.80):
        domain = self.registered_domain
        domain_lower = domain.lower()
        normalized_domain = self.normalize_for_comparison(domain)
        for trusted in self.TRUSTED_DOMAINS:
            trusted_lower = trusted.lower()
            normalized_trusted = self.normalize_for_comparison(trusted)
            if domain_lower == trusted_lower:
                continue
            if normalized_domain == normalized_trusted:
                return f"Character substitution attack mimicking '{trusted}'"
            for original_char, substitutes in self.CHAR_SUBSTITUTIONS.items():
                if (
                    any(sub in domain_lower for sub in substitutes)
                    and original_char in trusted_lower
                ):
                    similarity = SequenceMatcher(
                        None, normalized_domain, normalized_trusted
                    ).ratio()
                    if similarity >= threshold:
                        return f"Character substitution attack mimicking '{trusted}' (similarity: {similarity:.2f})"
                    domain_name = normalized_domain.split(".")[0]
                    trusted_name = normalized_trusted.split(".")[0]
                    name_similarity = SequenceMatcher(
                        None, domain_name, trusted_name
                    ).ratio()
                    if name_similarity >= 0.85:
                        return f"Character substitution attack mimicking '{trusted}' (domain name similarity: {name_similarity:.2f})"
        return None

    def check_trusted_domain_spoofing(self):
        for trusted in self.TRUSTED_DOMAINS:
            if trusted in self.hostname and self.registered_domain != trusted:
                if f"{trusted}." in self.hostname and not self.hostname.endswith(
                    f".{trusted}"
                ):
                    return f"Trusted domain '{trusted}' appears as subdomain of '{self.registered_domain}'"
        return None

    def is_similar_domain(self, domain, trusted_domain, threshold=0.9):
        if domain == trusted_domain:
            return False
        similarity = SequenceMatcher(None, domain, trusted_domain).ratio()
        if similarity >= threshold:
            return True
        d_name = domain.split(".")[0]
        t_name = trusted_domain.split(".")[0]
        if abs(len(d_name) - len(t_name)) <= 1:
            return SequenceMatcher(None, d_name, t_name).ratio() >= 0.85
        return False

    def contains_suspicious_patterns(self):
        patterns = []
        if ".." in self.url:
            patterns.append("Multiple consecutive dots in URL")
        if self.url.count("-") > 3:
            patterns.append("Excessive use of hyphens")
        if re.search(r"[а-я].*[a-z]|[a-z].*[а-я]", self.url, re.IGNORECASE):
            patterns.append("Mixed Latin and Cyrillic characters")
        if port := re.search(r":(\d+)", self.url):
            port = int(port.group(1))
            if port not in [80, 443, 8080, 8443] and port < 1024:
                patterns.append(f"Suspicious port number: {port}")
        return patterns

    def run_heuristics(self):
        reasons = []
        if not re.match(r"https?://.+", self.url):
            reasons.append("Invalid URL format")
            self.report["heuristics"] = reasons
            return reasons
        if not self.url.lower().startswith("https://"):
            reasons.append("URL does not use HTTPS")
        if not self.hostname:
            reasons.append("Could not extract hostname from URL")
            self.report["heuristics"] = reasons
            return reasons
        if re.match(r"^(\d{1,3}\.){3}\d{1,3}$", self.hostname):
            reasons.append("Domain is an IP address")
        if spoof := self.check_trusted_domain_spoofing():
            reasons.append(spoof)
        if char_attack := self.is_character_substitution_attack():
            reasons.append(char_attack)

        found_keywords = [
            kw for kw in self.BLACKLIST_KEYWORDS if kw in self.url.lower()
        ]
        if found_keywords:
            if self.registered_domain not in self.TRUSTED_DOMAINS:
                reasons.append(
                    f"Contains suspicious keywords: {', '.join(found_keywords)}"
                )

        if len(self.url) > 100:
            reasons.append("URL length is suspiciously long")
        if self.url.count("@") > 0:
            reasons.append("URL contains '@' symbol (potential redirect)")
        if "//" in self.url[8:]:
            reasons.append("Suspicious '//' found in URL path")
        if self.hostname.count(".") > 4:
            reasons.append("Excessive number of subdomains")
        if re.search(r"[\s\u202E\u202D\u200E\u200F]", self.url):
            reasons.append("Contains suspicious Unicode characters")
        if self.registered_domain in self.URL_SHORTENERS:
            reasons.append("Uses a URL shortening service")
        tld = self.hostname.split(".")[-1]
        if tld in self.SUSPICIOUS_TLDS:
            reasons.append(f"Uses suspicious top-level domain: .{tld}")
        try:
            self.hostname.encode("ascii")
        except UnicodeEncodeError:
            reasons.append(
                "Domain contains non-ASCII characters (potential IDN homograph attack)"
            )
        for trusted in self.TRUSTED_DOMAINS:
            if self.is_similar_domain(self.registered_domain, trusted):
                reasons.append(
                    f"Domain '{self.registered_domain}' is suspiciously similar to '{trusted}'"
                )
        reasons.extend(self.contains_suspicious_patterns())
        if "xn--" in self.hostname:
            reasons.append(
                "Domain uses Punycode encoding (potential IDN homograph attack)"
            )

        self.report["heuristics"] = reasons
        return reasons

    def perform_dns_lookup(self):
        try:
            dns.resolver.resolve(self.registered_domain, "A")

        except Exception:
            pass

    def perform_dnssec_validation(self):
        try:
            domain_name = dns.name.from_text(self.registered_domain)
            response = dns.query.udp(
                dns.message.make_query(domain_name, dns.rdatatype.DNSKEY), "8.8.8.8"
            )
        except Exception:
            pass

    def fetch_ssl_certificate(self):
        try:
            context = ssl.create_default_context()
            with socket.create_connection((self.hostname, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=self.hostname) as ssock:
                    pass
        except Exception:
            pass

    def perform_whois_lookup(self):
        try:
            whois.whois(self.registered_domain)
        except Exception:
            pass

    def calculate_final_risk(self):
        score = 0
        heuristic_count = len(self.report["heuristics"])
        if heuristic_count > 0:
            score += heuristic_count * 5
        self.report["final_risk_score"] = score
        if score >= 40:
            level = "HIGH"
        elif score >= 20:
            level = "MEDIUM"
        else:
            level = "LOW"
        self.report["final_risk_level"] = level

    def run_full_scan(self):
        self.run_heuristics()
        self.perform_dns_lookup()
        self.perform_dnssec_validation()
        self.fetch_ssl_certificate()
        self.perform_whois_lookup()
        self.calculate_final_risk()

        is_trusted_subdomain = any(
            self.hostname == trusted or self.hostname.endswith("." + trusted)
            for trusted in self.TRUSTED_DOMAINS
        )

        if is_trusted_subdomain:
            is_safe = True
            reasons = []
        else:
            is_safe = self.report["final_risk_score"] < 5
            reasons = self.report["heuristics"] if not is_safe else []

        output = {
            "url": self.report["url"],
            "final_risk_score": self.report["final_risk_score"],
            "final_risk_level": self.report["final_risk_level"],
            "is_safe": is_safe,
            "reasons": reasons,
        }
        return json.dumps(output, indent=4)