import re

# ─────────────────────────────────────────────────────────────────
#  Each rule receives the full evidence dict from Person 1.
#  Returns a dict if suspicious, None if clean.
# ─────────────────────────────────────────────────────────────────


# ══════════════════════════════════════════════════════════════════
#  ORIGINAL 5 RULES
# ══════════════════════════════════════════════════════════════════

def check_http_login_form(evidence: dict) -> dict | None:
    final_url      = evidence.get("final_url", "")
    form_submitted = len(evidence.get("js_events", {}).get("form_submissions", [])) > 0

    if final_url.startswith("http://") and form_submitted:
        return {
            "rule":        "http_login_form",
            "description": "Login form detected on plain HTTP (no TLS)",
            "severity":    "high"
        }
    return None


def check_obfuscated_js(evidence: dict) -> dict | None:
    eval_calls = evidence.get("js_events", {}).get("eval_calls", [])
    dom_writes = evidence.get("js_events", {}).get("dom_writes", [])

    suspicious  = re.compile(r"(unescape|atob|base64)", re.IGNORECASE)
    b64_pattern = re.compile(r"[A-Za-z0-9+/]{100,}={0,2}")

    for call in eval_calls:
        if suspicious.search(call):
            return {
                "rule":        "obfuscated_js",
                "description": "Obfuscated JavaScript detected (eval + encoding)",
                "severity":    "high",
                "sample":      call[:100]
            }

    for write in dom_writes:
        if b64_pattern.search(write):
            return {
                "rule":        "obfuscated_js_dom",
                "description": "Base64 payload injected into the DOM",
                "severity":    "medium"
            }

    return None


def check_typosquatting(evidence: dict) -> dict | None:
    known_brands = [
        "paypal.com", "google.com", "facebook.com", "amazon.com",
        "apple.com", "microsoft.com", "netflix.com", "instagram.com",
        "twitter.com", "linkedin.com", "ebay.com", "chase.com",
        "wellsfargo.com", "bankofamerica.com", "citibank.com",
        "dropbox.com", "icloud.com", "outlook.com", "gmail.com"
    ]

    def levenshtein(s1: str, s2: str) -> int:
        if len(s1) < len(s2):
            return levenshtein(s2, s1)
        if not s2:
            return len(s1)
        prev = list(range(len(s2) + 1))
        for i, c1 in enumerate(s1):
            curr = [i + 1]
            for j, c2 in enumerate(s2):
                curr.append(min(prev[j + 1] + 1, curr[j] + 1, prev[j] + (c1 != c2)))
            prev = curr
        return prev[-1]

    final_url = evidence.get("final_url", "")
    match = re.match(r"https?://([^/]+)", final_url)
    if not match:
        return None

    domain = match.group(1).lower()
    for brand in known_brands:
        dist = levenshtein(domain, brand)
        if 0 < dist <= 2:
            return {
                "rule":         "typosquatting",
                "description":  f"Domain '{domain}' looks like '{brand}' (edit distance={dist})",
                "severity":     "high",
                "lookalike_of": brand
            }

    return None


def check_excessive_redirects(evidence: dict) -> dict | None:
    chain = evidence.get("redirect_chain", [])
    if len(chain) > 3:
        return {
            "rule":        "excessive_redirects",
            "description": f"Redirect chain of {len(chain)} hops detected",
            "severity":    "medium",
            "chain":       chain
        }
    return None


def check_popup_social_engineering(evidence: dict) -> dict | None:
    popups = evidence.get("js_events", {}).get("popups", [])
    scam_keywords = [
        "infected", "virus", "warning", "click here", "download now",
        "urgent", "alert", "danger", "your pc", "your computer",
        "call now", "tech support", "toll-free", "hacked", "compromised",
        "immediately", "critical error", "security breach"
    ]

    for popup in popups:
        for keyword in scam_keywords:
            if keyword.lower() in popup.lower():
                return {
                    "rule":        "social_engineering_popup",
                    "description": f"Social-engineering popup detected: '{popup[:80]}'",
                    "severity":    "high",
                    "sample":      popup[:200]
                }
    return None


# ══════════════════════════════════════════════════════════════════
#  NEW 6 RULES
# ══════════════════════════════════════════════════════════════════

def check_suspicious_file_download(evidence: dict) -> dict | None:
    dangerous_extensions = [".exe", ".bat", ".ps1", ".vbs", ".js", ".msi", ".dll", ".scr", ".zip", ".rar"]
    for f in evidence.get("downloaded_files", []):
        filename = f.get("filename", "").lower()
        for ext in dangerous_extensions:
            if filename.endswith(ext):
                return {
                    "rule":        "suspicious_file_download",
                    "description": f"Dangerous file downloaded: {f.get('filename')}",
                    "severity":    "critical",
                    "filename":    f.get("filename"),
                    "sha256":      f.get("sha256", "N/A")
                }
    return None


def check_ip_address_url(evidence: dict) -> dict | None:
    ip_pattern = re.compile(r"https?://(\d{1,3}\.){3}\d{1,3}")
    for url in [evidence.get("url", ""), evidence.get("final_url", "")]:
        if ip_pattern.match(url):
            return {
                "rule":        "ip_address_url",
                "description": f"URL uses a raw IP address instead of a domain: {url}",
                "severity":    "high"
            }
    return None


WHITELISTED_DOMAINS = {
    "google.com", "googleapis.com", "gstatic.com",
    "cloudflare.com", "jquery.com", "bootstrapcdn.com",
    "cdnjs.cloudflare.com", "fonts.googleapis.com"
}

def check_data_exfiltration(evidence: dict) -> dict | None:
    final_url = evidence.get("final_url", "")
    match = re.match(r"https?://([^/]+)", final_url)
    if not match:
        return None

    page_domain = match.group(1).lower()
    suspicious_destinations = []

    for req in evidence.get("requests", []):
        req_url   = req.get("url", "")
        req_match = re.match(r"https?://([^/]+)", req_url)
        if not req_match:
            continue
        req_domain = req_match.group(1).lower()
        if req_domain != page_domain and req_domain not in WHITELISTED_DOMAINS:
            if req.get("method", "GET").upper() == "POST":
                suspicious_destinations.append(req_domain)

    if suspicious_destinations:
        return {
            "rule":         "data_exfiltration",
            "description":  f"Page is sending POST data to external domains: {suspicious_destinations}",
            "severity":     "critical",
            "destinations": suspicious_destinations
        }
    return None


def check_crypto_mining(evidence: dict) -> dict | None:
    miner_keywords = [
        "coinhive", "cryptonight", "minero", "webminer",
        "crypto-loot", "jsecoin", "miner.start", "wasm_miner",
        "monero", "xmrig", "deepminer"
    ]

    all_urls   = [req.get("url", "") for req in evidence.get("requests", [])]
    dom_writes = evidence.get("js_events", {}).get("dom_writes", [])

    for source in all_urls + dom_writes:
        for keyword in miner_keywords:
            if keyword in source.lower():
                return {
                    "rule":        "crypto_mining",
                    "description": f"Cryptomining script detected: '{keyword}'",
                    "severity":    "high",
                    "found_in":    source[:150]
                }
    return None


def check_iframe_injection(evidence: dict) -> dict | None:
    dom_writes    = evidence.get("js_events", {}).get("dom_writes", [])
    iframe_pattern = re.compile(r"<iframe", re.IGNORECASE)
    hidden_attrs   = re.compile(
        r'(width\s*=\s*["\']?0|height\s*=\s*["\']?0|display\s*:\s*none|visibility\s*:\s*hidden)',
        re.IGNORECASE
    )

    for write in dom_writes:
        if iframe_pattern.search(write) and hidden_attrs.search(write):
            return {
                "rule":        "iframe_injection",
                "description": "Hidden iframe injected into the page",
                "severity":    "high",
                "sample":      write[:200]
            }
    return None


def check_credential_harvesting_keywords(evidence: dict) -> dict | None:
    dom_writes = evidence.get("js_events", {}).get("dom_writes", [])
    harvesting_patterns = {
        "password_field":    re.compile(r'type\s*=\s*["\']password["\']',                       re.IGNORECASE),
        "credit_card_field": re.compile(r'name\s*=\s*["\']?(cc_?num|card_?num|credit_?card)',   re.IGNORECASE),
        "ssn_field":         re.compile(r'name\s*=\s*["\']?(ssn|social_?security)',             re.IGNORECASE),
        "cvv_field":         re.compile(r'name\s*=\s*["\']?(cvv|cvc|card_?code)',               re.IGNORECASE),
    }

    found_fields = set()
    for write in dom_writes:
        for field_name, pattern in harvesting_patterns.items():
            if pattern.search(write):
                found_fields.add(field_name)

    if len(found_fields) >= 2:
        return {
            "rule":         "credential_harvesting",
            "description":  f"Page contains multiple sensitive input fields: {list(found_fields)}",
            "severity":     "high",
            "fields_found": list(found_fields)
        }
    return None


# ══════════════════════════════════════════════════════════════════
#  ✅ NEW RULES using Person 1's extra fields
# ══════════════════════════════════════════════════════════════════

def check_invalid_tls(evidence: dict) -> dict | None:
    """
    ✅ NEW: Uses tls_info from Person 1's evidence.
    Flags sites that claim HTTPS but have an invalid/self-signed certificate.
    """
    tls = evidence.get("tls_info", {})
    if tls.get("has_tls") and not tls.get("certificate_valid"):
        return {
            "rule":        "invalid_tls_certificate",
            "description": "Site uses HTTPS but the TLS certificate is invalid or self-signed",
            "severity":    "high",
            "issuer":      tls.get("issuer")
        }
    return None


def check_no_tls_at_all(evidence: dict) -> dict | None:
    """
    ✅ NEW: Uses tls_info from Person 1's evidence.
    Flags sites that use plain HTTP with no encryption at all.
    """
    tls = evidence.get("tls_info", {})
    if not tls.get("has_tls"):
        return {
            "rule":        "no_tls",
            "description": "Site has no TLS/HTTPS at all — all traffic is unencrypted",
            "severity":    "medium"
        }
    return None


def check_suspicious_cookies(evidence: dict) -> dict | None:
    """
    ✅ NEW: Uses cookies from Person 1's evidence.
    Flags insecure cookies (missing 'secure' flag) on sensitive pages.
    """
    insecure = [
        c for c in evidence.get("cookies", [])
        if not c.get("secure")
    ]
    if insecure:
        names = [c.get("name", "?") for c in insecure]
        return {
            "rule":        "insecure_cookies",
            "description": f"Cookies set without 'Secure' flag: {names}",
            "severity":    "medium",
            "cookies":     names
        }
    return None


def check_misleading_page_title(evidence: dict) -> dict | None:
    """
    ✅ NEW: Uses page_title from Person 1's evidence.
    Flags pages whose title contains brand names but the domain doesn't match.
    """
    title = evidence.get("page_title", "").lower()
    final_url = evidence.get("final_url", "").lower()

    brand_names = ["paypal", "google", "facebook", "amazon", "apple",
                   "microsoft", "netflix", "instagram", "twitter", "ebay"]

    for brand in brand_names:
        if brand in title and brand not in final_url:
            return {
                "rule":        "misleading_page_title",
                "description": f"Page title mentions '{brand}' but domain doesn't match — possible phishing",
                "severity":    "high",
                "title":       evidence.get("page_title", ""),
                "domain":      final_url
            }
    return None


# ══════════════════════════════════════════════════════════════════
#  MAIN — runs ALL 15 rules
# ══════════════════════════════════════════════════════════════════

def run_heuristics(evidence: dict) -> list[dict]:
    print("\n[*] Running heuristic rules...")

    checks = [
        # Original 5
        check_http_login_form(evidence),
        check_obfuscated_js(evidence),
        check_typosquatting(evidence),
        check_excessive_redirects(evidence),
        check_popup_social_engineering(evidence),
        # Original new 6
        check_suspicious_file_download(evidence),
        check_ip_address_url(evidence),
        check_data_exfiltration(evidence),
        check_crypto_mining(evidence),
        check_iframe_injection(evidence),
        check_credential_harvesting_keywords(evidence),
        # ✅ New 4 using Person 1's richer fields
        check_invalid_tls(evidence),
        check_no_tls_at_all(evidence),
        check_suspicious_cookies(evidence),
        check_misleading_page_title(evidence),
    ]

    triggered = [c for c in checks if c is not None]

    for finding in triggered:
        print(f"    [!] {finding['rule']:<45} severity: {finding['severity'].upper()}")

    if not triggered:
        print("    [✓] No heuristic rules triggered")
    else:
        print(f"\n    Total rules triggered: {len(triggered)}/15")

    return triggered