import requests

# --- API keys ---
VIRUSTOTAL_API_KEY = "51aee4922c943cf96ea08e764f92b628ac44fcecf8f018da047a565d6263bb8a"
ABUSEIPDB_API_KEY  = "3fd16acf9f62330dd135a0fa288d14af0df2f1b79bec9a134a0a58f0851029e945d50b5d7925a8c5"


def check_domain_virustotal(domain: str) -> dict:
    """
    Query the VirusTotal API to check whether a domain is known as malicious.
    VirusTotal aggregates results from ~90 antivirus engines.

    Returns the number of engines that flagged the domain and the detected categories.
    Example return:
        {"source": "virustotal", "domain": "evil.com", "malicious": 14, "categories": ["phishing"]}
    """
    url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}

    try:
        response = requests.get(url, headers=headers, timeout=10)

        if response.status_code == 401:
            print(f"  [!] VirusTotal: invalid API key")
            return {"source": "virustotal", "domain": domain, "malicious": 0, "error": "invalid API key"}

        if response.status_code == 404:
            print(f"  [~] VirusTotal: domain {domain} not found in database")
            return {"source": "virustotal", "domain": domain, "malicious": 0, "suspicious": 0, "categories": []}

        data = response.json()
        attrs = data["data"]["attributes"]
        stats = attrs["last_analysis_stats"]
        categories = list(attrs.get("categories", {}).values())

        return {
            "source":     "virustotal",
            "domain":     domain,
            "malicious":  stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "categories": list(set(categories))
        }

    except Exception as e:
        print(f"  [!] VirusTotal error for {domain}: {e}")
        return {"source": "virustotal", "domain": domain, "malicious": 0, "error": str(e)}


def check_ip_abuseipdb(ip: str) -> dict:
    """
    Query AbuseIPDB to evaluate the reputation of an IP address.
    AbuseIPDB is a community database of IPs reported for malicious activity.

    Returns:
    - abuse_score : integer 0-100 (100 = IP heavily reported for abuse)
    - is_tor      : True if the IP is a Tor exit node
    - country     : two-letter country code of the IP
    """
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}
    params  = {"ipAddress": ip, "maxAgeInDays": 90}

    try:
        response = requests.get(url, headers=headers, params=params, timeout=10)

        if response.status_code == 401:
            print(f"  [!] AbuseIPDB: invalid API key")
            return {"source": "abuseipdb", "ip": ip, "abuse_score": 0, "error": "invalid API key"}

        data = response.json()["data"]
        return {
            "source":      "abuseipdb",
            "ip":          ip,
            "abuse_score": data.get("abuseConfidenceScore", 0),
            "is_tor":      data.get("isTor", False),
            "country":     data.get("countryCode", "?")
        }

    except Exception as e:
        print(f"  [!] AbuseIPDB error for {ip}: {e}")
        return {"source": "abuseipdb", "ip": ip, "abuse_score": 0, "error": str(e)}


def check_url_urlhaus(url_to_check: str) -> dict:
    """
    Query URLhaus to check whether a URL is known to distribute malware
    (ransomware, trojans, etc.). URLhaus is free and requires no API key.

    Returns whether the URL is listed and any associated malware tags.
    """
    api_url = "https://urlhaus-api.abuse.ch/v1/url/"

    try:
        response = requests.post(api_url, data={"url": url_to_check}, timeout=10)
        data = response.json()
        is_listed = data.get("query_status") == "is_listed"

        return {
            "source":         "urlhaus",
            "url":            url_to_check,
            "is_malware_url": is_listed,
            "tags":           data.get("tags", [])
        }

    except Exception as e:
        print(f"  [!] URLhaus error for {url_to_check}: {e}")
        return {"source": "urlhaus", "url": url_to_check, "is_malware_url": False, "error": str(e)}


def run_threat_intel(iocs: dict) -> list[dict]:
    """
    Main function: takes the extracted IOCs and queries all reputation APIs.
    Returns a flat list of result dictionaries, one per IOC checked.

    Typical call:
        iocs    = extract_all_iocs("evidence.json")
        results = run_threat_intel(iocs)
    """
    results = []

    print("\n[*] Querying VirusTotal for domains...")
    for domain in iocs.get("domains", []):
        print(f"    -> {domain}")
        results.append(check_domain_virustotal(domain))

    print("\n[*] Querying AbuseIPDB for IPs...")
    for ip in iocs.get("ips", []):
        print(f"    -> {ip}")
        results.append(check_ip_abuseipdb(ip))

    print("\n[*] Querying URLhaus for URLs...")
    for url in iocs.get("urls", [])[:5]:   # limit to 5 to avoid rate-limiting
        print(f"    -> {url}")
        results.append(check_url_urlhaus(url))

    return results