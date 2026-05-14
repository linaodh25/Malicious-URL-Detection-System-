import json
import re


def load_evidence(filepath: str) -> dict:
    with open(filepath, "r") as f:
        return json.load(f)


def extract_ips(evidence: dict) -> list[str]:
    ips = set()
    for request in evidence.get("requests", []):
        ip = request.get("ip")
        if ip and ip != "unknown":
            ips.add(ip)
    return list(ips)


def extract_domains(evidence: dict) -> list[str]:
    domains = set()
    pattern = r"https?://([^/]+)"

    # From requests
    for request in evidence.get("requests", []):
        url = request.get("url", "")
        match = re.match(pattern, url)
        if match:
            domains.add(match.group(1))

    # From redirect chain
    for url in evidence.get("redirect_chain", []):
        match = re.match(pattern, url)
        if match:
            domains.add(match.group(1))

    # From final URL
    final_url = evidence.get("final_url", "")
    match = re.match(pattern, final_url)
    if match:
        domains.add(match.group(1))

    return list(domains)


def extract_urls(evidence: dict) -> list[str]:
    urls = set()

    for request in evidence.get("requests", []):
        url = request.get("url", "")
        if url:
            urls.add(url)

    for url in evidence.get("redirect_chain", []):
        if url:
            urls.add(url)

    return list(urls)


def extract_file_hashes(evidence: dict) -> list[dict]:
    """
    ✅ UPDATED: Now reads from downloaded_files (Person 1's richer structure)
    instead of the old flat file_hashes list.
    Returns list of dicts with filename, md5, sha256.
    """
    hashes = []
    for f in evidence.get("downloaded_files", []):
        entry = {"filename": f.get("filename", "unknown")}
        if "md5"    in f: entry["md5"]    = f["md5"]
        if "sha256" in f: entry["sha256"] = f["sha256"]
        if "url"    in f: entry["url"]    = f["url"]
        hashes.append(entry)
    return hashes


def extract_tls_info(evidence: dict) -> dict:
    """
    ✅ NEW: Extract TLS certificate info from Person 1's evidence.
    Person 2 uses this to flag missing/invalid TLS.
    """
    return evidence.get("tls_info", {
        "has_tls": False,
        "certificate_valid": False,
        "issuer": None
    })


def extract_cookies(evidence: dict) -> list[dict]:
    """
    ✅ NEW: Extract cookies set by the page.
    Useful for detecting tracking or session-stealing cookies.
    """
    return evidence.get("cookies", [])


def extract_meta(evidence: dict) -> dict:
    """
    ✅ NEW: Extract scan metadata (sandbox ID, timestamp, etc.)
    Useful for audit trails in the verdict report.
    """
    return evidence.get("meta", {})


def extract_all_iocs(filepath: str) -> dict:
    """
    Main function: loads evidence and returns ALL IOCs grouped by type.
    Now includes tls_info, cookies, downloaded_files, and meta
    from Person 1's richer evidence structure.
    """
    evidence = load_evidence(filepath)
    return {
        "ips":          extract_ips(evidence),
        "domains":      extract_domains(evidence),
        "urls":         extract_urls(evidence),
        "file_hashes":  extract_file_hashes(evidence),   # ✅ updated
        "tls_info":     extract_tls_info(evidence),       # ✅ new
        "cookies":      extract_cookies(evidence),        # ✅ new
        "meta":         extract_meta(evidence),           # ✅ new
        "page_title":   evidence.get("page_title", ""),   # ✅ new
        "_raw":         evidence
    }