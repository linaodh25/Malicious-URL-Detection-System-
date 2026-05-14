RULE_WEIGHTS = {
    # Original 5
    "http_login_form":            20,
    "obfuscated_js":              25,
    "obfuscated_js_dom":          15,
    "typosquatting":              20,
    "excessive_redirects":        10,
    "social_engineering_popup":   20,
    # Original new 6
    "suspicious_file_download":   35,
    "ip_address_url":             20,
    "data_exfiltration":          35,
    "crypto_mining":              25,
    "iframe_injection":           20,
    "credential_harvesting":      25,
    # ✅ New 4 using Person 1's richer fields
    "invalid_tls_certificate":    20,
    "no_tls":                     10,
    "insecure_cookies":           10,
    "misleading_page_title":      25,
    # Threat intel (dynamic)
    "virustotal_hit":              0,
    "abuseipdb_hit":               0,
    "urlhaus_hit":                30,
}


def score_threat_intel(intel_results: list[dict]) -> tuple[int, list[str]]:
    score   = 0
    reasons = []

    for result in intel_results:
        source = result.get("source")

        if source == "virustotal":
            malicious = result.get("malicious", 0)
            if malicious >= 5:
                score += 40
                reasons.append(f"VirusTotal: {malicious} engines flagged domain '{result.get('domain')}' as malicious")
            elif malicious >= 1:
                score += 20
                reasons.append(f"VirusTotal: {malicious} engine(s) flagged domain '{result.get('domain')}' as suspicious")

        elif source == "abuseipdb":
            abuse_score = result.get("abuse_score", 0)
            if abuse_score >= 80:
                score += 30
                reasons.append(f"AbuseIPDB: IP {result.get('ip')} is highly malicious (score={abuse_score}/100)")
            elif abuse_score >= 30:
                score += 15
                reasons.append(f"AbuseIPDB: IP {result.get('ip')} is suspicious (score={abuse_score}/100)")

        elif source == "urlhaus":
            if result.get("is_malware_url"):
                score += 30
                tags    = result.get("tags", [])
                tag_str = ", ".join(tags) if tags else "no tags"
                reasons.append(f"URLhaus: URL is a known malware distribution point ({tag_str})")

    return score, reasons


def score_heuristics(triggered_rules: list[dict]) -> tuple[int, list[str]]:
    score   = 0
    reasons = []

    for rule in triggered_rules:
        rule_name = rule.get("rule", "")
        weight    = RULE_WEIGHTS.get(rule_name, 5)
        score    += weight
        reasons.append(rule.get("description", rule_name))

    return score, reasons


def compute_final_score(intel_results: list[dict], triggered_rules: list[dict]) -> dict:
    intel_score, intel_reasons = score_threat_intel(intel_results)
    heur_score,  heur_reasons  = score_heuristics(triggered_rules)

    total       = min(intel_score + heur_score, 100)
    all_reasons = intel_reasons + heur_reasons

    print(f"\n[*] Score breakdown:")
    print(f"    Threat intel : {intel_score} pts")
    print(f"    Heuristics   : {heur_score} pts")
    print(f"    Final score  : {total}/100")

    return {
        "score": total,
        "score_breakdown": {
            "threat_intel": intel_score,
            "heuristics":   heur_score
        },
        "reasons": all_reasons
    }