import json
import sys
from datetime import datetime

# Decision thresholds (defined in the project specification)
THRESHOLD_CLEAN      = 30   # score < 30  -> CLEAN
THRESHOLD_SUSPICIOUS = 70   # score < 70  -> SUSPICIOUS
                             # score >= 70 -> MALICIOUS


def map_score_to_verdict(score: int) -> str:
    """
    Map the numeric risk score to a verdict label.

    < 30   -> "CLEAN"      (no significant signals)
    30-69  -> "SUSPICIOUS" (signals present but not conclusive)
    >= 70  -> "MALICIOUS"  (confirmed threat)
    """
    if score < THRESHOLD_CLEAN:
        return "CLEAN"
    elif score < THRESHOLD_SUSPICIOUS:
        return "SUSPICIOUS"
    else:
        return "MALICIOUS"


def build_verdict(url: str, score_result: dict) -> dict:
    """
    Assemble the final verdict report from the URL and the score result.

    Parameters:
    - url          : the analysed URL (carried over for reference in the report)
    - score_result : dictionary returned by compute_final_score()

    Returns a structured dict that will be written to verdict.json:
    {
        "url":             "http://...",
        "verdict":         "MALICIOUS",
        "score":           85,
        "score_breakdown": {...},
        "reasons":         [...],
        "analyzed_at":     "2026-04-09T10:00:00Z"
    }
    """
    verdict_label = map_score_to_verdict(score_result["score"])

    return {
        "url":             url,
        "verdict":         verdict_label,
        "score":           score_result["score"],
        "score_breakdown": score_result.get("score_breakdown", {}),
        "reasons":         score_result.get("reasons", []),
        "analyzed_at":     datetime.utcnow().isoformat() + "Z"
    }


def save_verdict(verdict: dict, output_path: str = "verdict.json") -> None:
    """
    Write the verdict dictionary to a JSON file.
    This is the final output artifact of the Person 2 pipeline,
    equivalent to evidence.json for Person 1.

    Prints a short summary line to stdout after saving.
    Example output:
        [✓] Verdict saved to verdict.json
            -> MALICIOUS (score: 85/100)
    """
    with open(output_path, "w") as f:
        json.dump(verdict, f, indent=2, ensure_ascii=False)

    label = verdict["verdict"]
    score = verdict["score"]
    print(f"\n[✓] Verdict saved to {output_path}")
    print(f"    -> {label} (score: {score}/100)")


def run_verdict_pipeline(evidence_path: str) -> dict:
    """
    Main entry point: orchestrates the entire Person 2 pipeline.
    Call only this function from your main script or integration test.

    Execution order:
    1. Extract IOCs from evidence.json          (ioc_extractor)
    2. Query threat intelligence APIs           (threat_intel)
    3. Apply heuristic detection rules          (heuristics)
    4. Compute the final risk score             (scorer)
    5. Build, save, and return the verdict      (verdict)
    """
    from ioc_extractor import extract_all_iocs
    from threat_intel  import run_threat_intel
    from heuristics    import run_heuristics
    from scorer        import compute_final_score

    print(f"\n{'='*50}")
    print(f"  URL Threat Analysis — Person 2 Pipeline")
    print(f"{'='*50}")

    # Step 1 — Extract IOCs
    print(f"\n[*] Loading evidence from: {evidence_path}")
    iocs     = extract_all_iocs(evidence_path)
    evidence = iocs["_raw"]

    print(f"    IPs found      : {iocs['ips']}")
    print(f"    Domains found  : {iocs['domains']}")
    print(f"    URLs found     : {len(iocs['urls'])}")

    # Step 2 — Threat intelligence
    intel_results = run_threat_intel(iocs)

    # Step 3 — Heuristics
    triggered_rules = run_heuristics(evidence)

    # Step 4 — Scoring
    score_result = compute_final_score(intel_results, triggered_rules)

    # Step 5 — Verdict
    verdict = build_verdict(evidence.get("url", "unknown"), score_result)
    save_verdict(verdict)

    # Print triggered reasons
    print(f"\n[*] Triggered signals:")
    for reason in verdict["reasons"]:
        print(f"    - {reason}")

    print(f"\n{'='*50}\n")
    return verdict


# --- Entry point when the script is run directly ---
if __name__ == "__main__":
    evidence_file = sys.argv[1] if len(sys.argv) > 1 else "evidence.json"
    result = run_verdict_pipeline(evidence_file)
    print(json.dumps(result, indent=2, ensure_ascii=False))