import os
import sys


def run_verdict_pipeline(evidence_path: str,
                         output_path: str = "output/verdict.json") -> dict:
    from ioc_extractor import extract_all_iocs
    from threat_intel  import run_threat_intel
    from heuristics    import run_heuristics
    from scorer        import compute_final_score
    from verdict       import build_verdict, save_verdict

    print(f"\n{'='*50}")
    print(f"  URL Threat Analysis — Person 2 Pipeline")
    print(f"{'='*50}")

    print(f"\n[*] Loading evidence from: {evidence_path}")
    iocs     = extract_all_iocs(evidence_path)
    evidence = iocs["_raw"]

    print(f"    IPs found      : {iocs['ips']}")
    print(f"    Domains found  : {iocs['domains']}")
    print(f"    URLs found     : {len(iocs['urls'])}")

    intel_results   = run_threat_intel(iocs)
    triggered_rules = run_heuristics(evidence)
    score_result    = compute_final_score(intel_results, triggered_rules)

    verdict = build_verdict(evidence.get("url", "unknown"), score_result)

    # ✅ FIXED: use output_path parameter
    save_verdict(verdict, output_path)

    print(f"\n[*] Triggered signals:")
    for reason in verdict["reasons"]:
        print(f"    - {reason}")

    print(f"\n{'='*50}\n")
    return verdict

# ── Entry point when Docker runs: python /app/main.py <url> ──────────────────
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python main.py <url>")
        sys.exit(1)

    target_url = sys.argv[1]

    # Step 1: build evidence (browse the URL, take screenshot, etc.)
    os.makedirs("output", exist_ok=True)
    from evidence_builder import build_evidence
    build_evidence(target_url, output_path="output/evidence.json")

    # Step 2: run the verdict pipeline on that evidence
    run_verdict_pipeline("output/evidence.json", output_path="output/verdict.json")