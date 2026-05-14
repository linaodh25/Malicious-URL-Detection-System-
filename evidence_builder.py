import json
import time
import uuid
from datetime import datetime, timezone

from browser import run_browser
from network_capture import get_tls_info


def build_evidence(url: str, output_path: str = "output/evidence.json") -> dict:    
    print(f"\n{'='*55}")
    print(f"  EVIDENCE BUILDER — SCAN STARTED")
    print(f"  Target  : {url}")
    print(f"  Output  : {output_path}")
    print(f"{'='*55}\n")

    start_time = time.time()

    # ── Step 1: Visit URL ─────────────────────────────────────────────────────
    print("[1/3] Launching browser and visiting URL...")
    try:
        browser_data = run_browser(url)
        print("      ✓ Browser scan complete")
    except Exception as e:
        print(f"      ✗ Browser scan failed: {e}")
        browser_data = _empty_browser_data(url)

    # ── Step 2: TLS certificate check ─────────────────────────────────────────
    # ✅ browser.py now returns tls_info directly, so we just use that.
    # We only call get_tls_info() separately as a fallback if browser_data lacks it.
    print("[2/3] Checking TLS certificate...")
    try:
        tls_info = browser_data.get("tls_info") or get_tls_info(url)
        print(f"      ✓ TLS check done  (has_tls={tls_info['has_tls']})")
    except Exception as e:
        print(f"      ✗ TLS check failed: {e}")
        tls_info = {"has_tls": False, "certificate_valid": False, "issuer": None}

    # ── Step 3: JS events ─────────────────────────────────────────────────────
    print("[3/3] Reading JS hook events...")
    js_events = browser_data.get("js_events", _empty_js_events())

    # ✅ FIX Bug 1 (evidence side): Merge popup data from TWO sources:
    #   Source A — js_events["popups"]: alert/confirm/prompt calls caught by the spy
    #   Source B — browser_data["popups"]: new windows/tabs caught by Playwright
    # We merge them so nothing is lost.
    playwright_popups = browser_data.get("popups", [])
    if playwright_popups:
        # Tag them so analysts know the source
        tagged = [f"[new-window] {p}" for p in playwright_popups]
        js_events["popups"] = js_events.get("popups", []) + tagged

    print(f"      ✓ eval_calls={len(js_events['eval_calls'])}  "
          f"dom_writes={len(js_events['dom_writes'])}  "
          f"popups={len(js_events['popups'])}  "
          f"form_submissions={len(js_events['form_submissions'])}")

    scan_duration = round(time.time() - start_time, 2)

    # ── Assemble evidence ─────────────────────────────────────────────────────
    evidence = {
        "url":            url,
        "final_url":      browser_data.get("final_url", url),
        "redirect_chain": browser_data.get("redirect_chain", []),
        "requests":       browser_data.get("requests", []),
        "js_events":      js_events,
        "tls_info":       tls_info,
        "cookies":        browser_data.get("cookies", []),
        "downloaded_files": browser_data.get("downloaded_files", []),  # ✅ now populated
        "page_title":     browser_data.get("page_title", ""),
        "screenshot":     browser_data.get("screenshot", "shot.png"),
        "scan_duration":  scan_duration,
        "meta": {
            "sandbox_id":             f"sandbox-{uuid.uuid4().hex[:8]}",
            "scan_timestamp":         datetime.now(timezone.utc).isoformat(),
            "sandbox_exited_cleanly": True,
        }
    }

    # ── Write to disk ─────────────────────────────────────────────────────────
    try:
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(evidence, f, indent=4)
        print(f"\n  ✅  evidence.json written → {output_path}")
    except Exception as e:
        print(f"\n  ✗  Could not write file: {e}")

    # ── Summary ───────────────────────────────────────────────────────────────
    print(f"\n{'─'*55}")
    print(f"  SCAN SUMMARY")
    print(f"{'─'*55}")
    print(f"  Scan duration   : {scan_duration}s")
    print(f"  Final URL       : {evidence['final_url']}")
    print(f"  Redirects       : {len(evidence['redirect_chain'])}")
    print(f"  Requests        : {len(evidence['requests'])}")
    print(f"  JS eval calls   : {len(js_events['eval_calls'])}")
    print(f"  Popups detected : {len(js_events['popups'])}")
    print(f"  Files downloaded: {len(evidence['downloaded_files'])}")
    print(f"  Has TLS         : {tls_info['has_tls']}")
    print(f"{'='*55}\n")

    return evidence


def _empty_browser_data(url: str) -> dict:
    return {
        "url":            url,
        "final_url":      url,
        "redirect_chain": [],
        "requests":       [],
        "js_events":      _empty_js_events(),
        "tls_info":       {"has_tls": False, "certificate_valid": False, "issuer": None},
        "cookies":        [],
        "downloaded_files": [],
        "popups":         [],
        "page_title":     "",
        "screenshot":     "shot.png",
    }


def _empty_js_events() -> dict:
    return {
        "eval_calls":       [],
        "dom_writes":       [],
        "popups":           [],
        "form_submissions": [],
    }


if __name__ == "__main__":
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else "https://github.com/nicowillis/documents/raw/master/sample.zip"
    result = build_evidence(target)