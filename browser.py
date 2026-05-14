import hashlib
import os
import socket
import ssl
import time
from urllib.parse import urlparse

from playwright.sync_api import sync_playwright


def run_browser(url: str) -> dict:
    playwright = sync_playwright().start()
    browser = playwright.chromium.launch(
        headless=True,
        args=[
            "--no-sandbox",
            "--disable-dev-shm-usage",
            "--disable-gpu",
            "--disable-setuid-sandbox",
        ]
    )
    context = browser.new_context(
        accept_downloads=True,
        user_agent=(
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/122.0.0.0 Safari/537.36"
        ),
    )

    redirect_chain   = []
    popups           = []
    downloaded_files = []
    requests_log     = []

    try:
        page = context.new_page()

        # ── Redirects ─────────────────────────────────────────────────────
        page.on("response", lambda res:
            redirect_chain.append(res.url)
            if (300 <= res.status <= 399) else None
        )

        # ── Requests ──────────────────────────────────────────────────────
        def on_request(request):
            try:
                ip = socket.gethostbyname(urlparse(request.url).netloc)
            except Exception:
                ip = "unknown"
            requests_log.append({
                "url":    request.url,
                "type":   request.resource_type,
                "status": None,
                "ip":     ip,
            })

        def on_response(response):
            for req in requests_log:
                if req["url"] == response.url:
                    req["status"] = response.status
                    break

        page.on("request",  on_request)
        page.on("response", on_response)

        # ── Popups (new windows opened by Playwright) ─────────────────────
        def on_popup(popup_page):
            try:
                popup_page.wait_for_load_state("domcontentloaded", timeout=5000)
                url_caught = popup_page.url
            except Exception as e:
                url_caught = f"popup-detected (url unavailable): {e}"
            popups.append(url_caught)
            print(f"  [POPUP/NEW-WINDOW] {url_caught}")

        page.on("popup", on_popup)

        # ── Downloads ─────────────────────────────────────────────────────
        os.makedirs("downloads", exist_ok=True)

        def on_download(download):
            try:
                print(f"  [DOWNLOAD TRIGGERED] filename={download.suggested_filename} url={download.url}")
                os.makedirs("downloads", exist_ok=True)
                path = os.path.join(os.path.abspath("downloads"), download.suggested_filename)
                print(f"  [DOWNLOAD SAVING TO] {path}")
                download.save_as(path)
                with open(path, "rb") as fh:
                    content = fh.read()
                downloaded_files.append({
                    "filename": download.suggested_filename,
                    "url":      download.url,
                    "md5":      hashlib.md5(content).hexdigest(),
                    "sha256":   hashlib.sha256(content).hexdigest(),
                })
                print(f"  [DOWNLOAD] {download.suggested_filename} ({len(content):,} bytes)")
            except Exception as e:
                downloaded_files.append({
                    "filename": download.suggested_filename,
                    "url":      download.url,
                    "error":    str(e),
                })
                print(f"  [DOWNLOAD ERROR] {e}")

        page.on("download", on_download)

        # ── JS spy ────────────────────────────────────────────────────────
        # FIX (eval_calls bug): The old code used window.eval to read back
        # __spy data, which caused the readback expression itself to appear
        # in eval_calls. We now use a flag (__spy_reading) to suppress that,
        # so only the PAGE's own eval() calls are recorded.
        spy_script = """
        window.__spy = {
            eval_calls: [], dom_writes: [], popups: [], form_submissions: []
        };
        window.__spy_reading = false;

        const _re = window.eval;
        window.eval = function(c) {
            if (!window.__spy_reading) {
                window.__spy.eval_calls.push(String(c));
            }
            return _re(c);
        };
        const _rw = document.write.bind(document);
        document.write = function(h) { window.__spy.dom_writes.push(String(h)); return _rw(h); };
        window.alert   = function(m) { window.__spy.popups.push('[alert] '       + String(m)); };
        window.confirm = function(m) { window.__spy.popups.push('[confirm] '     + String(m)); return true; };
        window.prompt  = function(m) { window.__spy.popups.push('[prompt] '      + String(m)); return null; };
        window.open    = function(u) { window.__spy.popups.push('[window.open] ' + String(u)); return null; };
        document.addEventListener('submit', function(e) {
            const f = e.target, fields = [];
            for (const i of f.elements) if (i.name) fields.push(i.name);
            window.__spy.form_submissions.push({ action: f.action || 'unknown', fields });
        });
        """
        page.add_init_script(spy_script)

# ── Visit ─────────────────────────────────────────────────────────
        print(f"  Visiting {url} ...")
        try:
            page.goto(url, timeout=60000, wait_until="networkidle")
        except Exception as e:
            print(f"  [goto note] {e}")

        # ── Auto-click buttons to trigger JS popups ───────────────────────
        try:
            for frame in page.frames:
                buttons = frame.query_selector_all("button, input[type='button'], input[type='submit'], a")
                for btn in buttons[:5]:  # max 5 clicks
                    try:
                        btn.click(timeout=1000)
                        time.sleep(0.3)
                    except Exception:
                        pass
        except Exception:
            pass

        time.sleep(1)  # let async downloads/popups settle

        # ── Collect JS events ─────────────────────────────────────────────
        # FIX: set __spy_reading=true before evaluating so the readback call
        # itself is never pushed into eval_calls.
        try:
            js_events = page.evaluate("""
                () => {
                    window.__spy_reading = true;
                    const data = {
                        eval_calls:       window.__spy.eval_calls,
                        dom_writes:       window.__spy.dom_writes,
                        popups:           window.__spy.popups,
                        form_submissions: window.__spy.form_submissions,
                    };
                    window.__spy_reading = false;
                    return data;
                }
            """)
        except Exception:
            js_events = {
                "eval_calls": [], "dom_writes": [],
                "popups": [], "form_submissions": []
            }

        # Merge Playwright new-window popups into js_events
        for p in popups:
            js_events["popups"].append(f"[new-window] {p}")

        # ── TLS ───────────────────────────────────────────────────────────
        has_tls = url.startswith("https://")
        tls_info = {"has_tls": has_tls, "certificate_valid": False, "issuer": None}
        if has_tls:
            try:
                domain = urlparse(url).netloc
                ctx    = ssl.create_default_context()
                conn   = ctx.wrap_socket(socket.socket(), server_hostname=domain)
                conn.connect((domain, 443))
                cert   = conn.getpeercert()
                issuer = dict(x[0] for x in cert["issuer"])
                conn.close()
                tls_info = {
                    "has_tls":           True,
                    "certificate_valid": True,
                    "issuer":            issuer.get("organizationName", "unknown"),
                }
            except Exception as e:
                print(f"  [TLS error] {e}")

        cookies = [
            {"name": c["name"], "value": c["value"],
             "domain": c["domain"], "secure": c["secure"]}
            for c in page.context.cookies()
        ]

        if page.url not in redirect_chain:
            redirect_chain.append(page.url)

        try:
            import os as _os
            _os.makedirs("output", exist_ok=True)
            page.screenshot(path="output/shot.png", full_page=True)
            # Keep a root-level copy as fallback
            page.screenshot(path="shot.png", full_page=True)
        except Exception:
            pass

        try:
            page_title = page.title()
        except Exception:
            page_title = ""

        print(f"  Done — requests={len(requests_log)}  "
              f"popups={len(js_events['popups'])}  "
              f"downloads={len(downloaded_files)}")

        return {
            "url":              url,
            "final_url":        page.url,
            "redirect_chain":   list(dict.fromkeys(redirect_chain)),
            "requests":         requests_log,
            "js_events":        js_events,
            "tls_info":         tls_info,
            "cookies":          cookies,
            "downloaded_files": downloaded_files,
            "page_title":       page_title,
            "screenshot":       "shot.png",
        }

    except Exception as e:
        print(f"  [FATAL] {e}")
        return {
            "url":              url,
            "final_url":        url,
            "redirect_chain":   [],
            "requests":         requests_log,
            "js_events":        {"eval_calls":[],"dom_writes":[],"popups":[],"form_submissions":[]},
            "tls_info":         {"has_tls": False, "certificate_valid": False, "issuer": None},
            "cookies":          [],
            "downloaded_files": downloaded_files,
            "page_title":       "",
            "screenshot":       "shot.png",
            "error":            str(e),
        }

    finally:
        context.close()
        browser.close()
        playwright.stop()


if __name__ == "__main__":
    import json, sys
    target = sys.argv[1] if len(sys.argv) > 1 else "https://example.com"
    print(json.dumps(run_browser(target), indent=2))