import socket
import ssl
from urllib.parse import urlparse


def setup_network_capture(page):
    requests_log = []

    def on_request(request):
        try:
            domain = urlparse(request.url).netloc
            ip = socket.gethostbyname(domain)
        except:
            ip = "unknown"

        requests_log.append({
            "url": request.url,
            "type": request.resource_type,
            "status": None,  # Filled in when the response arrives
            "ip": ip
        })

    def on_response(response):
        for req in requests_log:
            if req["url"] == response.url:
                req["status"] = response.status
                break

    page.on("request", on_request)
    page.on("response", on_response)

    print("Network Capture Ready!")
    return requests_log


def get_tls_info(url):
    try:
        has_tls = url.startswith("https")

        if has_tls:
            domain = urlparse(url).netloc
            context = ssl.create_default_context()
            conn = context.wrap_socket(
                socket.socket(socket.AF_INET),
                server_hostname=domain
            )
            conn.connect((domain, 443))
            cert = conn.getpeercert()
            issuer = dict(x[0] for x in cert["issuer"])
            conn.close()

            return {
                "has_tls": True,
                "certificate_valid": True,
                "issuer": issuer.get("organizationName", "unknown")
            }
        else:
            return {
                "has_tls": False,
                "certificate_valid": False,
                "issuer": None
            }
    except:
        return {
            "has_tls": False,
            "certificate_valid": False,
            "issuer": None
        }


def get_cookies(page):
    cookies_log = []
    cookies = page.context.cookies()

    for cookie in cookies:
        cookies_log.append({
            "name": cookie["name"],
            "value": cookie["value"],
            "domain": cookie["domain"],
            "secure": cookie["secure"]
        })

    print(f"Captured {len(cookies_log)} cookies")
    return cookies_log


# ✅ FIX Bug 2: get_downloaded_files() is REMOVED from here.
#
# WHY: browser.py already sets page.on("download", ...) with its own listener.
# If we also call get_downloaded_files() here, Playwright fires BOTH listeners
# for every download, causing:
#   - Duplicate entries in two separate lists
#   - Race condition: both try to save_as() the same file at the same time → crash
#
# The single download listener now lives entirely in browser.py's run_browser().
# All download data is returned inside the browser_data dict to evidence_builder.


def run_network_capture(page, url):
    """Combined helper — use this if you want everything in one call."""
    requests_log = setup_network_capture(page)
    tls_info = get_tls_info(url)
    cookies = get_cookies(page)

    return {
        "requests": requests_log,
        "tls_info": tls_info,
        "cookies": cookies,
        # downloaded_files intentionally omitted — handled in browser.py
    }