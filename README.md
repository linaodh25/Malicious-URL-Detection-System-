# Malicious URL Detection Sandbox

A browser-based tool that visits a URL inside a Docker container, analyzes its behavior, and returns a threat verdict (CLEAN / SUSPICIOUS / MALICIOUS) with a risk score.

---

## Requirements

- Python 3.12+
- Docker Desktop (must be running)
- All dependencies from `requirements.txt`

---

## Setup

```bash
# 1. Install Python dependencies
python -m pip install -r requirements.txt
python -m pip install docker

# 2. Install Playwright browser
playwright install chromium

# 3. Build the Docker image (only once)
docker build -t malicious-url-scanner .

# 4. Create the output folder
mkdir output
```

---

## Run

```bash
python app.py
```

Then open your browser at **http://127.0.0.1:5000**

---

## How to Use

1. Type or paste a URL into the input field
2. Click **Scan URL**
3. Wait 20–60 seconds while the sandbox runs inside Docker
4. Read the result:
   - **Score** — risk level from 0 to 100
   - **Verdict** — CLEAN / SUSPICIOUS / MALICIOUS
   - **Signals** — exact reasons the score was raised
   - **Technical details** — redirects, requests, TLS, cookies, scan duration
   - **Screenshot** — what the page looked like inside the sandbox

---

## Project Structure

| File | Role |
|---|---|
| `app.py` | Flask web server |
| `main.py` | Pipeline orchestrator |
| `browser.py` | Playwright browser + JS spy |
| `evidence_builder.py` | Builds `evidence.json` |
| `ioc_extractor.py` | Extracts IPs, domains, hashes |
| `threat_intel.py` | VirusTotal, AbuseIPDB, URLhaus |
| `heuristics.py` | 16 detection rules |
| `scorer.py` | Risk scoring |
| `verdict.py` | Final verdict |
| `sandbox.py` | Docker container management |



<!-- https://www.wikipedia.org -->
<!-- https://brunovcg.github.io/Netflix-login-page-clone -->