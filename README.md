# 🛡️ Malicious URL Detection Sandbox:

![Python](https://img.shields.io/badge/Python-3.12+-1a1a2e?style=for-the-badge&logo=python&logoColor=f5a623)
![Docker](https://img.shields.io/badge/Docker-Required-1a1a2e?style=for-the-badge&logo=docker&logoColor=f5a623)
![Flask](https://img.shields.io/badge/Flask-Web%20Server-1a1a2e?style=for-the-badge&logo=flask&logoColor=f5a623)
![Security](https://img.shields.io/badge/Security-URL%20Scanner-1a1a2e?style=for-the-badge&logo=shield&logoColor=f5a623)

> A browser-based sandbox that visits a URL inside an isolated Docker container, analyzes its behavior, and returns a threat verdict with a risk score.

| 🟢 CLEAN | 🟠 SUSPICIOUS | 🔴 MALICIOUS |
|:---:|:---:|:---:|
| Score 0 – 30 | Score 31 – 69 | Score 70 – 100 |

---

##  Demo Video

[▶ Watch the Full Demo](https://www.youtube.com/watch?v=DAkPTsAi1RQ)

---

## 📄 Report
[Read the Full Report](./REPORT.pdf)

---


##  Preview

<img width="1915" height="951" alt="Website" src="https://github.com/user-attachments/assets/e07f5a50-c955-4c66-a08c-4d1e0b8568ab" />

<table>
<tr>
<td align="center"><strong>🟢 Clean Case</strong></td>
<td align="center"><strong>🔴 Malicious Case</strong></td>
<td align="center"><strong>🔴 Malicious Case (Detail)</strong></td>
</tr>
<tr>
<td><img width="576" src="https://github.com/user-attachments/assets/b3165506-8011-4839-9c6c-b192feba5526" /></td>
<td><img width="556" src="https://github.com/user-attachments/assets/ffabed52-1384-48a9-a46c-0073d881f1d7" /></td>
<td><img width="551" src="https://github.com/user-attachments/assets/47c6c8b5-de33-4c03-9efb-5e30f6da1c46" /></td>
</tr>
</table>

---

##  Requirements

- Python 3.12+
- Docker Desktop — must be running
- Dependencies listed in `requirements.txt`

---

##  Setup

```bash
# Install dependencies
python -m pip install -r requirements.txt
python -m pip install docker

# Install Playwright browser
playwright install chromium

# Build the Docker image (once)
docker build -t malicious-url-scanner .

# Create output folder
mkdir output
```

---

##  Run

```bash
python app.py
```

Open **http://127.0.0.1:5000** in your browser.

---

##  How It Works

The system runs a two-part pipeline:

```
URL Input ──► Browser (Playwright) ──► evidence.json ──► Analysis Pipeline ──► Verdict
```

**Pipeline 1 — Evidence Collection**
Visits the URL in a headless Chromium browser, hooks JavaScript functions (`eval`, `document.write`, form submissions), logs every network request, verifies TLS, and records any file downloads.

**Pipeline 2 — Threat Analysis**
Queries VirusTotal, AbuseIPDB, and URLhaus, applies 16 heuristic detection rules, and produces a final risk score.

**Every scan runs inside a fresh Docker container — the host machine is never exposed.**

---

##  How to Use

1. Paste any URL into the input field
2. Click **Scan URL**
3. Wait 20 – 60 seconds while the sandbox runs
4. Read the result

| Field | Description |
|---|---|
| **Score** | Risk level from 0 to 100 |
| **Verdict** | CLEAN / SUSPICIOUS / MALICIOUS |
| **Signals** | Exact reasons the score was raised |
| **Technical Details** | Redirects, requests, TLS, cookies, duration |
| **Screenshot** | What the page looked like inside the sandbox |

---

##  Project Structure

| File | Role |
|---|---|
| `app.py` | Flask web server |
| `main.py` | Pipeline orchestrator |
| `browser.py` | Playwright browser + JS spy |
| `js_hooks.py` | JavaScript instrumentation |
| `network_capture.py` | TLS verification + request logging |
| `evidence_builder.py` | Builds `evidence.json` |
| `ioc_extractor.py` | Extracts IPs, domains, hashes |
| `threat_intel.py` | VirusTotal · AbuseIPDB · URLhaus |
| `heuristics.py` | 16 detection rules |
| `scorer.py` | Risk scoring |
| `verdict.py` | Final verdict |
| `sandbox.py` | Docker container management |

---

##  Live Test Result

Tested on a Netflix phishing clone — verdict: **SUSPICIOUS 55/100**

| Metric | Value |
|---|---|
| Scan duration | 14.72s |
| HTTP requests | 9 |
| Redirects | 2 |
| TLS issuer | Let's Encrypt |
| VirusTotal | 16 engines flagged |
| AbuseIPDB | Score 32/100 |

---

> 📚 Network & System Security — April 2026
