from flask import Flask, request, jsonify, send_from_directory
import json
import os
import traceback

app = Flask(__name__)

@app.route("/")
def index():
    return send_from_directory(".", "page.html")

@app.route("/scan", methods=["POST"])
def scan():
    data = request.get_json()
    url = data.get("url", "").strip()

    if not url:
        return jsonify({"error": "No URL provided"}), 400

    # Make sure URL has a scheme
    if not url.startswith("http"):
        url = "https://" + url

    print(f"\n🔍 Scanning: {url}")  # confirm correct URL in terminal

    try:
        os.makedirs("output", exist_ok=True)

        # Run the scan INSIDE Docker
        from sandbox import run_sandbox
        evidence = run_sandbox(url)

        # ✅ FIXED: read from output/ not root!
        verdict_path = os.path.join("output", "verdict.json")
        if os.path.exists(verdict_path):
            with open(verdict_path, "r") as f:
                verdict = json.load(f)
        else:
            verdict = {"error": "Scan failed — verdict.json not found"}

        return jsonify({
            "verdict": verdict,
            "evidence": evidence
        })

    except Exception as e:
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500

@app.route("/screenshot")
def screenshot():
    # Use absolute paths — Flask's send_from_directory fails with relative dirs
    base = os.path.abspath(".")
    output_shot = os.path.join(base, "output", "shot.png")
    root_shot   = os.path.join(base, "shot.png")

    if os.path.exists(output_shot) and os.path.getsize(output_shot) > 0:
        return send_from_directory(os.path.join(base, "output"), "shot.png")
    elif os.path.exists(root_shot) and os.path.getsize(root_shot) > 0:
        return send_from_directory(base, "shot.png")
    else:
        return ("No screenshot", 404)

if __name__ == "__main__":
    app.run(debug=True, port=5000)