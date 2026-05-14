import docker
import json
import os


def connect_to_docker():
    client = docker.from_env()  # Connect to Docker on this machine
    print("Connected to Docker!")
    return client


def create_container(client, url: str):
    # ── Get absolute path to the project directory ────────────────────────────
    # We mount the current working directory into the container so the scanner
    # scripts (browser.py, evidence_builder.py, etc.) are available inside it.
    project_dir = os.path.abspath(".")

    # Ensure shot.png exists so Docker can mount it
    shot_path = os.path.join(project_dir, "shot.png")
    if not os.path.exists(shot_path):
        open(shot_path, "wb").close()

    container = client.containers.create(
        image="malicious-url-scanner",

        # FIX 1: Run the actual scanner instead of "echo hello"
        command=f"python /app/main.py {url}",

        mem_limit="512m",
        nano_cpus=500_000_000,  # 0.5 CPU

        # FIX 2: "none" cut off ALL network access — the scanner couldn't reach
        # any URL. "bridge" gives normal outbound internet access while still
        # isolating the container from your host's internal network.
        network_mode="bridge",

        # FIX 3: read_only=True prevented pip installs and writing evidence.json.
        # We mount a dedicated output folder as the writable area instead.
        read_only=False,

        volumes={
            project_dir: {"bind": "/app", "mode": "ro"},
            os.path.join(project_dir, "output"): {"bind": "/app/output", "mode": "rw"},
            os.path.join(project_dir, "shot.png"): {"bind": "/app/shot.png", "mode": "rw"},
        },

        working_dir="/app",
    )
    print("Container created.")
    return container


def run_sandbox(url: str) -> dict:
    # Make sure the output folder exists on the host before mounting it
    os.makedirs("output", exist_ok=True)

    client    = connect_to_docker()
    container = create_container(client, url)

    try:
        container.start()
        print("Container started!")

        # Wait up to 120 s — page scans can take a while
        result = container.wait(timeout=120)
        exit_code = result.get("StatusCode", -1)

        # Stream logs so you can see progress
        logs = container.logs().decode("utf-8", errors="replace")
        print("── Container output ──────────────────────────────")
        print(logs)
        print("──────────────────────────────────────────────────")

        if exit_code != 0:
            print(f"[WARN] Container exited with code {exit_code}")

        # Read evidence.json that the scanner wrote to /app/output/
        evidence_path = os.path.join("output", "evidence.json")
        if os.path.exists(evidence_path):
            with open(evidence_path, "r", encoding="utf-8") as f:
                return json.load(f)
        else:
            print("[WARN] evidence.json not found in output/")
            return {}

    finally:
        # Always destroy the container — no matter what
        container.remove(force=True)
        print("Container destroyed.")


if __name__ == "__main__":
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else "https://example.com"
    evidence = run_sandbox(target)
    print(json.dumps(evidence, indent=2))