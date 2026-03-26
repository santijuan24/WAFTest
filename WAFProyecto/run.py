"""
WAF Project Launcher — run from the WAFProyecto root directory.
Usage:
    python run.py api      # starts API + Dashboard on port 8000
    python run.py waf      # starts WAF Proxy on port 8080
    python run.py all      # starts both (press Ctrl+C to stop)
"""

import sys
import os
import subprocess

PROJECT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "waf_project")

# Set PYTHONPATH globally so uvicorn --reload subprocesses inherit it
os.environ["PYTHONPATH"] = PROJECT_DIR + os.pathsep + os.environ.get("PYTHONPATH", "")


def run_api():
    print("[*] Starting API & Dashboard on port 8000...")
    subprocess.run([
        sys.executable, "-m", "uvicorn",
        "api.server:app",
        "--host", "0.0.0.0", "--port", "8000",
        "--reload",
    ], cwd=PROJECT_DIR)


def run_waf():
    print("[*] Starting WAF Proxy on port 8080...")
    subprocess.run([
        sys.executable, "-m", "uvicorn",
        "main:app",
        "--host", "0.0.0.0", "--port", "8080",
        "--reload",
    ], cwd=PROJECT_DIR)


def run_all():
    import threading
    t1 = threading.Thread(target=run_api, daemon=True)
    t2 = threading.Thread(target=run_waf, daemon=True)
    t1.start()
    t2.start()
    try:
        t1.join()
        t2.join()
    except KeyboardInterrupt:
        print("\n[*] Shutting down...")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python run.py [api|waf|all]")
        sys.exit(1)

    mode = sys.argv[1].lower()
    if mode == "api":
        run_api()
    elif mode == "waf":
        run_waf()
    elif mode == "all":
        run_all()
    else:
        print(f"Unknown mode: {mode}")
        print("Usage: python run.py [api|waf|all]")
