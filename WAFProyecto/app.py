"""
WAF – Main Application Entry Point (Phase 1)

Starts Flask, wires up SQLAlchemy with MySQL, and registers a minimal
health-check endpoint.  The proxy engine and REST API will be added in
later phases.
"""

from flask import Flask, jsonify
from config import Config
from database import init_db

app = Flask(__name__)
app.config.from_object(Config)

# Initialise the database (creates tables if they don't exist)
init_db(app)


# ── Health-check ────────────────────────────────────────────────────────────
@app.route("/health", methods=["GET"])
def health():
    """Simple liveness probe."""
    return jsonify({"status": "running"}), 200


# ────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
