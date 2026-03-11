"""Demo backend server – simulates the protected application (Phase 2+)."""

from flask import Flask, jsonify

app = Flask(__name__)


@app.route("/")
def index():
    return jsonify({"message": "Backend demo running"})


if __name__ == "__main__":
    app.run(port=8080)
