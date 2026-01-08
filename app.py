import ssl
ssl._create_default_https_context = ssl._create_unverified_context

import os
from flask import Flask, request, jsonify
from urllib.parse import urlparse

app = Flask(__name__)

# ---------- FILE PATH SAFETY (IMPORTANT FOR RENDER) ----------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

LEAK_FILE = os.path.join(BASE_DIR, "leaks1.txt")
if not os.path.exists(LEAK_FILE):
    LEAK_FILE = os.path.join(BASE_DIR, "leaks.txt")

print("🚀 App started")
print("📂 Using leak file:", LEAK_FILE)
print("📂 File exists:", os.path.exists(LEAK_FILE))


def extract_username_from_url(url):
    """
    Extracts meaningful username from URL path
    Example:
    https://accounts.google.com/signin/v2/speedbump/changepassword
    → speedbump
    """
    ignore = {
        "signin", "signup", "login", "auth",
        "v1", "v2", "v3",
        "changepassword", "resetpassword",
        "password", "account", "accounts"
    }

    try:
        path_parts = [
            p for p in urlparse(url).path.split("/")
            if p and p.lower() not in ignore
        ]

        if path_parts:
            return path_parts[0]
    except Exception as e:
        print("❌ Username extract error:", str(e))

    return "unknown"


@app.route("/check-leak", methods=["POST"])
def check_leak():
    try:
        data = request.get_json(force=True)
        query = data.get("query", "").strip()

        print("🔍 Incoming query:", query)

        if not query:
            return jsonify({
                "status": "error",
                "message": "Query is required"
            }), 400

        results = []

        if not os.path.exists(LEAK_FILE):
            raise FileNotFoundError(f"{LEAK_FILE} not found on server")

        with open(LEAK_FILE, "r", encoding="utf-8", errors="ignore") as file:
            for line in file:
                line = line.strip()

                if query in line:
                    url = ""
                    username = ""
                    password = ""

                    kv_pairs = {}

                    # Parse key=value pairs separated by ;
                    for part in [p.strip() for p in line.split(";") if p.strip()]:
                        if "=" in part:
                            k, v = part.split("=", 1)
                            kv_pairs[k.strip().lower()] = v.strip()

                    if kv_pairs:
                        url = kv_pairs.get("url", "") or kv_pairs.get("link", "")
                        username = kv_pairs.get("username", "") or kv_pairs.get("user", "")
                        password = kv_pairs.get("password", "") or kv_pairs.get("pass", "")
                    else:
                        parts = line.split()
                        if parts:
                            url = parts[0]
                            creds = parts[1] if len(parts) > 1 else ""

                            if ":" in creds:
                                username, password = creds.split(":", 1)
                            elif "=" in creds:
                                k, v = creds.split("=", 1)
                                if k.lower() in ("password", "pass"):
                                    password = v
                                elif k.lower() in ("username", "user"):
                                    username = v

                    if url and not username:
                        username = extract_username_from_url(url)

                    if not url:
                        for token in line.split():
                            if token.startswith("http://") or token.startswith("https://"):
                                url = token
                                break

                    results.append({
                        "url": url,
                        "username": username,
                        "password": password
                    })

        print("✅ Matches found:", len(results))

        if results:
            return jsonify({
                "status": "leak_found",
                "message": "Data leak detected",
                "count": len(results),
                "data": results
            })

        return jsonify({
            "status": "safe",
            "message": "No data leak found"
        })

    except Exception as e:
        # 🔥 THIS PREVENTS 500 CRASH AND SHOWS REAL ERROR
        print("🔥 SERVER ERROR:", str(e))
        return jsonify({
            "status": "error",
            "message": str(e)
        }), 500


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
