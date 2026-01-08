from flask import Flask, request, jsonify
from urllib.parse import urlparse

app = Flask(__name__)

LEAK_FILE = "leaks.txt"


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
    except:
        pass

    return "unknown"


@app.route("/check-leak", methods=["POST"])
def check_leak():
    data = request.get_json()
    query = data.get("query", "").strip()

    if not query:
        return jsonify({
            "status": "error",
            "message": "Query is required"
        }), 400

    results = []

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


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
