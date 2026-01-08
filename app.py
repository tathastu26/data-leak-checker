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
    try:
        path_parts = urlparse(url).path.split("/")
        path_parts = [p for p in path_parts if p]

        # choose middle meaningful part
        if len(path_parts) >= 3:
            return path_parts[2]
        elif len(path_parts) >= 1:
            return path_parts[-1]
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
                # Example format:
                # URL username:password
                parts = line.split()

                url = parts[0]
                creds = parts[1] if len(parts) > 1 else ""

                password = ""
                if ":" in creds:
                    password = creds.split(":")[0]

                username = extract_username_from_url(url)

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
