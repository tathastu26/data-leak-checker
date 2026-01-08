from flask import Flask, request, jsonify

app = Flask(__name__)
LEAK_FILE = "leaks.txt"

def mask(value):
    if len(value) <= 4:
        return "****"
    return value[:2] + "****" + value[-2:]

@app.route("/check-leak", methods=["POST"])
def check_leak():
    data = request.json
    query = data.get("query")

    if not query:
        return jsonify({"error": "query is required"}), 400

    with open(LEAK_FILE, "r", errors="ignore") as file:
        for line in file:
            if query in line:
                if ":" in line:
                    _, password = line.rsplit(":", 1)
                else:
                    password = "unknown"

                return jsonify({
                    "status": "leaked",
                    "message": "⚠️ Data Leak Found",
                    "password_masked": mask(password.strip())
                })

    return jsonify({
        "status": "safe",
        "message": "✅ No Data Leak Found"
    })

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)

