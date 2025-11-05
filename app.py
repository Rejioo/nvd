from flask import Flask, jsonify, request
from storage import load_cve_data, filter_by_days
import requests
import json

app = Flask(__name__)

# Load local CVEs
cves = load_cve_data()
@app.route("/")
def home():
    return jsonify({
        "message": "Welcome to CVE Info API 🚀",
        "usage": {
            "by_id": "/cve/<cve_id>",
            "recent": "/cve/recent?days=<num>",
            "example_id":"/cve/CVE-2025-0177",
        }
        
    })

@app.route("/cve/<cve_id>")
def get_cve_by_id(cve_id):
    """Return CVE details by ID, fetch from NVD if not found locally."""
    for item in cves:
        if item["cve"]["id"].lower() == cve_id.lower():
            return jsonify(item)

    # If not found locally — fetch directly from NVD
    print(f"Fetching {cve_id} from NVD API...")
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
    response = requests.get(url)
    if response.status_code == 200:
        data = response.json()
        if data.get("vulnerabilities"):
            cve_data = data["vulnerabilities"][0]
            # Optionally, store it locally for later
            cves.append(cve_data)
            with open("cve_data.json", "w") as f:
                json.dump(cves, f, indent=4)
            return jsonify(cve_data)
        else:
            return jsonify({"error": f"{cve_id} not found in NVD database"}), 404
    else:
        return jsonify({"error": "Failed to reach NVD API"}), 500

@app.route("/cve/recent")
def get_recent_cves():
    """Return CVEs modified in the last 'days' days."""
    days = int(request.args.get("days", 7))  # default 7
    recent = filter_by_days(cves, days)
    return jsonify({
        "count": len(recent),
        "recent_cves": recent
    })
@app.route("/test")
def test():
    return "Flask is working!"
if __name__ == "__main__":
    app.run(debug=True)
