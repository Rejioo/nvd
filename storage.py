import json
from datetime import datetime, timedelta

def load_cve_data(filename="cve_data.json"):
    """Load CVE data from JSON file."""
    with open(filename, "r", encoding="utf-8") as f:
        return json.load(f)

def filter_by_days(cves, days):
    """Filter CVEs modified in the last `days` days."""
    recent = []
    cutoff_date = datetime.utcnow() - timedelta(days=days)
    for cve in cves:
        try:
            last_modified = cve["cve"]["lastModified"]
            last_modified_date = datetime.fromisoformat(last_modified.replace("Z", "+00:00"))
            if last_modified_date >= cutoff_date:
                recent.append(cve)
        except KeyError:
            continue
    return recent
