import requests
import json
import time

def fetch_cve_data(start_index=0, results_per_page=2000):
    """Fetch CVE data using NVD API with pagination."""
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?startIndex={start_index}&resultsPerPage={results_per_page}"
    print(f"Fetching: {url}")
    response = requests.get(url)
    if response.status_code == 200:
        data = response.json()
        return data.get("vulnerabilities", [])
    else:
        print("Failed to fetch data:", response.status_code)
        return []

def save_to_file(data, filename="cve_data.json"):
    """Save data to JSON file."""
    with open(filename, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4)
    print(f"✅ Saved {len(data)} CVEs to {filename}")

def main():
    all_cves = []
    start_index = 0
    results_per_page = 2000  # max allowed by NVD

    # Fetch first 5000 CVEs (for demo; full set = millions)
    for _ in range(3):  
        cves = fetch_cve_data(start_index, results_per_page)
        if not cves:
            break
        all_cves.extend(cves)
        start_index += results_per_page
        time.sleep(1)  # be nice to the API

    save_to_file(all_cves)

if __name__ == "__main__":
    main()
