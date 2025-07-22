import requests
import time

VULNERS_API_KEY = "API_KEY"
VULNERS_API_URL = "https://vulners.com/api/v3/burp/software/"

def query_vulners(product: str, version: str):
    try:
        params = {
            "software": product,
            "version": version,
            "apiKey": VULNERS_API_KEY
        }
        response = requests.get(VULNERS_API_URL, params=params)
        if response.status_code == 200:
            return response.json()
        return {"error": "No data from Vulners"}
    except Exception as e:
        return {"error": str(e)}

def query_nvd(cpe: str):
    try:
        headers = {"User-Agent": "agentrecon"}
        response = requests.get(f"https://services.nvd.nist.gov/rest/json/cves/2.0?cpeName={cpe}", headers=headers)
        return response.json()
    except Exception as e:
        return {"error": str(e)}

def lookup(product: str, version: str, cpe: str = None):
    vulners_data = query_vulners(product, version)
    nvd_data = query_nvd(cpe) if cpe else {}
    return {"vulners": vulners_data, "nvd": nvd_data}

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 3:
        print("Usage: python cve_lookup.py <product> <version> [cpe]")
    else:
        result = lookup(sys.argv[1], sys.argv[2], sys.argv[3] if len(sys.argv) > 3 else None)
        print(result)
