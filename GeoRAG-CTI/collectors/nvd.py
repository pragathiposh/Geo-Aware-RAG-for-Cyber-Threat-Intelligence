import requests

def fetch_nvd(api_key):
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    params = {
        "resultsPerPage": 2000,
        "startIndex": 0
    }

    headers = {
        "apiKey": api_key
    }

    response = requests.get(url, params=params, headers=headers)
    response.raise_for_status()

    return response.json()["vulnerabilities"]