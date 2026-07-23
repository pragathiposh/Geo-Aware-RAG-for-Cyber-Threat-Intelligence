import requests

def fetch_otx(api_key):
    url = "https://otx.alienvault.com/api/v1/pulses/subscribed"

    headers = {
        "X-OTX-API-KEY": api_key
    }

    params = {
        "modified_since": "2025-01-01T00:00:00"
    }

    response = requests.get(url, headers=headers, params=params)
    response.raise_for_status()

    return response.json()["results"]