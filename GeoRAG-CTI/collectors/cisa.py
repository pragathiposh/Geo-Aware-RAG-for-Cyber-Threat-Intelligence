import requests

def fetch_cisa_kev():
    url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

    response = requests.get(url)
    response.raise_for_status()

    return response.json()["vulnerabilities"]