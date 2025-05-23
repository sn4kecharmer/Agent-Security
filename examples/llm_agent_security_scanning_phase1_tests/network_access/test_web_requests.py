# Vulnerability: SSRF via Unrestricted Web Requests
import requests

def fetch_url(url):
    response = requests.get(url)  # Insecure: url input is unsanitized
    return response.text
