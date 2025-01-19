import re
import requests
import json

# URLScan class for interacting with the urlscan.io API
class URLScan:
    def __init__(self):
        self.apikey = "fbdea673-aa27-4d64-891e-f12287d7b9b0"  # Please enter your own API
        self.headers = {'API-Key': self.apikey, 'Content-Type': 'application/json'}

    def scan_url(self, url):
        data = {"url": url, "visibility": "public"}
        response = requests.post('https://urlscan.io/api/v1/scan/', headers=self.headers, data=json.dumps(data))
        return response.json()

    def search_url(self, url):
        response = requests.get('https://urlscan.io/api/v1/search/?q=domain:' + url)
        return response.json()

# AbuseIPDB class for interacting with the AbuseIPDB API
class AbuseIPDB:
    def scan_ipdb(self, IPAddress):
        url = 'https://api.abuseipdb.com/api/v2/check'
        querystring = {
            'ipAddress': IPAddress,
            'maxAgeInDays': '90'
        }

        headers = {
            'Accept': 'application/json',
            'Key': '1965b5860ddac5550566add3208bd05dc18768512e92c6cdc4dbe22ede79d394e8d0811c93973ef2'  # Please enter your own API
        }

        response = requests.request(method='GET', url=url, headers=headers, params=querystring)
        return response.json()

# VirusTotal class for interacting with the VirusTotal API
class VirusTotal:
    def scan_file(self, hash):
        url = "https://www.virustotal.com/api/v3/files/" + hash
        headers = {
            "accept": "application/json",
            "x-apikey": "5c2f2c0e4f1a1962f68d33d46784a9d700a105c397c3d067e28ab367dd54f1e5"  # Please enter your own API
        }
        response = requests.get(url, headers=headers)
        return response.json()

    def scan_domain(self, domain):
        url = f"https://www.virustotal.com/api/v3/domains/{domain}"
        headers = {
            "accept": "application/json",
            "x-apikey": "5c2f2c0e4f1a1962f68d33d46784a9d700a105c397c3d067e28ab367dd54f1e5"  # Please enter your own API
        }
        response = requests.get(url, headers=headers)
        return response.json()

# ConsoleApp class for handling user input and running the application
class ConsoleApp:
    def __init__(self):
        self.urlscan = URLScan()
        self.abuseIPDB = AbuseIPDB()
        self.virusTotal = VirusTotal()

    def display_welcome_message(self):
        print("=" * 50)
        print("Welcome to the IoC Auto Detection Tool!")
        print("This tool allows you to analyze Indicators of Compromise (IoCs) including:")
        print("  - Domains")
        print("  - IP Addresses")
        print("  - File Hashes")
        print("Integrated Tools:")
        print("  - URLScan.io")
        print("  - AbuseIPDB")
        print("  - VirusTotal")
        print("Simply input a domain, IP address, or hash to get started.")
        print("Designed by ADSTech.")
        print("=" * 50)

    def detect_input_type(self, user_input):
        ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
        hash_pattern = re.compile(r'^[a-fA-F0-9]{32,64}$')
        domain_pattern = re.compile(r'^(?:[a-zA-Z0-9-]+\.)*[a-zA-Z0-9-]+\.[a-zA-Z]{2,}$')

        if ip_pattern.match(user_input):
            return "ip"
        elif hash_pattern.match(user_input):
            return "hash"
        elif domain_pattern.match(user_input):
            return "domain"
        else:
            return None

    def parse_and_display_results(self, urlscan_response, virustotal_response):
        print("\n=== URLScan Summary ===")
        for result in urlscan_response.get("results", []):
            task = result.get("task", {})
            page = result.get("page", {})
            print(f"URL: {task.get('url', 'N/A')}")
            print(f"IP: {page.get('ip', 'N/A')}")
            print(f"ASN: {page.get('asnname', 'N/A')} ({page.get('asn', 'N/A')})")
            print(f"TLS Validity: {page.get('tlsValidDays', 'N/A')} days")
            print(f"Title: {page.get('title', 'N/A')}")
            print(f"Screenshot: {result.get('screenshot', 'N/A')}")
            print("-" * 50)

        print("\n=== VirusTotal Summary ===")
        vt_attributes = virustotal_response.get("data", {}).get("attributes", {})
        print(f"Reputation: {vt_attributes.get('reputation', 'N/A')}")
        print(f"Malicious Detections: {vt_attributes.get('last_analysis_stats', {}).get('malicious', 'N/A')}")
        print(f"Last Analysis Results:")
        for engine, details in vt_attributes.get("last_analysis_results", {}).items():
            if details.get("category") in ["malicious", "suspicious"]:
                print(f"  - {engine}: {details.get('result', 'N/A')}")
        print("-" * 50)

    def process_input(self, user_input):
        input_type = self.detect_input_type(user_input)
        if input_type == "ip":
            print("Detected IP address. Querying AbuseIPDB...")
            response = self.abuseIPDB.scan_ipdb(user_input)
            print(json.dumps(response, indent=4))
        elif input_type == "hash":
            print("Detected hash value. Querying VirusTotal...")
            response = self.virusTotal.scan_file(user_input)
            print(json.dumps(response, indent=4))
        elif input_type == "domain":
            print("Detected domain. Querying URLScan...")
            urlscan_response = self.urlscan.search_url(user_input)

            print("Querying VirusTotal for domain...")
            virustotal_response = self.virusTotal.scan_domain(user_input)

            # Parse and display the results
            self.parse_and_display_results(urlscan_response, virustotal_response)
        else:
            print("Invalid input. Please enter a valid IP address, hash, or domain.")

    def run(self):
        self.display_welcome_message()
        while True:
            user_input = input("Enter an IP, hash, or domain (or type 'exit' to quit): ")
            if user_input.lower() == 'exit':
                break
            self.process_input(user_input)

# Main execution
if __name__ == '__main__':
    app = ConsoleApp()
    app.run()
