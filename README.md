# IoC_Tool-Updated
The code uses regular expressions to automatically identify the input type (IP address, hash, or domain) and queries the relevant APIs, delivering concise and user-friendly results.

It supports the following input types, detected via regular expression patterns:

IP Address: Matches IPv4 format and queries the AbuseIPDB API.
Hash: Matches MD5, SHA-1, or SHA-256 formats and queries the VirusTotal API.
Domain: Matches valid domain names and queries the URLScan API.
Invalid inputs that do not match any pattern are flagged with an error message. This regex-driven approach streamlines the user experience by removing the need for a menu and automating operations.
