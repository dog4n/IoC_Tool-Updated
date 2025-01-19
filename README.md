# IoC_Tool-Updated
  The code automatically identifies the input type (IP, hash, or domain) and queries the relevant APIs, providing concise and user-friendly results.


  The code analyzes user input, automatically determines its type, and queries relevant APIs. It supports the following input types:

IP Address: Sends a query to the AbuseIPDB API.
Hash: Sends a query to the VirusTotal API.
Domain: Sends a query to the URLScan API.

The input is classified based on regular expressions, and an appropriate error message is displayed if the input is invalid. The code improves the user experience by eliminating the need for a menu, ensuring smoother operation.
