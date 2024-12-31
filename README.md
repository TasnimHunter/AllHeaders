# AllHeaders

**AllHeaders** is a Python tool designed to test web applications for common HTTP header vulnerabilities. This tool automates checks for issues such as HTTP Response Splitting, Header Injection, Sensitive Information Exposure, and other vulnerabilities, making it easier for penetration testers and bug hunters to identify security flaws.

---



## Installation

### Prerequisites
- Python 3.7 or higher
- `requests` library

### Steps
1. Clone the repository:
   ```bash
   git clone https://github.com/TasnimHunter/AllHeaders.git
   cd AllHeaders
2. Install the required dependencies:
   ```
   pip install -r requirements.txt
## Usage
1. Run the script:
   ```
   python AllHeaders.py
2. Enter the target URL when prompted:
   ```
   Enter the URL to test for HTTP header vulnerabilities: http://example.com

Vulnerabilities Tested

The tool currently tests for the following vulnerabilities:

1. **HTTP Response Splitting:** Attempts to inject newline characters to split headers.
2. **HTTP Header Injection:** Tests for header injection payloads.
3. **Sensitive Information Exposure:** Identifies sensitive headers like X-Powered-By and Server.
4. **XSS in HTTP Headers:** Checks if custom headers like User-Agent can trigger XSS.
5. **Host Header Injection:** Exploits applications relying on the Host header.
6. **CSRF Vulnerabilities:** Manipulates Referer and Origin headers.
7. **Cache Poisoning:** Detects improper Cache-Control headers.
8. **HSTS Misconfiguration:** Verifies if Strict-Transport-Security is implemented.
9. **X-Forwarded-For Spoofing:** Checks for spoofing of IP addresses via headers.
		
### Contribution

Feel free to contribute to this project by submitting issues or pull requests. All contributions are welcome!

### Disclaimer

This tool is intended for educational purposes and authorized security testing only. The author is not responsible for any misuse or illegal activity conducted with this tool.
