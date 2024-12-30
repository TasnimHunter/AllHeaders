import socket
from urllib.parse import urlparse
import requests
import argparse


# ANSI escape codes for colors
GREEN = "\033[92m"
RED = "\033[91m"
RESET = "\033[0m"

def format_result(message, positive=True):
    """
    Formats the message with green for positive results and red for negative results.
    """
    color = GREEN if positive else RED
    return f"{color}{message}{RESET}"

# Function to display the image as ASCII art

def check_http_response_splitting(url):
    parsed_url = urlparse(url)
    host = parsed_url.netloc
    path = parsed_url.path or "/"

    payload = "foo\r\nAnother-Header: Bar"
    request = f"GET {path} HTTP/1.1\r\nHost: {host}\r\nX-Injected-Header: {payload}\r\nConnection: close\r\n\r\n"

    try:
        with socket.create_connection((host, 80)) as s:
            s.sendall(request.encode())
            response = s.recv(4096).decode()
            if "Another-Header" in response:
                return format_result("\n\n[+]..Possible HTTP Response Splitting Vulnerability Found", True)
    except Exception as e:
        return format_result(f"\nError occurred: {e}", False)
    return format_result("\n[-]..No HTTP Response Splitting Detected", False)

def check_header_injection(url):
    parsed_url = urlparse(url)
    host = parsed_url.netloc
    path = parsed_url.path or "/"

    payloads = ["\r\nX-Injected-Header: Malicious", "\nX-Injected-Header: Malicious"]
    for payload in payloads:
        request = f"GET {path} HTTP/1.1\r\nHost: {host}\r\nX-Test-Header: {payload}\r\nConnection: close\r\n\r\n"
        try:
            with socket.create_connection((host, 80)) as s:
                s.sendall(request.encode())
                response = s.recv(4096).decode()
                if "Malicious" in response:
                    return format_result("\n[+]..Possible HTTP Header Injection Vulnerability Found", True)
        except Exception as e:
            return format_result(f"\nError occurred: {e}", False)
    return format_result("\n[-]..No HTTP Header Injection Detected", False)

def check_sensitive_info_exposure(url):
    try:
        response = requests.get(url)
        sensitive_headers = ['X-Powered-By', 'Server']
        missing_security_headers = ['Strict-Transport-Security', 'Content-Security-Policy', 
                                     'X-Content-Type-Options', 'X-Frame-Options', 'X-XSS-Protection']
        
        exposed_info = []
        for header in sensitive_headers:
            if header in response.headers:
                exposed_info.append(f"{header}: {response.headers[header]}")
        
        missing_flags = []
        for header in missing_security_headers:
            if header not in response.headers:
                missing_flags.append(header)
        
        if exposed_info or missing_flags:
            result = ""
            if exposed_info:
                result += format_result(f"\n[+]..Sensitive Information Found: {', '.join(exposed_info)}", True) + "\n"
            if missing_flags:
                result += format_result(f"\n[+]..Missing Security Headers: {', '.join(missing_flags)}", True)
            return result
    except Exception as e:
        return format_result(f"\nError occurred: {e}", False)
    return format_result("\nNo Sensitive Information or Missing Security Headers Detected", False)

def check_xss_in_headers(url):
    payload = '"><script>alert("xss")</script>'
    headers = {'User-Agent': payload, 'Referer': payload}
    try:
        response = requests.get(url, headers=headers)
        if payload in response.text:
            return format_result("\n[+]..Possible XSS via Headers Found", True)
    except Exception as e:
        return format_result(f"Error occurred: {e}", False)
    return format_result("\n[-]..No XSS in Headers Detected", False)

def check_host_header_injection(url):
    headers = {'Host': 'malicious.com'}
    try:
        response = requests.get(url, headers=headers)
        if 'malicious.com' in response.text:
            return format_result("\n[+]..Possible Host Header Injection Found", True)
    except Exception as e:
        return format_result(f"\nError occurred: {e}", False)
    return format_result("\n[-]..No Host Header Injection Detected", False)

def check_csrf_vulnerability(url):
    headers = {'Referer': 'http://malicious.com', 'Origin': 'http://malicious.com'}
    try:
        response = requests.get(url, headers=headers)
        if 'malicious.com' in response.text:
            return format_result("\n[+]..Possible CSRF Vulnerability Found", True)
    except Exception as e:
        return format_result(f"\nError occurred: {e}", False)
    return format_result("\n[-]..No CSRF Vulnerability Detected", False)

def check_cache_poisoning(url):
    headers = {'Cache-Control': 'no-store, private'}
    try:
        response = requests.get(url, headers=headers)
        if 'Cache-Control' in response.headers and 'no-store' in response.headers['Cache-Control']:
            return format_result("\n[+]..Possible Cache Poisoning Risk Detected", True)
    except Exception as e:
        return format_result(f"\nError occurred: {e}", False)
    return format_result("\n[-]..No Cache Poisoning Risk Detected", False)

def check_hsts_misconfiguration(url):
    try:
        response = requests.get(url)
        if 'Strict-Transport-Security' not in response.headers:
            return format_result("\n[+]..HSTS Misconfiguration Detected (HSTS header missing)", True)
    except Exception as e:
        return format_result(f"\nError occurred: {e}", False)
    return format_result("\n[-]..HSTS Configured Properly", False)

def check_x_forwarded_for_spoofing(url):
    headers = {'X-Forwarded-For': 'malicious-ip'}
    try:
        response = requests.get(url, headers=headers)
        if 'malicious-ip' in response.text:
            return format_result("\n[+]..Possible X-Forwarded-For Spoofing Detected", True)
    except Exception as e:
        return format_result(f"\nError occurred: {e}", False)
    return format_result("\n[-]..No X-Forwarded-For Spoofing Detected", False)

def main():
    # Parse command-line arguments
    parser = argparse.ArgumentParser(description="HTTP Header Vulnerability Checker")
    parser.add_argument("url", help="The URL to test for vulnerabilities")
    args = parser.parse_args()

    # Get the URL from the arguments
    url = args.url
    
    print(check_http_response_splitting(url))
    print(check_header_injection(url))
    print(check_sensitive_info_exposure(url))
    print(check_xss_in_headers(url))
    print(check_host_header_injection(url))
    print(check_csrf_vulnerability(url))
    print(check_cache_poisoning(url))
    print(check_hsts_misconfiguration(url))
    print(check_x_forwarded_for_spoofing(url))

if __name__ == "__main__":
    main()
