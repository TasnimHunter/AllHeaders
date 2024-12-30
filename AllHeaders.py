import requests

def check_http_response_splitting(url):
    """
    Checks if the server is vulnerable to HTTP Response Splitting by injecting a newline in the headers.
    """
    headers = {'X-Injected-Header': 'foo\r\nAnother-Header: Bar'}
    response = requests.get(url, headers=headers)
    
    # Ensure the injected header is present
    if 'Another-Header' in response.headers:
        return "Possible HTTP Response Splitting Vulnerability Found"
    # Further check response content to see if it reflects injected headers in the body
    if "Another-Header" in response.text:
        return "Possible HTTP Response Splitting (Content Reflecting) Found"
    return "No HTTP Response Splitting Detected"

def check_header_injection(url):
    """
    Checks for HTTP Header Injection vulnerability.
    """
    payloads = ['\r\nX-Injected-Header: Malicious', '\nX-Injected-Header: Malicious']
    for payload in payloads:
        headers = {'X-Test-Header': payload}
        response = requests.get(url, headers=headers)
        
        # Checking for unexpected content in response body
        if "Malicious" in response.text:
            return "Possible HTTP Header Injection Vulnerability Found"
        if payload in response.headers.get('X-Test-Header', ''):
            return "Possible HTTP Header Injection Detected in Headers"
    return "No HTTP Header Injection Detected"

def check_sensitive_info_exposure(url):
    """
    Checks if the server is exposing sensitive information in the headers.
    """
    response = requests.get(url)
    sensitive_headers = ['X-Powered-By', 'Server', 'Set-Cookie', 'X-AspNet-Version']
    exposed_info = []
    
    for header in sensitive_headers:
        if header in response.headers:
            exposed_info.append(f"{header}: {response.headers[header]}")
    
    if exposed_info:
        return f"Sensitive Information Found: {', '.join(exposed_info)}"
    return "No Sensitive Information Exposure Detected"

def check_xss_in_headers(url):
    """
    Checks for potential XSS vulnerabilities via HTTP headers (e.g., User-Agent, Referer).
    """
    payload = '<script>alert("XSS")</script>'
    headers = {'User-Agent': payload, 'Referer': payload}
    response = requests.get(url, headers=headers)
    
    # Check if payload is reflected in the response body
    if payload in response.text:
        return "Possible XSS via Headers Found"
    # Check if any reflected payloads might have been sanitized or not executed
    if "<script>" in response.text:
        return "Potential XSS, but sanitization detected"
    return "No XSS in Headers Detected"

def check_host_header_injection(url):
    """
    Checks for Host Header Injection vulnerability.
    """
    headers = {'Host': 'malicious.com'}
    response = requests.get(url, headers=headers)
    
    # Check if the Host header is reflected anywhere in the response body
    if 'malicious.com' in response.text:
        return "Possible Host Header Injection Found"
    # Further check for SSRF or cache issues if Host header is mishandled
    if "localhost" in response.text or "127.0.0.1" in response.text:
        return "Possible Host Header Injection - SSRF Vulnerability Detected"
    return "No Host Header Injection Detected"

def check_csrf_vulnerability(url):
    """
    Checks for potential CSRF vulnerability by manipulating the Referer and Origin headers.
    """
    headers = {'Referer': 'http://malicious.com', 'Origin': 'http://malicious.com'}
    response = requests.get(url, headers=headers)
    
    # Check if the CSRF origin is accepted or reflected
    if 'malicious.com' in response.text:
        return "Possible CSRF Vulnerability Found"
    return "No CSRF Vulnerability Detected"

def check_cache_poisoning(url):
    """
    Checks for potential cache poisoning vulnerabilities via headers like Cache-Control.
    """
    headers = {'Cache-Control': 'no-store, private'}
    response = requests.get(url, headers=headers)
    
    # Check if cache-control headers are used to prevent caching
    if 'Cache-Control' in response.headers and 'no-store' in response.headers['Cache-Control']:
        return "Possible Cache Poisoning Risk Detected"
    return "No Cache Poisoning Risk Detected"

def check_hsts_misconfiguration(url):
    """
    Checks for potential HSTS misconfigurations by looking for the Strict-Transport-Security header.
    """
    response = requests.get(url)
    
    # Ensure the HSTS header is properly configured
    if 'Strict-Transport-Security' not in response.headers:
        return "HSTS Misconfiguration Detected (HSTS header missing)"
    return "HSTS Configured Properly"

def check_x_forwarded_for_spoofing(url):
    """
    Checks for the possibility of X-Forwarded-For header spoofing.
    """
    headers = {'X-Forwarded-For': 'malicious-ip'}
    response = requests.get(url, headers=headers)
    
    # Ensure the X-Forwarded-For header is sanitized or not reflected
    if 'malicious-ip' in response.text:
        return "Possible X-Forwarded-For Spoofing Detected"
    return "No X-Forwarded-For Spoofing Detected"

def main():
    url = input("Enter the URL to test for HTTP header vulnerabilities: ")
    print("\nChecking for vulnerabilities...\n")
    
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
