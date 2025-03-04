import requests

class PenetrationTester:
    def __init__(self):
        self.test_results = ""

    def test_website(self, url):
        print(f"\nTesting website: {url}")
        # Perform SQL Injection and XSS tests, and store the results
        self.test_results = self._check_sql_injection(url) + "\n" + self._check_xss(url)
        print(self.test_results)

    def _check_sql_injection(self, url):
        # Modify the URL to test for SQL Injection by adding a single quote
        test_url = f"{url}?id=1'"
        # Send a GET request to the modified URL
        response = requests.get(test_url)
        # Check if the response contains the word error
        if "error" in response.text.lower():
            return "Potential SQL Injection vulnerability found." 
        else:
            return "No SQL Injection vulnerability detected." 

    def _check_xss(self, url):
        # Modify the URL to test for XSS by adding a script tag
        test_url = f"{url}?search=<script>alert('XSS')</script>"
        # Send a GET request to the modified URL
        response = requests.get(test_url)
        # Check if the response contains the script tag
        if "<script>alert('XSS')</script>" in response.text:
            return "Potential XSS vulnerability found." 
        else:
            return "No XSS vulnerability detected." 