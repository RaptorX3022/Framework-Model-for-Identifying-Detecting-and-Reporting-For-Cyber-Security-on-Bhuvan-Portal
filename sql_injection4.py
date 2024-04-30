import requests
from bs4 import BeautifulSoup
import re
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse
from concurrent.futures import ThreadPoolExecutor


class WebVulnerabilityScanner:
    def __init__(self, target_url):
        self.target_url = target_url
        self.session = requests.Session()
        self.visited_links = set()
        self.vulnerabilities = []
        self.xss_payloads = self.load_xss_payloads()
        self.sql_injection_payloads = self.load_sql_injection_payloads()

    def load_xss_payloads(self):
        with open('xss-payload-list.txt', 'r', encoding='utf-8') as file:
            return [line.strip() for line in file.readlines()]

    def load_sql_injection_payloads(self):
        # Fetch SQL injection payloads from the provided link
        response = requests.get(
            "https://raw.githubusercontent.com/payloadbox/sql-injection-payload-list/master/README.md")
        sql_payloads = response.text.split("\n")
        # Filter out empty lines and comments
        sql_payloads = [payload.strip() for payload in sql_payloads if payload.strip() and not payload.startswith("#")]
        return sql_payloads

    def crawl(self, url):
        if url in self.visited_links:
            return
        print("[+] Crawling:", url)
        try:
            # Filter out non-HTTP/HTTPS URLs
            if url.startswith('http://') or url.startswith('https://'):
                response = self.session.get(url)
                if response.status_code == 200:
                    self.visited_links.add(url)
                    links = self.extract_links(response.text, url)
                    with ThreadPoolExecutor(max_workers=10) as executor:
                        executor.map(self.crawl, links)
                        executor.map(self.scan_page, links)
        except Exception as e:
            print("[-] Error crawling {}: {}".format(url, e))

    def extract_links(self, html_content, base_url):
        links = []
        soup = BeautifulSoup(html_content, 'html.parser')
        for link in soup.find_all('a', href=True):
            href = link.get('href')
            if not href:
                continue
            absolute_url = urljoin(base_url, href)
            links.append(absolute_url)
        return links

    def scan_page(self, url):
        print("[+] Scanning:", url)
        try:
            response = self.session.get(url)
            if response.status_code == 200:
                self.detect_xss_vulnerability(url, response)
                self.detect_sql_injection_vulnerability(url, response)

        except Exception as e:
            print("[-] Error scanning {}: {}".format(url, e))

    def detect_xss_vulnerability(self, url, response):
        forms = self.extract_forms(response.text)
        for form in forms:
            form_data = self.extract_form_data(form)
            for field_name, field_value in form_data.items():
                tampered_data = self.modify_field_value(field_value)
                tampered_url = self.build_tampered_url(url, form_data, {field_name: tampered_data})
                tampered_response = self.session.get(tampered_url)
                if self.is_xss_detected(tampered_response):
                    self.vulnerabilities.append({
                        "vulnerability": "XSS",
                        "url": tampered_url,
                        "form_data": form_data,
                        "payload": tampered_data
                    })

    def detect_sql_injection_vulnerability(self, url, response):
        for payload in self.sql_injection_payloads:
            # Construct the tampered URL by appending the payload to the base URL
            tampered_url = url + payload
            tampered_response = self.session.get(tampered_url)
            if self.is_sql_injection_detected(tampered_response):
                self.vulnerabilities.append({
                    "vulnerability": "SQL Injection",
                    "url": tampered_url,
                    "payload": payload
                })

    def is_sql_injection_detected(self, response):
        # Common SQL error messages indicating a potential SQL injection vulnerability
        sql_error_messages = [
            "SQL syntax",
            "MySQL server",
            "Syntax error",
            "Unclosed quotation mark",
            "You have an error in your SQL syntax",
            "Database error",
            "Microsoft SQL Server",
            "ODBC SQL",
            "PostgreSQL query failed",
            "Warning: mysql_fetch_array()",
            "Warning: mysql_fetch_assoc()",
            "Fatal error",
            "MySqlException",
            "PL/SQL",
            "PG::SyntaxError:",
            "ORA-00933:",
            "SQLiteException",
            "JDBCException",
            "SQLException"
        ]

        # Check if any of the common SQL error messages are present in the response
        for error_message in sql_error_messages:
            if error_message.lower() in response.text.lower():
                return True

        return False

    def extract_forms(self, html_content):
        soup = BeautifulSoup(html_content, 'html.parser')
        return soup.find_all('form')

    def extract_form_data(self, form):
        form_data = {}
        for input_field in form.find_all('input'):
            if input_field.get('name'):
                form_data[input_field['name']] = input_field.get('value', '')
        return form_data

    def modify_field_value(self, value):
        # Use payloads from the loaded list
        return self.xss_payloads.pop(0) if self.xss_payloads else '"><script>alert("XSS")</script>'

    def build_tampered_url(self, url, form_data, params):
        parsed_url = urlparse(url)
        query_params = parse_qs(parsed_url.query)
        query_params.update(params)
        modified_query = urlencode(query_params, doseq=True)
        tampered_url = urlunparse(parsed_url._replace(query=modified_query))
        return tampered_url

    def is_xss_detected(self, response):
        return re.search(r'<script>alert\("XSS"\)</script>', response.text, re.IGNORECASE)

    def generate_report(self):
        if self.vulnerabilities:
            print("[+] Vulnerabilities Found:")
            for vuln in self.vulnerabilities:
                print("    - Type:", vuln["vulnerability"])
                print("      URL:", vuln["url"])
                print("      Form Data:", vuln["form_data"])
                print("      Payload:", vuln["payload"])
                print()
        else:
            print("[+] No vulnerabilities found.")

    def scan_site(self):
        self.crawl(self.target_url)
        print("[+] Starting vulnerability scan...")
        self.generate_report()

if __name__ == "__main__":
    target_url = input("Enter target URL: ")
    scanner = WebVulnerabilityScanner(target_url)
    scanner.scan_site()
