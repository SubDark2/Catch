#!/usr/bin/env python3

import requests
import shodan
import argparse
import sys
from bs4 import BeautifulSoup, Comment
from urllib.parse import urljoin
from colorama import init, Fore

# Initialize colorama for colored output
init()

# ASCII Art Logo
LOGO = '''
    ███████╗ █████╗ ██╗   ██╗███████╗██████╗ ██╗     ██╗███╗   ██╗██╗   ██╗██╗  ██╗
    ██╔════╝██╔══██╗╚██╗ ██╔╝██╔════╝██╔══██╗██║     ██║████╗  ██║██║   ██║╚██╗██╔╝
    ███████╗███████║ ╚████╔╝ █████╗  ██████╔╝██║     ██║██╔██╗ ██║██║   ██║ ╚███╔╝ 
    ╚════██║██╔══██║  ╚██╔╝  ██╔══╝  ██╔══██╗██║     ██║██║╚██╗██║██║   ██║ ██╔██╗ 
    ███████║██║  ██║   ██║   ███████╗██║  ██║███████╗██║██║ ╚████║╚██████╔╝██╔╝ ██╗
    ╚══════╝╚═╝  ╚═╝   ╚═╝   ╚══════╝╚═╝  ╚═╝╚══════╝╚═╝╚═╝  ╚═══╝ ╚═════╝ ╚═╝  ╚═╝
                                                        By: SayerLinux
                                                        Email: SayerLinux1@gmail.com
'''

class TayseerScanner:
    def __init__(self, target_url, shodan_api_key=None):
        self.target_url = target_url.rstrip('/')
        self.shodan_api = shodan.Shodan(shodan_api_key) if shodan_api_key else None
        self.visited_urls = set()
        self.hidden_pages = set()
        self.external_links = set()
        self.sensitive_files = set()
        self.api_endpoints = set()
        self.session = requests.Session()
        self.session.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        
        # Common API endpoint patterns
        self.api_patterns = [
            '/api/', '/v1/', '/v2/', '/v3/', '/rest/', '/graphql',
            '/swagger', '/docs/api', '/api-docs', '/api/v1/',
            '/wp-json/', '/api/swagger', '/openapi', '/redoc'
        ]

    def crawl_site(self):
        print(f"{Fore.GREEN}[+] Starting crawl on {self.target_url}{Fore.RESET}")
        self._crawl_recursive(self.target_url)
        
        # Print summary after crawling
        self._print_summary()

    def _crawl_recursive(self, url):
        if url in self.visited_urls:
            return

        self.visited_urls.add(url)
        try:
            response = self.session.get(url)
            if response.status_code == 200:
                soup = BeautifulSoup(response.text, 'html.parser')
                self._analyze_page(url, soup, response)
                self._find_links(url, soup)
            elif response.status_code == 403 or response.status_code == 401:
                self.hidden_pages.add(url)
                print(f"{Fore.YELLOW}[!] Protected page found: {url}{Fore.RESET}")

        except Exception as e:
            print(f"{Fore.RED}[-] Error crawling {url}: {str(e)}{Fore.RESET}")

    def _find_links(self, base_url, soup):
        sensitive_patterns = [
            'admin', 'login', 'wp-admin', 'dashboard', 'config',
            'backup', 'db', 'database', 'dev', 'test',
            'phpinfo', 'info.php', '.git', '.env', 'robots.txt',
            'sitemap.xml', '.htaccess', 'console'
        ]

        for link in soup.find_all(['a', 'link', 'script', 'img']):
            href = link.get('href') or link.get('src')
            if href:
                full_url = urljoin(base_url, href)
                if self.target_url in full_url:
                    if full_url not in self.visited_urls:
                        self._crawl_recursive(full_url)
                    
                    # Check for sensitive files and API endpoints
                    path = full_url.split(self.target_url)[1].lower()
                    
                    # Check sensitive files
                    for pattern in sensitive_patterns:
                        if pattern in path:
                            self.sensitive_files.add(full_url)
                    
                    # Check API endpoints
                    for pattern in self.api_patterns:
                        if pattern.lower() in path:
                            self.api_endpoints.add(full_url)
                else:
                    self.external_links.add(full_url)

    def _analyze_page(self, url, soup, response):
        # Analyze comments
        comments = soup.find_all(string=lambda text: isinstance(text, Comment))
        if comments:
            print(f"\n{Fore.BLUE}[+] Found {len(comments)} HTML comments in {url}:{Fore.RESET}")
            for comment in comments:
                comment_text = str(comment).strip()
                if comment_text:
                    print(f"  {Fore.CYAN}└─ {comment_text[:100]}{'...' if len(comment_text) > 100 else ''}{Fore.RESET}")

        # Check for hidden inputs
        hidden_inputs = soup.find_all('input', type='hidden')
        if hidden_inputs:
            print(f"\n{Fore.BLUE}[+] Found {len(hidden_inputs)} hidden inputs in {url}:{Fore.RESET}")
            for hidden_input in hidden_inputs:
                name = hidden_input.get('name', 'unnamed')
                value = hidden_input.get('value', '')
                print(f"  {Fore.CYAN}└─ {name}: {value[:50]}{'...' if len(value) > 50 else ''}{Fore.RESET}")

        # Check for JavaScript files
        scripts = soup.find_all('script', src=True)
        if scripts:
            print(f"\n{Fore.BLUE}[+] Found {len(scripts)} JavaScript files in {url}:{Fore.RESET}")
            for script in scripts:
                src = script.get('src')
                print(f"  {Fore.CYAN}└─ {src}{Fore.RESET}")

    def _print_summary(self):
        print(f"\n{Fore.GREEN}{'='*50}{Fore.RESET}")
        print(f"{Fore.GREEN}Scan Summary for {self.target_url}{Fore.RESET}")
        print(f"{Fore.GREEN}{'='*50}{Fore.RESET}")
        
        print(f"\n{Fore.CYAN}[+] Total Pages Scanned: {len(self.visited_urls)}{Fore.RESET}")
        
        if self.hidden_pages:
            print(f"\n{Fore.YELLOW}[!] Protected Pages ({len(self.hidden_pages)}):{Fore.RESET}")
            for page in sorted(self.hidden_pages):
                print(f"  {Fore.YELLOW}└─ {page}{Fore.RESET}")

        if self.api_endpoints:
            print(f"\n{Fore.MAGENTA}[+] API Endpoints ({len(self.api_endpoints)}):{Fore.RESET}")
            for endpoint in sorted(self.api_endpoints):
                print(f"  {Fore.MAGENTA}└─ {endpoint}{Fore.RESET}")

        if self.sensitive_files:
            print(f"\n{Fore.RED}[!] Potentially Sensitive URLs ({len(self.sensitive_files)}):{Fore.RESET}")
            for file in sorted(self.sensitive_files):
                print(f"  {Fore.RED}└─ {file}{Fore.RESET}")

        if self.external_links:
            print(f"\n{Fore.BLUE}[+] External Links ({len(self.external_links)}):{Fore.RESET}")
            for link in sorted(self.external_links):
                print(f"  {Fore.BLUE}└─ {link}{Fore.RESET}")

    def shodan_scan(self):
        if not self.shodan_api:
            print(f"\n{Fore.RED}[-] Shodan API key not provided{Fore.RESET}")
            return

        try:
            import socket
            ip = socket.gethostbyname(self.target_url.replace('https://', '').replace('http://', '').split('/')[0])
            results = self.shodan_api.host(ip)
            print(f"{Fore.GREEN}[+] Shodan Results for {self.target_url}:{Fore.RESET}")
            print(f"IP: {ip}")
            print(f"OS: {results.get('os', 'Unknown')}")
            print(f"Organization: {results.get('org', 'Unknown')}")
            print(f"Open Ports: {', '.join(map(str, results.get('ports', [])))}")
            print(f"Location: {results.get('city', 'Unknown')}, {results.get('country_name', 'Unknown')}")
            print(f"Last Update: {results.get('last_update', 'Unknown')}")
            
            # Display vulnerabilities if any
            vulns = results.get('vulns', [])
            if vulns:
                print(f"\n{Fore.RED}[!] Found Vulnerabilities:{Fore.RESET}")
                for vuln in vulns:
                    print(f"- {vuln}") 

        except Exception as e:
            print(f"{Fore.RED}[-] Shodan scan error: {str(e)}{Fore.RESET}")

def main():
    print(Fore.CYAN + LOGO + Fore.RESET)
    parser = argparse.ArgumentParser(description='Tayseer Website Scanner')
    parser.add_argument('-u', '--url', required=True, help='Target URL')
    parser.add_argument('-k', '--shodan-key', default='IVYPa91tXBuOvKLJiRnlivqMQYEeSnLD', help='Shodan API Key')
    args = parser.parse_args()

    scanner = TayseerScanner(args.url, args.shodan_key)
    scanner.crawl_site()
    scanner.shodan_scan()

if __name__ == '__main__':
    main()