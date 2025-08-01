#!/usr/bin/env python3

import re
import sys
import os
import argparse
import jsbeautifier
import webbrowser
import subprocess
import base64
import ssl
import xml.etree.ElementTree

try:
    from urllib.parse import urlparse
except ImportError:
    print("[-] Error importing urllib library")
    sys.exit(1)

try:
    import requests
except ImportError:
    print("[-] Error importing requests library")
    print("[-] Try: pip3 install requests")
    sys.exit(1)

# Regex used
regex_str = r"""

  (?:"|')
  (
    ((?:[a-zA-Z]{1,10}://|//)                        # Match protocol or protocol-less URLs
    [^"'/]{1,}\.[a-zA-Z]{2,}[^"']{0,}               # Match domain name and path
    )
    |
    ((?:/|\.\./|\./)[^"'><,;| *()(%%$^/\\\[\]]       # Match relative paths
    [^"'><,;|()]{1,})
    |
    ([a-zA-Z0-9_\-/]{1,}/                            # Match API endpoints
    [a-zA-Z0-9_\-/]{1,}\.(?:[a-zA-Z]{1,4}|action)
    (?:[\?|/][^"|']{0,}|))
    |
    ([a-zA-Z0-9_\-]{1,}\.(?:php|asp|aspx|jsp|json|action|html|js|txt|xml)
    (?:\?[^"|']{0,}|))
  )
  (?:"|')

"""

def parser_error(errmsg):
    print("Usage: python3 linkfinder.py [Options] use -h for help")
    print("Error: " + errmsg)
    sys.exit(1)

def parser_input(input):
    try:
        with open(input, 'r', encoding='utf-8') as f:
            return f.read()
    except FileNotFoundError:
        parser_error("File not found")
    except Exception as e:
        parser_error(f"Error reading file: {str(e)}")

def send_request(url):
    try:
        requests.packages.urllib3.disable_warnings()
        return requests.get(url, verify=False, timeout=10).text
    except Exception as e:
        print(f"\n\033[1;31m[!] Error connecting to {url}\033[1;m")
        print(f"[!] Error: {str(e)}")
        return None

def extract_endpoints(content):
    endpoints = []
    if not content:
        return endpoints

    content = jsbeautifier.beautify(content)
    matches = re.finditer(regex_str, content, re.VERBOSE)
    for match in matches:
        endpoint = match.group(1)
        if endpoint not in endpoints:
            endpoints.append(endpoint)

    return endpoints

def analyze_js(url_or_file):
    """Analyze JavaScript file for endpoints and return findings"""
    if os.path.exists(url_or_file):
        content = parser_input(url_or_file)
    else:
        content = send_request(url_or_file)

    if content:
        endpoints = extract_endpoints(content)
        return endpoints
    return []

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--input",
                        help="Input a: URL, file or folder. For folders a wildcard can be used (e.g. '/*.js')")
    parser.add_argument("-o", "--output",
                        help="Where to save the results (default: stdout)")
    args = parser.parse_args()

    if not args.input:
        parser.print_help()
        sys.exit(1)

    endpoints = analyze_js(args.input)

    if args.output:
        with open(args.output, 'w') as f:
            for endpoint in endpoints:
                f.write(f"{endpoint}\n")
    else:
        print("\n".join(endpoints))

if __name__ == "__main__":
    main()