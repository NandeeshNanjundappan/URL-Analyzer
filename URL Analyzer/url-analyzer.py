import socket
import requests
from bs4 import BeautifulSoup

def validate_url(url):
    """Ensure the URL has a valid scheme."""
    if not url.startswith(("http://", "https://")):
        return "https://" + url
    return url


def get_subdomains(domain):
    """
    Discover subdomains using crt.sh (Certificate Transparency Logs).
    """
    print(f"[*] Discovering subdomains for: {domain}")
    try:
        response = requests.get(f"https://crt.sh/?q=%.{domain}&output=json", timeout=10)
        if response.status_code == 200:
            certs = response.json()
            subdomains = list({cert['name_value'] for cert in certs})
            return subdomains if subdomains else ["No subdomains found."]
        else:
            return ["Failed to fetch subdomains."]
    except Exception as e:
        return [f"Error: {str(e)}"]


def get_tech_stack(url):
    """
    Detect the tech stack by analyzing meta tags, headers, and page content.
    """
    print(f"[*] Detecting tech stack for: {url}")
    try:
        response = requests.get(url, timeout=10)
        soup = BeautifulSoup(response.text, 'html.parser')

        # Check meta generator tag
        generator = soup.find("meta", attrs={"name": "generator"})
        if generator:
            return [f"Generator: {generator['content']}"]

        # Check headers
        headers = response.headers
        technologies = []
        if "X-Powered-By" in headers:
            technologies.append(f"X-Powered-By: {headers['X-Powered-By']}")
        if "Server" in headers:
            technologies.append(f"Server: {headers['Server']}")

        return technologies if technologies else ["No technologies detected."]
    except Exception as e:
        return [f"Error: {str(e)}"]


def scan_ports(domain):
    """
    Scan common ports for a given domain.
    """
    print(f"[*] Scanning open ports for: {domain}")
    ports_to_scan = [80, 443, 22, 21, 3306, 8080, 25, 110, 143]
    open_ports = []
    try:
        for port in ports_to_scan:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1)
                result = s.connect_ex((domain, port))
                if result == 0:
                    open_ports.append(port)
    except Exception as e:
        return [f"Error: {str(e)}"]
    return open_ports if open_ports else ["No open ports detected."]


def main():
    print("=== URL Analysis and Enumeration Tool ===")
    url = input("Enter URL (e.g., https://example.com): ").strip()
    url = validate_url(url)
    domain = url.replace("http://", "").replace("https://", "").split('/')[0]
    
    # Subdomain Discovery
    subdomains = get_subdomains(domain)
    print("\n[+] Subdomains Discovered:")
    for subdomain in subdomains:
        print(f"  - {subdomain}")

    # Tech Stack Detection
    tech_stack = get_tech_stack(url)
    print("\n[+] Tech Stack Identified:")
    for tech in tech_stack:
        print(f"  - {tech}")

    # Open Port Scanning
    open_ports = scan_ports(domain)
    print("\n[+] Open Ports Detected:")
    for port in open_ports:
        print(f"  - {port}")


if __name__ == "__main__":
    main()
