import argparse
import requests
import re
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor
import os
import sys

def print_banner():
    banner = r"""
 _____  ____  ____   ___    ____  ____    ____      ____  ______ 
|     ||    ||    \ |   \  |    ||    \  /    |    |    ||      |
|   __| |  | |  _  ||    \  |  | |  _  ||   __|     |  | |      |
|  |_   |  | |  |  ||  D  | |  | |  |  ||  |  |     |  | |_|  |_|
|   _]  |  | |  |  ||     | |  | |  |  ||  |_ |     |  |   |  |  
|  |    |  | |  |  ||     | |  | |  |  ||     |     |  |   |  |  
|__|   |____||__|__||_____||____||__|__||___,_|    |____|  |__|  

                Passive Subdomain Hunter 🦅
                  with love, JAGADEESH
"""
    print("\033[1;32m" + banner + "\033[0m")

def crtsh_enum(domain):
    print("[+] Enumerating from crt.sh...")
    try:
        r = requests.get(f"https://crt.sh/?q=%25.{domain}&output=json", timeout=10)
        return list(set(re.findall(r'[\w.-]+\.%s' % re.escape(domain), r.text)))
    except:
        return []

def rapid_dns_enum(domain):
    print("[+] Enumerating from rapiddns.io...")
    try:
        r = requests.get(f"https://rapiddns.io/subdomain/{domain}?full=1", timeout=10)
        return list(set(re.findall(r'([\w.-]+\.%s)' % re.escape(domain), r.text)))
    except:
        return []

def wayback_enum(domain):
    print("[+] Enumerating from Wayback Machine...")
    try:
        r = requests.get(f"http://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=text&fl=original&collapse=urlkey", timeout=10)
        urls = set()
        for line in r.text.splitlines():
            hostname = urlparse(line).hostname
            if hostname and domain in hostname:
                urls.add(hostname)
        return list(urls)
    except:
        return []

def is_alive(subdomain):
    try:
        for proto in ["http://", "https://"]:
            try:
                r = requests.get(proto + subdomain, timeout=3)
                if r.status_code < 400:
                    return subdomain
            except:
                continue
    except:
        pass
    return None

def find_subdomains(domain, show_all=False, check_alive=False, save_file=False, output_file=None):
    print_banner()
    print(f"[+] Target Domain: {domain}\n")
    
    subs = set()
    subs.update(crtsh_enum(domain))
    subs.update(rapid_dns_enum(domain))
    subs.update(wayback_enum(domain))

    subs = sorted(set([s.strip() for s in subs if s.endswith(domain)]))
    print(f"\n[+] Total Passive Subdomains Found: {len(subs)}")

    if show_all:
        print("\n[+] Showing all found subdomains:\n")
        for s in subs:
            print("  -", s)

    alive = []
    if check_alive:
        print("\n[+] Checking for alive subdomains...\n")
        with ThreadPoolExecutor(max_workers=30) as executor:
            results = executor.map(is_alive, subs)
            for res in results:
                if res:
                    print(" [ALIVE] " + res)
                    alive.append(res)

    if save_file:
    	filename = output_file if output_file else "alive_subdomains.txt"
    	with open(filename, "w") as f:
    		f.write("\n".join(alive if check_alive else subs))
    		print(f"\n[+] Results saved to '{filename}'")


def main():
    parser = argparse.ArgumentParser(
        description="ReconRaptor 🦅 — Passive Subdomain Hunter\nwith love, JAGADEESH",
        formatter_class=argparse.RawTextHelpFormatter
    )

    parser.add_argument("-d", "--domain", help="Target domain to scan (e.g., example.com)")
    parser.add_argument("-a", "--all", help="Show all found subdomains", action="store_true")
    parser.add_argument("-l", "--alive-only", help="Only show/check alive subdomains", action="store_true")
    parser.add_argument("-o", "--output", help="Specify output file name (e.g., results.txt)")
    parser.add_argument("-s", "--save", help="Save results to file (alive_subdomains.txt)", action="store_true")
    #parser.add_argument("-h", "--help", action="help", help="Show this help message and exit")

    args = parser.parse_args()

    if not args.domain:
        print("\n[!] Error: Domain is required.\nUse -h for help.")
        sys.exit(1)

    find_subdomains(
    domain=args.domain,
    show_all=args.all,
    check_alive=args.alive_only,
    save_file=args.save,
    output_file=args.output
)

if __name__ == "__main__":
    main()
