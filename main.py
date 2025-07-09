import argparse
from autoreconx import recon, scanners, utils, proxy
from urllib.parse import urljoin

def dir_brute(domain, wordlist, session, thread_count=50):
    import threading
    import queue

    print(f"[+] Starting directory brute force on {domain}")
    q = queue.Queue()
    found_dirs = []

    def worker():
        while True:
            path = q.get()
            if path is None:
                break
            url = urljoin(domain, path)
            try:
                r = session.get(url, timeout=5, allow_redirects=False)
                if r.status_code in [200, 301, 302]:
                    found_dirs.append(url)
                    print(f"[DIR] Found: {url} ({r.status_code})")
            except Exception as e:
                print(f"[-] Error requesting {url}: {e}")
            q.task_done()

    with open(wordlist, 'r') as f:
        for line in f:
            q.put(line.strip())

    threads = []
    for _ in range(thread_count):
        t = threading.Thread(target=worker)
        t.start()
        threads.append(t)

    q.join()

    for _ in range(thread_count):
        q.put(None)
    for t in threads:
        t.join()

    return found_dirs

def main():
    parser = argparse.ArgumentParser(description="AutoReconX - Full Automated Scan")
    parser.add_argument("--domain", required=True, help="Target domain")
    parser.add_argument("--threads", type=int, default=50, help="Number of threads")
    parser.add_argument("--wordlist", default="wordlists/common.txt", help="Wordlist for directory brute forcing")
    parser.add_argument("--use-tor", action="store_true", help="Use Tor proxy")
    parser.add_argument("--http-proxy", help="HTTP proxy URL")
    parser.add_argument("--https-proxy", help="HTTPS proxy URL")
    parser.add_argument("--shodan-api-key", help="Shodan API key")
    parser.add_argument("--virustotal-api-key", help="VirusTotal API key")
    parser.add_argument("--output", default="full_report.json", help="Output JSON report file")
    parser.add_argument("--html", action="store_true", help="Generate HTML report")

    args = parser.parse_args()

    domain = args.domain
    if not domain.startswith("http"):
        domain = "http://" + domain

    proxies = proxy.get_proxies(args.use_tor, args.http_proxy, args.https_proxy)
    session = utils.create_session(proxies=proxies)
    session = utils.requests_retry_session(session=session)

    results = {
        "subdomains": [],
        "open_ports": [],
        "directories": [],
        "vulnerabilities": {
            "xss": [],
            "sqli": [],
            "lfi": [],
            "rce": [],
            "ssrf": [],
            "open_redirect": []
        }
    }

    print("[*] Starting full AutoReconX scan...")

    # Subdomain enumeration
    print("[*] Running subdomain enumeration...")
    subs = recon.subdomain_enum(args.domain)
    results['subdomains'] = subs

    if args.shodan_api_key:
        shodan_hosts = recon.shodan_search(args.shodan_api_key, args.domain)
        results['subdomains'].extend(shodan_hosts)
        results['subdomains'] = list(set(results['subdomains']))

    # Port scanning
    import socket
    import concurrent.futures

    def scan_port(ip, port):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1)
                result = s.connect_ex((ip, port))
                if result == 0:
                    return port
        except:
            return None
        return None

    print("[*] Running port scan...")
    ports_to_scan = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080]
    open_ports = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = {executor.submit(scan_port, args.domain, port): port for port in ports_to_scan}
        for future in concurrent.futures.as_completed(futures):
            port = futures[future]
            if future.result():
                open_ports.append(port)
                print(f"[PORT] {args.domain}:{port} is open")

    results['open_ports'] = open_ports

    # Directory brute forcing
    print("[*] Running directory brute forcing...")
    dirs = dir_brute(domain, args.wordlist, session, args.threads)
    results['directories'] = dirs

    # Prepare URLs with parameters for vulnerability scanning
    param_urls = [domain + "/?id=1", domain + "/?search=test"]
    param_urls.extend([d + "/?id=1" for d in dirs])

    # Run all vulnerability scans
    print("[*] Running XSS scan...")
    results['vulnerabilities']['xss'] = scanners.xss_test(param_urls, session)

    print("[*] Running SQLi scan...")
    results['vulnerabilities']['sqli'] = scanners.sqli_test(param_urls, session)

    print("[*] Running LFI scan...")
    results['vulnerabilities']['lfi'] = scanners.lfi_test(param_urls, session)

    print("[*] Running RCE scan...")
    results['vulnerabilities']['rce'] = scanners.rce_test(param_urls, session)

    print("[*] Running SSRF scan...")
    results['vulnerabilities']['ssrf'] = scanners.ssrf_test(param_urls, session)

    print("[*] Running Open Redirect scan...")
    results['vulnerabilities']['open_redirect'] = scanners.open_redirect_test(param_urls, session)

    # Save JSON report
    with open(args.output, 'w') as f:
        import json
        json.dump(results, f, indent=4)
    print(f"[+] Full JSON report saved to {args.output}")

    # Generate HTML report if requested
    if args.html:
        html_content = "<html><head><title>AutoReconX Full Report</title></head><body>"
        html_content += f"<h1>AutoReconX Full Report for {args.domain}</h1>"

        html_content += "<h2>Subdomains</h2><ul>"
        for sub in results['subdomains']:
            html_content += f"<li>{sub}</li>"
        html_content += "</ul>"

        html_content += "<h2>Open Ports</h2><ul>"
        for port in results['open_ports']:
            html_content += f"<li>{port}</li>"
        html_content += "</ul>"

        html_content += "<h2>Directories Found</h2><ul>"
        for d in results['directories']:
            html_content += f"<li>{d}</li>"
        html_content += "</ul>"

        html_content += "<h2>Vulnerabilities</h2>"
        for vuln_type, vulns in results['vulnerabilities'].items():
            html_content += f"<h3>{vuln_type.upper()}</h3><ul>"
            if vulns:
                for v in vulns:
                    html_content += "<li>"
                    for k, val in v.items():
                        html_content += f"{k}: {val} "
                    html_content += "</li>"
            else:
                html_content += "<li>None found</li>"
            html_content += "</ul>"

        html_content += "</body></html>"

        html_file = args.output.replace(".json", ".html")
        with open(html_file, 'w') as f:
            f.write(html_content)
        print(f"[+] Full HTML report saved to {html_file}")

if __name__ == "__main__":
    main()
