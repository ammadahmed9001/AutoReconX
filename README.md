# AutoReconX

AutoReconX is an advanced all-in-one bug bounty and penetration testing automation tool. It integrates subdomain enumeration, port scanning, directory brute forcing, multiple vulnerability scanners (XSS, SQLi, LFI, RCE, SSRF, Open Redirect), authentication brute forcing, session handling, proxy/Tor support, and API integrations (Shodan, VirusTotal).

## Features

- Subdomain enumeration via crt.sh and Shodan API
- Port scanning with multithreading
- Directory brute forcing with customizable wordlists
- Vulnerability scanning for XSS, SQLi, LFI, RCE, SSRF, Open Redirect
- Authentication brute forcing (Basic Auth)
- Session and cookie support for authenticated scans
- Proxy and Tor support
- Rate limiting and retry logic for stable scanning
- VirusTotal domain reputation checks
- JSON and HTML report generation
- Logging and error handling
- Modular and extensible design

## Installation

```bash
git clone https://github.com/ammadahmed9001/AutoReconX.git
cd AutoReconX
pip install -r requirements.txt
