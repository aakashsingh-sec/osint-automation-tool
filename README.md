# OSINT Automation Tool

A command-line threat intelligence aggregator that investigates IPs, domains, and URLs across six independent OSINT sources and produces a weighted risk verdict. Built to automate the manual indicator-triage workflow common in SOC operations.

## What it does

Given an IP address, domain, or URL, the tool queries multiple threat intelligence sources in one command and synthesizes the results into a single weighted verdict (CLEAN / SUSPICIOUS / MALICIOUS) with supporting reasons.

## Sources

| Source | Provides |
|--------|----------|
| VirusTotal | Multi-engine reputation (90+ AV engines) |
| AbuseIPDB | IP abuse confidence score and report history |
| Shodan InternetDB | Exposed ports, services, and known CVEs |
| URLhaus (abuse.ch) | Known malware-distribution URLs |
| AlienVault OTX | Threat intelligence pulses and campaign tags |
| RDAP | Domain registration data and age |

## Why multiple sources

Each source detects a different threat type. A Tor exit node, for example, shows clean on URLhaus (it hosts no malware) but flags 100% on AbuseIPDB (it's an attack source). Aggregating sources produces a complete risk picture that no single tool provides.

## Verdict scoring

Results are weighted by source reliability and combined into a 0–100 risk score:
- 0–20: CLEAN
- 21–50: SUSPICIOUS
- 51–100: MALICIOUS

## Setup

```bash
git clone https://github.com/asingh140696/osint-automation-tool.git
cd osint-automation-tool
pip install -r requirements.txt
```

Copy `.env.example` to `.env` and add your API keys:

```bash
cp .env.example .env
```

## API keys required

Free-tier keys from: VirusTotal, AbuseIPDB, AlienVault OTX, URLhaus (auth.abuse.ch). Shodan InternetDB and RDAP require no key.

## Usage

```bash
python osint.py 8.8.8.8
python osint.py google.com
python osint.py https://example.com
```

## File mode (batch)

```bash
python osint.py --file indicators.txt
```

One indicator per line. Results saved to a single combined JSON report.

## Example output

[Add screenshot of a CLEAN verdict and a MALICIOUS verdict here]

## Tech stack

Python 3.11+, requests, rich, python-dotenv, OTXv2

## Disclaimer

Built for defensive security research and SOC triage. Submitting indicators to public scanning services may alert threat actors that their infrastructure is under investigation.
