# OSINT Automation Tool

A threat intelligence aggregator — CLI and Streamlit dashboard — that investigates IPs, domains, URLs, and file hashes across six independent OSINT sources and produces a single weighted risk verdict. Built to automate the manual indicator-triage workflow common in SOC operations.

## What it does

Given an IP address, domain, URL, or file hash (MD5/SHA1/SHA256), the tool queries multiple threat intelligence sources concurrently and synthesizes the results into a single weighted verdict (CLEAN / SUSPICIOUS / MALICIOUS) with supporting reasons. All input is validated before use — malformed or unsafe indicators are rejected outright.

## Sources

| Source | Provides | Supports |
|--------|----------|----------|
| VirusTotal | Multi-engine reputation (90+ AV engines) | IP, domain, URL, hash |
| AbuseIPDB | IP abuse confidence score and report history | IP |
| Shodan InternetDB | Exposed ports, services, and known CVEs | IP |
| URLhaus (abuse.ch) | Known malware-distribution URLs / payload sightings | IP, domain, URL, hash |
| AlienVault OTX | Threat intelligence pulses and campaign tags | IP, domain, URL, hash |
| RDAP | Domain registration data and age | domain |

## Why multiple sources

Each source detects a different threat type. A Tor exit node, for example, shows clean on URLhaus (it hosts no malware) but flags 100% on AbuseIPDB (it's an attack source). Aggregating sources produces a complete risk picture that no single tool provides.

## Verdict scoring

Results are weighted by source reliability and combined into a 0–100 risk score:
- 0–20: CLEAN
- 21–50: SUSPICIOUS
- 51–100: MALICIOUS

## Project structure

```
osint.py              # thin CLI entrypoint (argparse, single/batch/file modes)
osint/
  config.py            # environment / API-key loading
  validation.py        # IOC validation & classification (IP/domain/URL/hash)
  throttle.py           # VirusTotal rate-limit throttling
  scoring.py            # weighted verdict calculation
  io_utils.py            # report persistence
  core.py                 # concurrent source fan-out (investigate())
  sources/                # one module per OSINT source
dashboard.py             # Streamlit dashboard (lookup, bulk, compare, timeline)
```

## Setup

```bash
git clone https://github.com/aakashsingh-sec/osint-automation-tool.git
cd osint-automation-tool
pip install