"""Centralized environment / API-key configuration for the osint package."""

import os
from dotenv import load_dotenv

load_dotenv()

VT_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
ABUSE_API_KEY = os.getenv("ABUSEIPDB_API_KEY")
SHODAN_API_KEY = os.getenv("SHODAN_API_KEY")
URLSCAN_API_KEY = os.getenv("URLSCAN_API_KEY")
OTX_API_KEY = os.getenv("OTX_API_KEY")
URLHAUS_API_KEY = os.getenv("URLHAUS_API_KEY")
