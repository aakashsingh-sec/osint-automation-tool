"""VirusTotal source: multi-engine reputation for IP/domain/URL/hash."""

import json
import logging
import requests

from osint.config import VT_API_KEY
from osint.throttle import vt_throttle

logger = logging.getLogger(__name__)


def check_virustotal(indicator: str, ioc_type: str) -> tuple:
    """Query VirusTotal for an IP, domain, URL, or hash and return (stats, display_lines)."""
    lines = ["\n[bold cyan][ VirusTotal ][/bold cyan]"]
    vt_throttle()
    headers = {"x-apikey": VT_API_KEY}

    if ioc_type == "ip":
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{indicator}"
    elif ioc_type == "domain":
        url = f"https://www.virustotal.com/api/v3/domains/{indicator}"
    elif ioc_type == "url":
        import base64
        url_id = base64.urlsafe_b64encode(indicator.encode()).decode().strip("=")
        url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
    elif ioc_type == "hash":
        url = f"https://www.virustotal.com/api/v3/files/{indicator}"
    else:
        lines.append("[red]  Unsupported IOC type for VirusTotal[/red]")
        return {}, lines

    try:
        logger.info("Querying VirusTotal for %s (%s)", indicator, ioc_type)
        r = requests.get(url, headers=headers, timeout=10)
        if r.status_code == 429:
            logger.warning("VirusTotal rate limit hit for %s", indicator)
            lines.append("[yellow]  VirusTotal: Rate limit reached — wait 60 seconds and retry[/yellow]")
            return {}, lines
        try:
            data = r.json()
        except json.JSONDecodeError:
            logger.error("VirusTotal returned non-JSON response (status %s)", r.status_code)
            lines.append(f"[red]  VirusTotal: API returned non-JSON response (status {r.status_code})[/red]")
            return {}, lines
        logger.debug("VirusTotal raw response for %s: %s", indicator, data)
        stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        harmless = stats.get("harmless", 0)
        undetected = stats.get("undetected", 0)

        color = "red" if malicious > 0 else "green"
        lines.append(f"  Malicious  : [{color}]{malicious}[/{color}]")
        lines.append(f"  Suspicious : {suspicious}")
        lines.append(f"  Harmless   : {harmless}")
        lines.append(f"  Undetected : {undetected}")
        return stats, lines
    except Exception as e:
        logger.error("VirusTotal error for %s: %s", indicator, e)
        lines.append(f"[red]  VirusTotal error: {type(e).__name__}[/red]")
        return {}, lines
