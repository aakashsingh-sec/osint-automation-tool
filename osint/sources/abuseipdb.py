"""AbuseIPDB source: IP abuse confidence score and report history."""

import json
import logging
import requests

from osint.config import ABUSE_API_KEY

logger = logging.getLogger(__name__)


def check_abuseipdb(ip: str) -> tuple:
    """Query AbuseIPDB for an IP address and return (data, display_lines)."""
    lines = ["\n[bold cyan][ AbuseIPDB ][/bold cyan]"]
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Key": ABUSE_API_KEY, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": 90, "verbose": True}

    try:
        logger.info("Querying AbuseIPDB for %s", ip)
        r = requests.get(url, headers=headers, params=params, timeout=10)
        if r.status_code == 429:
            logger.warning("AbuseIPDB rate limit hit for %s", ip)
            lines.append("[yellow]  AbuseIPDB: Rate limit reached — wait 60 seconds and retry[/yellow]")
            return {}, lines
        try:
            data = r.json().get("data", {})
        except json.JSONDecodeError:
            logger.error("AbuseIPDB returned non-JSON response (status %s)", r.status_code)
            lines.append(f"[red]  AbuseIPDB: API returned non-JSON response (status {r.status_code})[/red]")
            return {}, lines
        logger.debug("AbuseIPDB raw response for %s: %s", ip, data)
        score = data.get("abuseConfidenceScore", 0)
        country = data.get("countryCode", "N/A")
        isp = data.get("isp", "N/A")
        total_reports = data.get("totalReports", 0)
        domain = data.get("domain", "N/A")

        color = "red" if score > 50 else "yellow" if score > 10 else "green"
        lines.append(f"  Abuse Score   : [{color}]{score}%[/{color}]")
        lines.append(f"  Total Reports : {total_reports}")
        lines.append(f"  Country       : {country}")
        lines.append(f"  ISP           : {isp}")
        lines.append(f"  Domain        : {domain}")
        return data, lines
    except Exception as e:
        logger.error("AbuseIPDB error for %s: %s", ip, e)
        lines.append(f"[red]  AbuseIPDB error: {type(e).__name__}[/red]")
        return {}, lines
