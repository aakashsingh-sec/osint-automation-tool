"""Shodan InternetDB source: exposed ports, hostnames, and known CVEs (no API key required)."""

import json
import logging
import requests

logger = logging.getLogger(__name__)


def check_shodan(ip: str) -> tuple:
    """Query Shodan InternetDB for an IP address and return (data, display_lines)."""
    lines = ["\n[bold cyan][ InternetDB (Shodan) ][/bold cyan]"]
    try:
        logger.info("Querying InternetDB for %s", ip)
        r = requests.get(f"https://internetdb.shodan.io/{ip}", timeout=15)
        if r.status_code == 404:
            lines.append("  No InternetDB data for this IP.")
            return {}, lines
        if r.status_code != 200:
            logger.warning("InternetDB returned %s for %s", r.status_code, ip)
            lines.append(f"  [yellow]InternetDB returned {r.status_code}: {r.text[:200]}[/yellow]")
            return {}, lines
        try:
            data = r.json()
        except json.JSONDecodeError:
            logger.error("InternetDB returned non-JSON response (status %s)", r.status_code)
            lines.append(f"[red]  InternetDB: API returned non-JSON response (status {r.status_code})[/red]")
            return {}, lines
        logger.debug("InternetDB raw response for %s: %s", ip, data)
        ports = data.get("ports", [])
        hostnames = data.get("hostnames", [])
        vulns = data.get("vulns", [])

        lines.append(f"  Open Ports   : {', '.join(map(str, ports)) if ports else 'None'}")
        lines.append(f"  Hostnames    : {', '.join(hostnames) if hostnames else 'None'}")
        if vulns:
            lines.append(f"  [red]CVEs Found   : {', '.join(vulns[:5])}[/red]")
        else:
            lines.append("  CVEs Found   : None")
        return data, lines
    except Exception as e:
        logger.error("InternetDB error for %s: %s", ip, e)
        lines.append(f"[red]  InternetDB error: {type(e).__name__}[/red]")
        return {}, lines
