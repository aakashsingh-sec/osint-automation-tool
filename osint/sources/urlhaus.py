"""URLhaus (abuse.ch) source: known malware-distribution URLs and payload sightings."""

import os
import json
import logging
import requests

from osint.config import URLHAUS_API_KEY
from osint.validation import hash_subtype

logger = logging.getLogger(__name__)


def check_urlhaus(indicator: str, ioc_type: str = "domain") -> tuple:
    """Query URLhaus for a host/domain/URL or a file hash payload and return (data, display_lines)."""
    lines = ["\n[bold cyan][ URLhaus ][/bold cyan]"]
    try:
        if ioc_type == "hash":
            subtype = hash_subtype(indicator)
            if subtype == "sha256":
                field = "sha256_hash"
            elif subtype == "md5":
                field = "md5_hash"
            else:
                lines.append("  URLhaus: only MD5 and SHA256 are supported for payload lookups")
                return {}, lines
            logger.info("Querying URLhaus payload endpoint for %s (%s)", indicator, field)
            r = requests.post(
                "https://urlhaus-api.abuse.ch/v1/payload/",
                headers={"Auth-Key": URLHAUS_API_KEY},
                data={field: indicator},
                timeout=15,
            )
        else:
            logger.info("Querying URLhaus host endpoint for %s", indicator)
            r = requests.post(
                "https://urlhaus-api.abuse.ch/v1/host/",
                headers={"Auth-Key": URLHAUS_API_KEY},
                data={"host": indicator},
                timeout=15,
            )
        try:
            data = r.json()
        except json.JSONDecodeError:
            logger.error("URLhaus returned non-JSON response (status %s)", r.status_code)
            lines.append(f"[red]  URLhaus: API returned non-JSON response (status {r.status_code})[/red]")
            return {}, lines
        logger.debug("URLhaus raw response for %s: %s", indicator, data)
        if "query_status" not in data:
            lines.append("  URLhaus requires a free Auth-Key — register at auth.abuse.ch")
            return {}, lines
        query_status = data.get("query_status")

        if query_status == "no_results":
            lines.append("  No known malicious URLs — clean.")
            return data, lines

        if query_status != "ok":
            lines.append(f"  query_status: {query_status}")
            return data, lines

        urls = data.get("urls", [])
        url_count = int(data.get("url_count", len(urls)))

        color = "red" if url_count > 0 else "green"
        label = "Malicious payload sightings" if ioc_type == "hash" else "Malicious URLs"
        lines.append(f"  {label} : [{color}]{url_count}[/{color}]")
        for entry in urls[:3]:
            lines.append(f"  URL            : {entry.get('url', 'N/A')}")
            lines.append(f"    Threat       : {entry.get('threat', 'N/A')}")
            lines.append(f"    Status       : {entry.get('url_status', 'N/A')}")
        return data, lines
    except Exception as e:
        logger.error("URLhaus error for %s: %s", indicator, e)
        lines.append(f"[red]  URLhaus error: {type(e).__name__}[/red]")
        return {}, lines
