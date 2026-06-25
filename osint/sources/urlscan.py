"""URLScan.io source: submits a URL and polls for results. Dormant — not wired into investigate()."""

import json
import time
import logging
import requests

from osint.config import URLSCAN_API_KEY

logger = logging.getLogger(__name__)


def check_urlscan(indicator: str) -> tuple:
    """Submit a URL to URLScan.io and poll for results."""
    lines = ["\n[bold cyan][ URLScan.io ][/bold cyan]"]
    headers = {"API-Key": URLSCAN_API_KEY, "Content-Type": "application/json"}

    try:
        r = requests.post(
            "https://urlscan.io/api/v1/scan/",
            headers=headers,
            json={"url": indicator, "visibility": "public"},
            timeout=10,
        )
        try:
            submit_data = r.json()
        except json.JSONDecodeError:
            lines.append(f"[red]  URLScan: API returned non-JSON response (status {r.status_code})[/red]")
            return {}, lines
        uuid = submit_data.get("uuid")
        result_url = submit_data.get("result", "N/A")

        lines.append(f"  Scan submitted (uuid: {uuid}). Polling for results...")

        result_data = None
        for attempt in range(12):
            time.sleep(10)
            elapsed = (attempt + 1) * 10
            poll = requests.get(f"https://urlscan.io/api/v1/result/{uuid}/", timeout=10)
            if poll.status_code == 200:
                try:
                    result_data = poll.json()
                except json.JSONDecodeError:
                    lines.append(f"[red]  URLScan: non-JSON poll response (status {poll.status_code})[/red]")
                    break
                break
            lines.append(f"  Processing scan... ({elapsed}s)")

        if result_data is None:
            lines.append("  Scan still processing — view full report at the URL below")
            lines.append(f"  Full Report  : {result_url}")
            return {}, lines

        page = result_data.get("page", {})
        verdicts = result_data.get("verdicts", {}).get("overall", {})

        url = page.get("url", "N/A")
        domain = page.get("domain", "N/A")
        ip = page.get("ip", "N/A")
        country = page.get("country", "N/A")
        server = page.get("server", "N/A")
        title = page.get("title", "N/A")
        malicious = verdicts.get("malicious", "N/A")
        score = verdicts.get("score", "N/A")

        color = "red" if malicious is True else "green"
        lines.append(f"  URL          : {url}")
        lines.append(f"  Domain       : {domain}")
        lines.append(f"  IP           : {ip}")
        lines.append(f"  Country      : {country}")
        lines.append(f"  Server       : {server}")
        lines.append(f"  Title        : {title}")
        lines.append(f"  Malicious    : [{color}]{malicious}[/{color}]")
        lines.append(f"  Score        : {score}")
        lines.append(f"  Full Report  : {result_url}")
        return result_data, lines
    except Exception as e:
        logger.error("URLScan error for %s: %s", indicator, e)
        lines.append(f"[red]  URLScan error: {type(e).__name__}[/red]")
        return {}, lines
