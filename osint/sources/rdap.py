"""RDAP source: domain registration data and age, with registrable-domain walking."""

import json
import logging
import requests
from datetime import datetime, timezone

logger = logging.getLogger(__name__)


def check_rdap(indicator: str) -> tuple:
    """Query RDAP for domain registration data, walking up labels to find a registrable domain."""
    lines = ["\n[bold cyan][ RDAP ][/bold cyan]"]
    try:
        # RDAP only accepts registrable domains, not subdomains.
        # Walk up labels (malware.wicar.org -> wicar.org) until we get a 200.
        labels = indicator.split(".")
        r = None
        queried_domain = indicator
        for start in range(len(labels) - 1):
            candidate = ".".join(labels[start:])
            if candidate.count(".") < 1:
                break
            logger.info("Querying RDAP for %s", candidate)
            resp = requests.get(
                f"https://rdap.org/domain/{candidate}",
                headers={"Accept": "application/rdap+json", "User-Agent": "OSINT-Tool/1.0"},
                allow_redirects=True,
                timeout=15,
            )
            if resp.status_code == 200:
                r = resp
                queried_domain = candidate
                break
            if start == 0 and resp.status_code != 400:
                # Non-400 errors on the original domain are reported as-is
                lines.append(f"  RDAP returned status {resp.status_code}")
                return {}, lines
            if candidate != indicator:
                logger.warning("RDAP: %s not found, walking up to %s", indicator, candidate)

        if r is None:
            lines.append(f"  RDAP: could not resolve a registrable domain for {indicator}")
            return {}, lines

        if queried_domain != indicator:
            lines.append(f"  [dim](queried registrable domain: {queried_domain})[/dim]")

        if r.status_code != 200:
            lines.append(f"  RDAP returned status {r.status_code}")
            return {}, lines
        try:
            data = r.json()
        except json.JSONDecodeError:
            logger.error("RDAP returned non-JSON response (status %s)", r.status_code)
            lines.append(f"[red]  RDAP: API returned non-JSON response (status {r.status_code})[/red]")
            return {}, lines
        logger.debug("RDAP raw response for %s: %s", queried_domain, data)

        events = data.get("events", [])
        creation_date = None
        expiry_date = None
        for event in events:
            action = event.get("eventAction", "")
            if action == "registration":
                creation_date = event.get("eventDate")
            elif action == "expiration":
                expiry_date = event.get("eventDate")

        status = data.get("status", [])

        registrar = "N/A"
        for entity in data.get("entities", []):
            roles = entity.get("roles", [])
            if "registrar" in roles:
                vcard = entity.get("vcardArray", [])
                if len(vcard) > 1:
                    for field in vcard[1]:
                        if len(field) > 3 and field[0] == "fn":
                            registrar = field[3]
                            break
                break

        age_str = "N/A"
        if creation_date:
            try:
                created_dt = datetime.fromisoformat(creation_date.replace("Z", "+00:00"))
                now = datetime.now(timezone.utc)
                age_days = (now - created_dt).days
                age_years = age_days / 365.25
                if age_days < 90:
                    age_str = f"[red]{age_days} days ({age_years:.1f} years) — newly registered[/red]"
                else:
                    age_str = f"{age_days} days ({age_years:.1f} years)"
            except ValueError:
                age_str = creation_date

        lines.append(f"  Registrar    : {registrar}")
        lines.append(f"  Created      : {creation_date or 'N/A'}")
        lines.append(f"  Expires      : {expiry_date or 'N/A'}")
        lines.append(f"  Age          : {age_str}")
        lines.append(f"  Status       : {', '.join(status) if status else 'N/A'}")
        return data, lines
    except Exception as e:
        logger.error("RDAP error for %s: %s", indicator, e)
        lines.append(f"[red]  RDAP error: {type(e).__name__}[/red]")
        return {}, lines
