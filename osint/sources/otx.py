"""AlienVault OTX source: threat-intelligence pulses and campaign tags."""

import logging
from OTXv2 import OTXv2, IndicatorTypes

from osint.config import OTX_API_KEY
from osint.validation import hash_subtype

logger = logging.getLogger(__name__)


def check_otx(indicator: str, ioc_type: str) -> tuple:
    """Query AlienVault OTX for an IP, domain, URL, or hash and return (data, display_lines)."""
    lines = ["\n[bold cyan][ AlienVault OTX ][/bold cyan]"]
    otx = OTXv2(OTX_API_KEY)

    try:
        if ioc_type == "ip":
            result = otx.get_indicator_details_by_section(IndicatorTypes.IPv4, indicator, "general")
        elif ioc_type == "domain":
            result = otx.get_indicator_details_by_section(IndicatorTypes.DOMAIN, indicator, "general")
        elif ioc_type == "url":
            result = otx.get_indicator_details_by_section(IndicatorTypes.URL, indicator, "general")
        elif ioc_type == "hash":
            subtype = hash_subtype(indicator)
            hash_type_map = {
                "md5": IndicatorTypes.FILE_HASH_MD5,
                "sha1": IndicatorTypes.FILE_HASH_SHA1,
                "sha256": IndicatorTypes.FILE_HASH_SHA256,
            }
            otx_type = hash_type_map.get(subtype)
            if otx_type is None:
                lines.append("[red]  Unsupported hash length for OTX[/red]")
                return {}, lines
            result = otx.get_indicator_details_by_section(otx_type, indicator, "general")
        else:
            lines.append("[red]  Unsupported IOC type for OTX[/red]")
            return {}, lines

        logger.info("Querying OTX for %s (%s)", indicator, ioc_type)
        logger.debug("OTX raw response for %s: %s", indicator, result)
        pulse_info = result.get("pulse_info", {})
        pulse_count = pulse_info.get("count", 0)
        reputation = result.get("reputation", 0)
        tags = []
        for pulse in pulse_info.get("pulses", [])[:5]:
            tags.extend(pulse.get("tags", []))

        color = "red" if pulse_count > 5 else "yellow" if pulse_count > 0 else "green"
        lines.append(f"  Pulse Count  : [{color}]{pulse_count}[/{color}]")
        lines.append(f"  Reputation   : {reputation}")
        lines.append(f"  Tags         : {', '.join(set(tags[:5])) if tags else 'None'}")
        return result, lines
    except Exception as e:
        if "429" in str(e):
            logger.warning("OTX rate limit hit for %s", indicator)
            lines.append("[yellow]  OTX: Rate limit reached — wait 60 seconds and retry[/yellow]")
        else:
            logger.error("OTX error for %s: %s", indicator, e)
            lines.append(f"[red]  OTX error: {type(e).__name__}[/red]")
        return {}, lines
