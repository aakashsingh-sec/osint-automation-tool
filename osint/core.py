"""Core investigation logic: fans out to all applicable sources concurrently."""

import logging
import argparse
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

from rich.panel import Panel

from osint.validation import validate_indicator
from osint.scoring import calculate_verdict
from osint.sources.virustotal import check_virustotal
from osint.sources.abuseipdb import check_abuseipdb
from osint.sources.shodan_idb import check_shodan
from osint.sources.urlhaus import check_urlhaus
from osint.sources.otx import check_otx
from osint.sources.rdap import check_rdap

logger = logging.getLogger(__name__)

# Fixed print order regardless of which futures complete first
DISPLAY_ORDER = ["virustotal", "abuseipdb", "shodan", "urlhaus", "rdap", "otx"]

SOURCE_DISPLAY_NAMES = {
    "virustotal": "VirusTotal",
    "abuseipdb": "AbuseIPDB",
    "shodan": "InternetDB",
    "urlhaus": "URLhaus",
    "rdap": "RDAP",
    "otx": "OTX",
}


def investigate(indicator: str, args: argparse.Namespace) -> tuple:
    """Run all applicable sources concurrently for one indicator.

    Returns (output_buf, indicator, ioc_type, results, score, verdict, reasons).
    output_buf is a list of rich renderables — callers print them when ready.
    Raises ValueError if the indicator fails validation.
    """
    is_valid, ioc_type = validate_indicator(indicator)
    if not is_valid:
        logger.error("Rejected invalid indicator: %r", indicator)
        raise ValueError(
            f"Invalid indicator format: {indicator!r}. "
            "Provide a valid IP, domain, URL, or MD5/SHA1/SHA256 hash."
        )

    output_buf = []
    output_buf.append(Panel.fit(
        f"[bold white]OSINT Threat Intelligence Report[/bold white]\n"
        f"Indicator : [yellow]{indicator}[/yellow]\n"
        f"Type      : [cyan]{ioc_type.upper()}[/cyan]\n"
        f"Time      : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        border_style="blue",
    ))

    # Build the list of (result_key, function, args_tuple) for this indicator type
    tasks = [("virustotal", check_virustotal, (indicator, ioc_type))]
    source_status = {}

    if ioc_type == "ip":
        tasks.append(("abuseipdb", check_abuseipdb, (indicator,)))
        if not args.no_shodan:
            tasks.append(("shodan", check_shodan, (indicator,)))
        else:
            source_status["InternetDB"] = None
    else:
        source_status["AbuseIPDB"] = None
        source_status["InternetDB"] = None

    tasks.append(("urlhaus", check_urlhaus, (indicator, ioc_type)))

    if ioc_type == "domain":
        tasks.append(("rdap", check_rdap, (indicator,)))
    else:
        source_status["RDAP"] = None

    tasks.append(("otx", check_otx, (indicator, ioc_type)))

    # Run all sources concurrently; collect results keyed by source name
    results = {}
    output_map = {}

    with ThreadPoolExecutor(max_workers=len(tasks)) as executor:
        future_to_key = {
            executor.submit(fn, *fn_args): key
            for key, fn, fn_args in tasks
        }
        for future in as_completed(future_to_key):
            key = future_to_key[future]
            try:
                data, lines = future.result()
            except Exception as e:
                logger.error("%s unexpected error for %s: %s", key, indicator, e)
                data = {}
                lines = [f"[red]  {key} unexpected error: {type(e).__name__}[/red]"]
            results[key] = data
            output_map[key] = lines

    # Append source sections to output buffer in a fixed display order
    for key in DISPLAY_ORDER:
        if key in output_map:
            for line in output_map[key]:
                output_buf.append(line)

    # Build source status summary
    for key in results:
        display_name = SOURCE_DISPLAY_NAMES.get(key, key)
        source_status[display_name] = bool(results[key])

    ran = {k: v for k, v in source_status.items() if v is not None}
    ok_count = sum(1 for v in ran.values() if v)
    skipped = [k for k, v in source_status.items() if v is None]
    skip_note = f" ({', '.join(skipped)} skipped for {ioc_type.upper()})" if skipped else ""
    output_buf.append(f"\n[dim]Sources: {ok_count}/{len(ran)} returned data{skip_note}[/dim]")

    score, verdict, verdict_color, reasons = calculate_verdict(results)

    reasons_text = "\n".join(f"  • {r}" for r in reasons) if reasons else "  • No threat signals detected"
    output_buf.append(Panel.fit(
        f"[bold {verdict_color}]Verdict: {verdict}[/bold {verdict_color}]\n"
        f"Score  : [{verdict_color}]{score}/100[/{verdict_color}]\n"
        f"\n{reasons_text}",
        border_style=verdict_color,
        title="[bold white]Threat Assessment[/bold white]",
    ))

    return output_buf, indicator, ioc_type, results, score, verdict, reasons
