import os
import re
import sys
import json
import time
import threading
import requests
import argparse
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed
from dotenv import load_dotenv
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import print as rprint
from OTXv2 import OTXv2, IndicatorTypes

load_dotenv()

console = Console()

VT_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
ABUSE_API_KEY = os.getenv("ABUSEIPDB_API_KEY")
SHODAN_API_KEY = os.getenv("SHODAN_API_KEY")
URLSCAN_API_KEY = os.getenv("URLSCAN_API_KEY")
OTX_API_KEY = os.getenv("OTX_API_KEY")

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

# VirusTotal free tier: 4 requests/minute across all threads
_vt_lock = threading.Lock()
_vt_timestamps: list = []


def _vt_throttle():
    """Block until a VirusTotal call is within the 4-per-minute budget."""
    while True:
        with _vt_lock:
            now = time.monotonic()
            _vt_timestamps[:] = [t for t in _vt_timestamps if now - t < 60.0]
            if len(_vt_timestamps) < 4:
                _vt_timestamps.append(now)
                return
            wait = 60.0 - (now - _vt_timestamps[0])
        # Sleep outside the lock so other threads can enter and check
        time.sleep(wait + 0.1)


# ---------------------------------------------------------------------------
# Check functions — each returns (data_dict, output_lines_list).
# No direct console.print calls inside these functions; callers print lines.
# ---------------------------------------------------------------------------

def check_virustotal(indicator, ioc_type):
    lines = ["\n[bold cyan][ VirusTotal ][/bold cyan]"]
    _vt_throttle()
    headers = {"x-apikey": VT_API_KEY}

    if ioc_type == "ip":
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{indicator}"
    elif ioc_type == "domain":
        url = f"https://www.virustotal.com/api/v3/domains/{indicator}"
    elif ioc_type == "url":
        import base64
        url_id = base64.urlsafe_b64encode(indicator.encode()).decode().strip("=")
        url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
    else:
        lines.append("[red]  Unsupported IOC type for VirusTotal[/red]")
        return {}, lines

    try:
        r = requests.get(url, headers=headers, timeout=10)
        if r.status_code == 429:
            lines.append("[yellow]  VirusTotal: Rate limit reached — wait 60 seconds and retry[/yellow]")
            return {}, lines
        try:
            data = r.json()
        except json.JSONDecodeError:
            lines.append(f"[red]  VirusTotal: API returned non-JSON response (status {r.status_code})[/red]")
            return {}, lines
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
        lines.append(f"[red]  VirusTotal error: {type(e).__name__}[/red]")
        return {}, lines


def check_abuseipdb(ip):
    lines = ["\n[bold cyan][ AbuseIPDB ][/bold cyan]"]
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Key": ABUSE_API_KEY, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": 90, "verbose": True}

    try:
        r = requests.get(url, headers=headers, params=params, timeout=10)
        if r.status_code == 429:
            lines.append("[yellow]  AbuseIPDB: Rate limit reached — wait 60 seconds and retry[/yellow]")
            return {}, lines
        try:
            data = r.json().get("data", {})
        except json.JSONDecodeError:
            lines.append(f"[red]  AbuseIPDB: API returned non-JSON response (status {r.status_code})[/red]")
            return {}, lines
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
        lines.append(f"[red]  AbuseIPDB error: {type(e).__name__}[/red]")
        return {}, lines


def check_shodan(ip):
    lines = ["\n[bold cyan][ InternetDB (Shodan) ][/bold cyan]"]
    try:
        r = requests.get(f"https://internetdb.shodan.io/{ip}", timeout=15)
        if r.status_code == 404:
            lines.append("  No InternetDB data for this IP.")
            return {}, lines
        if r.status_code != 200:
            lines.append(f"  [yellow]InternetDB returned {r.status_code}: {r.text[:200]}[/yellow]")
            return {}, lines
        try:
            data = r.json()
        except json.JSONDecodeError:
            lines.append(f"[red]  InternetDB: API returned non-JSON response (status {r.status_code})[/red]")
            return {}, lines
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
        lines.append(f"[red]  InternetDB error: {type(e).__name__}[/red]")
        return {}, lines


def check_urlscan(indicator):
    """Dormant — not called from investigate(). Preserved for future use."""
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
        lines.append(f"[red]  URLScan error: {type(e).__name__}[/red]")
        return {}, lines


def check_otx(indicator, ioc_type):
    lines = ["\n[bold cyan][ AlienVault OTX ][/bold cyan]"]
    otx = OTXv2(OTX_API_KEY)

    try:
        if ioc_type == "ip":
            result = otx.get_indicator_details_by_section(IndicatorTypes.IPv4, indicator, "general")
        elif ioc_type == "domain":
            result = otx.get_indicator_details_by_section(IndicatorTypes.DOMAIN, indicator, "general")
        elif ioc_type == "url":
            result = otx.get_indicator_details_by_section(IndicatorTypes.URL, indicator, "general")
        else:
            lines.append("[red]  Unsupported IOC type for OTX[/red]")
            return {}, lines

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
            lines.append("[yellow]  OTX: Rate limit reached — wait 60 seconds and retry[/yellow]")
        else:
            lines.append(f"[red]  OTX error: {type(e).__name__}[/red]")
        return {}, lines


def check_urlhaus(indicator):
    lines = ["\n[bold cyan][ URLhaus ][/bold cyan]"]
    URLHAUS_API_KEY = os.getenv("URLHAUS_API_KEY")
    try:
        r = requests.post(
            "https://urlhaus-api.abuse.ch/v1/host/",
            headers={"Auth-Key": URLHAUS_API_KEY},
            data={"host": indicator},
            timeout=15,
        )
        try:
            data = r.json()
        except json.JSONDecodeError:
            lines.append(f"[red]  URLhaus: API returned non-JSON response (status {r.status_code})[/red]")
            return {}, lines
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

        url_count = data.get("url_count", 0)
        urls = data.get("urls", [])

        color = "red" if url_count > 0 else "green"
        lines.append(f"  Malicious URLs : [{color}]{url_count}[/{color}]")
        for entry in urls[:3]:
            lines.append(f"  URL            : {entry.get('url', 'N/A')}")
            lines.append(f"    Threat       : {entry.get('threat', 'N/A')}")
            lines.append(f"    Status       : {entry.get('url_status', 'N/A')}")
        return data, lines
    except Exception as e:
        lines.append(f"[red]  URLhaus error: {type(e).__name__}[/red]")
        return {}, lines


def check_rdap(indicator):
    lines = ["\n[bold cyan][ RDAP ][/bold cyan]"]
    try:
        r = requests.get(
            f"https://rdap.org/domain/{indicator}",
            headers={"Accept": "application/rdap+json", "User-Agent": "OSINT-Tool/1.0"},
            allow_redirects=True,
            timeout=15,
        )
        if r.status_code != 200:
            lines.append(f"  RDAP returned status {r.status_code}")
            return {}, lines
        try:
            data = r.json()
        except json.JSONDecodeError:
            lines.append(f"[red]  RDAP: API returned non-JSON response (status {r.status_code})[/red]")
            return {}, lines

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
        lines.append(f"[red]  RDAP error: {type(e).__name__}[/red]")
        return {}, lines


# ---------------------------------------------------------------------------
# Utility / scoring
# ---------------------------------------------------------------------------

def validate_indicator(indicator):
    ip_re = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")
    url_re = re.compile(r"^https?://\S+")
    domain_re = re.compile(
        r"^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?"
        r"(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)+$"
    )
    if ip_re.match(indicator):
        octets = indicator.split(".")
        if all(0 <= int(o) <= 255 for o in octets):
            return
    if url_re.match(indicator):
        return
    if domain_re.match(indicator):
        return
    console.print("[red]Invalid indicator format. Provide a valid IP, domain, or URL.[/red]")
    sys.exit(1)


def determine_ioc_type(indicator):
    ip_pattern = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
    if ip_pattern.match(indicator):
        return "ip"
    elif indicator.startswith("http://") or indicator.startswith("https://"):
        return "url"
    else:
        return "domain"


def calculate_verdict(results):
    score = 0
    reasons = []

    malicious = results.get("virustotal", {}).get("malicious", 0)
    score += min(malicious * 3, 30)
    if malicious > 0:
        reasons.append(f"VirusTotal: {malicious} engines flagged")

    abuse_score = results.get("abuseipdb", {}).get("abuseConfidenceScore", 0)
    score += abuse_score * 0.25
    if abuse_score > 25:
        reasons.append(f"AbuseIPDB: {abuse_score}% abuse confidence")

    pulse_count = results.get("otx", {}).get("pulse_info", {}).get("count", 0)
    score += min(pulse_count, 20)
    if pulse_count > 0:
        reasons.append(f"OTX: {pulse_count} threat pulses")

    if results.get("urlhaus", {}).get("query_status") == "ok":
        score += 15
        reasons.append("URLhaus: known malicious URLs")

    vulns = results.get("shodan", results.get("internetdb", {})).get("vulns", [])
    if vulns:
        score += min(len(vulns) * 2, 10)
        reasons.append(f"InternetDB: {len(vulns)} known CVEs")

    for event in results.get("rdap", {}).get("events", []):
        if event.get("eventAction") == "registration":
            try:
                created_dt = datetime.fromisoformat(event["eventDate"].replace("Z", "+00:00"))
                age_days = (datetime.now(timezone.utc) - created_dt).days
                if age_days < 30:
                    score += 10
                    reasons.append("RDAP: domain registered under 30 days ago")
            except ValueError:
                pass
            break

    score = min(int(score), 100)

    if score <= 20:
        verdict, color = "CLEAN", "green"
    elif score <= 50:
        verdict, color = "SUSPICIOUS", "yellow"
    else:
        verdict, color = "MALICIOUS", "red"

    return score, verdict, color, reasons


def save_report(indicator, ioc_type, results, score=None, verdict=None, reasons=None):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_name = re.sub(r'[^a-zA-Z0-9._-]', '_', indicator)
    safe_name = safe_name.lstrip('.')
    safe_name = os.path.basename(safe_name)
    filename = os.path.join("outputs", f"{safe_name}_{timestamp}.json")
    report = {
        "indicator": indicator,
        "type": ioc_type,
        "timestamp": timestamp,
        "score": score,
        "verdict": verdict,
        "reasons": reasons or [],
        "results": results,
    }
    with open(filename, "w") as f:
        json.dump(report, f, indent=4)
    console.print(f"\n[green]Report saved to {filename}[/green]")


# ---------------------------------------------------------------------------
# Core investigation logic
# ---------------------------------------------------------------------------

def investigate(indicator, args):
    """
    Run all applicable sources concurrently for one indicator.
    Returns (output_buf, indicator, ioc_type, results, score, verdict, reasons).
    output_buf is a list of rich renderables — callers print them when ready.
    """
    validate_indicator(indicator)
    ioc_type = determine_ioc_type(indicator)

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

    tasks.append(("urlhaus", check_urlhaus, (indicator,)))

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


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="OSINT Automation Tool — Threat Intelligence Aggregator"
    )
    parser.add_argument("indicator", nargs="?", help="IP address, domain, or URL to investigate")
    parser.add_argument("--file", help="Path to file with one indicator per line")
    parser.add_argument(
        "--workers", type=int, default=3,
        help="Max concurrent indicators in --file mode (default: 3)",
    )
    parser.add_argument("--no-urlscan", action="store_true", help="Skip URLScan")
    parser.add_argument("--no-shodan", action="store_true", help="Skip Shodan/InternetDB")
    args = parser.parse_args()

    if args.file:
        try:
            with open(args.file) as f:
                indicators = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            console.print(f"[red]File not found: {args.file}[/red]")
            sys.exit(1)

        # Investigate up to --workers indicators concurrently; buffer all output
        results_map: dict = {}
        with ThreadPoolExecutor(max_workers=args.workers) as executor:
            future_to_ind = {
                executor.submit(investigate, ind, args): ind
                for ind in indicators
            }
            for future in as_completed(future_to_ind):
                ind = future_to_ind[future]
                try:
                    results_map[ind] = future.result()
                except Exception as e:
                    results_map[ind] = (
                        [f"[red]Fatal error for {ind}: {type(e).__name__}[/red]"],
                        ind, "unknown", {}, 0, "ERROR", [],
                    )

        # Print in original input order (not completion order) and collect for JSON
        combined = []
        for ind in indicators:
            output_buf, indicator, ioc_type, results, score, verdict, reasons = results_map[ind]
            console.print(f"\n[bold blue]{'=' * 60}[/bold blue]")
            for item in output_buf:
                console.print(item)
            combined.append({
                "indicator": indicator,
                "type": ioc_type,
                "score": score,
                "verdict": verdict,
                "reasons": reasons,
                "results": results,
            })

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"outputs/batch_{timestamp}.json"
        with open(filename, "w") as f:
            json.dump({"timestamp": timestamp, "indicators": combined}, f, indent=4)
        console.print(f"\n[green]Batch report saved to {filename}[/green]")

    elif args.indicator:
        output_buf, indicator, ioc_type, results, score, verdict, reasons = investigate(
            args.indicator.strip(), args
        )
        for item in output_buf:
            console.print(item)
        save_report(indicator, ioc_type, results, score=score, verdict=verdict, reasons=reasons)

    else:
        parser.print_help()
        sys.exit(1)

    console.print(Panel.fit(
        "[bold green]Investigation Complete[/bold green]",
        border_style="green",
    ))


if __name__ == "__main__":
    main()
