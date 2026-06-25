import os
import re
import sys
import json
import requests
import argparse
from datetime import datetime
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


def check_virustotal(indicator, ioc_type):
    console.print("\n[bold cyan][ VirusTotal ][/bold cyan]")
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
        console.print("[red]Unsupported IOC type for VirusTotal[/red]")
        return {}

    try:
        r = requests.get(url, headers=headers, timeout=10)
        if r.status_code == 429:
            console.print("[yellow]  VirusTotal: Rate limit reached — wait 60 seconds and retry[/yellow]")
            return {}
        data = r.json()
        stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        harmless = stats.get("harmless", 0)
        undetected = stats.get("undetected", 0)

        color = "red" if malicious > 0 else "green"
        console.print(f"  Malicious  : [{color}]{malicious}[/{color}]")
        console.print(f"  Suspicious : {suspicious}")
        console.print(f"  Harmless   : {harmless}")
        console.print(f"  Undetected : {undetected}")
        return stats
    except Exception as e:
        console.print(f"[red]VirusTotal error: {e}[/red]")
        return {}


def check_abuseipdb(ip):
    console.print("\n[bold cyan][ AbuseIPDB ][/bold cyan]")
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Key": ABUSE_API_KEY, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": 90, "verbose": True}

    try:
        r = requests.get(url, headers=headers, params=params, timeout=10)
        if r.status_code == 429:
            console.print("[yellow]  AbuseIPDB: Rate limit reached — wait 60 seconds and retry[/yellow]")
            return {}
        data = r.json().get("data", {})
        score = data.get("abuseConfidenceScore", 0)
        country = data.get("countryCode", "N/A")
        isp = data.get("isp", "N/A")
        total_reports = data.get("totalReports", 0)
        domain = data.get("domain", "N/A")

        color = "red" if score > 50 else "yellow" if score > 10 else "green"
        console.print(f"  Abuse Score   : [{color}]{score}%[/{color}]")
        console.print(f"  Total Reports : {total_reports}")
        console.print(f"  Country       : {country}")
        console.print(f"  ISP           : {isp}")
        console.print(f"  Domain        : {domain}")
        return data
    except Exception as e:
        console.print(f"[red]AbuseIPDB error: {e}[/red]")
        return {}


def check_shodan(ip):
    console.print("\n[bold cyan][ InternetDB (Shodan) ][/bold cyan]")
    try:
        r = requests.get(f"https://internetdb.shodan.io/{ip}", timeout=15)
        if r.status_code == 404:
            console.print("  No InternetDB data for this IP.")
            return {}
        if r.status_code != 200:
            console.print(f"  [yellow]InternetDB returned {r.status_code}: {r.text[:200]}[/yellow]")
            return {}
        data = r.json()
        ports = data.get("ports", [])
        hostnames = data.get("hostnames", [])
        vulns = data.get("vulns", [])

        console.print(f"  Open Ports   : {', '.join(map(str, ports)) if ports else 'None'}")
        console.print(f"  Hostnames    : {', '.join(hostnames) if hostnames else 'None'}")
        if vulns:
            console.print(f"  [red]CVEs Found   : {', '.join(vulns[:5])}[/red]")
        else:
            console.print("  CVEs Found   : None")
        return data
    except Exception as e:
        console.print(f"[red]InternetDB error: {e}[/red]")
        return {}


def check_urlscan(indicator):
    console.print("\n[bold cyan][ URLScan.io ][/bold cyan]")
    headers = {"API-Key": URLSCAN_API_KEY, "Content-Type": "application/json"}

    try:
        import time
        r = requests.post(
            "https://urlscan.io/api/v1/scan/",
            headers=headers,
            json={"url": indicator, "visibility": "public"},
            timeout=10,
        )
        submit_data = r.json()
        uuid = submit_data.get("uuid")
        result_url = submit_data.get("result", "N/A")

        console.print(f"  Scan submitted (uuid: {uuid}). Polling for results...")

        result_data = None
        for attempt in range(12):
            time.sleep(10)
            elapsed = (attempt + 1) * 10
            poll = requests.get(f"https://urlscan.io/api/v1/result/{uuid}/", timeout=10)
            if poll.status_code == 200:
                result_data = poll.json()
                break
            console.print(f"  Processing scan... ({elapsed}s)")

        if result_data is None:
            console.print("  Scan still processing — view full report at the URL below")
            console.print(f"  Full Report  : {result_url}")
            return {}

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
        console.print(f"  URL          : {url}")
        console.print(f"  Domain       : {domain}")
        console.print(f"  IP           : {ip}")
        console.print(f"  Country      : {country}")
        console.print(f"  Server       : {server}")
        console.print(f"  Title        : {title}")
        console.print(f"  Malicious    : [{color}]{malicious}[/{color}]")
        console.print(f"  Score        : {score}")
        console.print(f"  Full Report  : {result_url}")
        return result_data
    except Exception as e:
        console.print(f"[red]URLScan error: {e}[/red]")
        return {}


def check_otx(indicator, ioc_type):
    console.print("\n[bold cyan][ AlienVault OTX ][/bold cyan]")
    otx = OTXv2(OTX_API_KEY)

    try:
        if ioc_type == "ip":
            result = otx.get_indicator_details_by_section(IndicatorTypes.IPv4, indicator, "general")
        elif ioc_type == "domain":
            result = otx.get_indicator_details_by_section(IndicatorTypes.DOMAIN, indicator, "general")
        elif ioc_type == "url":
            result = otx.get_indicator_details_by_section(IndicatorTypes.URL, indicator, "general")
        else:
            console.print("[red]Unsupported IOC type for OTX[/red]")
            return {}

        pulse_info = result.get("pulse_info", {})
        pulse_count = pulse_info.get("count", 0)
        reputation = result.get("reputation", 0)
        tags = []
        for pulse in pulse_info.get("pulses", [])[:5]:
            tags.extend(pulse.get("tags", []))

        color = "red" if pulse_count > 5 else "yellow" if pulse_count > 0 else "green"
        console.print(f"  Pulse Count  : [{color}]{pulse_count}[/{color}]")
        console.print(f"  Reputation   : {reputation}")
        console.print(f"  Tags         : {', '.join(set(tags[:5])) if tags else 'None'}")
        return result
    except Exception as e:
        if "429" in str(e):
            console.print("[yellow]  OTX: Rate limit reached — wait 60 seconds and retry[/yellow]")
        else:
            console.print(f"[red]OTX error: {e}[/red]")
        return {}


def check_urlhaus(indicator):
    console.print("\n[bold cyan][ URLhaus ][/bold cyan]")
    URLHAUS_API_KEY = os.getenv("URLHAUS_API_KEY")
    try:
        r = requests.post(
            "https://urlhaus-api.abuse.ch/v1/host/",
            headers={"Auth-Key": URLHAUS_API_KEY},
            data={"host": indicator},
            timeout=15,
        )
        data = r.json()
        if "query_status" not in data:
            console.print("  URLhaus requires a free Auth-Key — register at auth.abuse.ch")
            return {}
        query_status = data.get("query_status")

        if query_status == "no_results":
            console.print("  No known malicious URLs — clean.")
            return data

        if query_status != "ok":
            console.print(f"  query_status: {query_status}")
            return data

        url_count = data.get("url_count", 0)
        urls = data.get("urls", [])

        color = "red" if url_count > 0 else "green"
        console.print(f"  Malicious URLs : [{color}]{url_count}[/{color}]")
        for entry in urls[:3]:
            console.print(f"  URL            : {entry.get('url', 'N/A')}")
            console.print(f"    Threat       : {entry.get('threat', 'N/A')}")
            console.print(f"    Status       : {entry.get('url_status', 'N/A')}")
        return data
    except Exception as e:
        console.print(f"[red]URLhaus error: {e}[/red]")
        return {}


def check_rdap(indicator):
    console.print("\n[bold cyan][ RDAP ][/bold cyan]")
    try:
        from datetime import datetime, timezone
        r = requests.get(
            f"https://rdap.org/domain/{indicator}",
            headers={"Accept": "application/rdap+json", "User-Agent": "OSINT-Tool/1.0"},
            allow_redirects=True,
            timeout=15,
        )
        if r.status_code != 200:
            console.print(f"  RDAP returned status {r.status_code}")
            return {}
        try:
            data = r.json()
        except Exception:
            console.print(f"  RDAP parse error (status {r.status_code}): {r.text[:200]}")
            return {}

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
                        if field[0] == "fn":
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

        console.print(f"  Registrar    : {registrar}")
        console.print(f"  Created      : {creation_date or 'N/A'}")
        console.print(f"  Expires      : {expiry_date or 'N/A'}")
        console.print(f"  Age          : {age_str}")
        console.print(f"  Status       : {', '.join(status) if status else 'N/A'}")
        return data
    except Exception as e:
        console.print(f"[red]RDAP error: {e}[/red]")
        return {}


def validate_indicator(indicator):
    ip_re = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")
    url_re = re.compile(r"^https?://\S+")
    domain_re = re.compile(r"^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)+$")
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

    rdap_events = results.get("rdap", {}).get("events", [])
    for event in rdap_events:
        if event.get("eventAction") == "registration":
            try:
                from datetime import timezone
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
        verdict = "CLEAN"
        color = "green"
    elif score <= 50:
        verdict = "SUSPICIOUS"
        color = "yellow"
    else:
        verdict = "MALICIOUS"
        color = "red"

    return score, verdict, color, reasons


def save_report(indicator, ioc_type, results, score=None, verdict=None, reasons=None):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"outputs/{indicator.replace('/', '_').replace(':', '_')}_{timestamp}.json"
    report = {
        "indicator": indicator,
        "type": ioc_type,
        "timestamp": timestamp,
        "score": score,
        "verdict": verdict,
        "reasons": reasons or [],
        "results": results
    }
    with open(filename, "w") as f:
        json.dump(report, f, indent=4)
    console.print(f"\n[green]Report saved to {filename}[/green]")


def investigate(indicator, args):
    validate_indicator(indicator)
    ioc_type = determine_ioc_type(indicator)

    console.print(Panel.fit(
        f"[bold white]OSINT Threat Intelligence Report[/bold white]\n"
        f"Indicator : [yellow]{indicator}[/yellow]\n"
        f"Type      : [cyan]{ioc_type.upper()}[/cyan]\n"
        f"Time      : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        border_style="blue"
    ))

    results = {}
    source_status = {}

    results["virustotal"] = check_virustotal(indicator, ioc_type)
    source_status["VirusTotal"] = bool(results["virustotal"])

    if ioc_type == "ip":
        results["abuseipdb"] = check_abuseipdb(indicator)
        source_status["AbuseIPDB"] = bool(results["abuseipdb"])
        if not args.no_shodan:
            results["shodan"] = check_shodan(indicator)
            source_status["InternetDB"] = bool(results["shodan"])
        else:
            source_status["InternetDB"] = None
    else:
        source_status["AbuseIPDB"] = None
        source_status["InternetDB"] = None

    results["urlhaus"] = check_urlhaus(indicator)
    source_status["URLhaus"] = bool(results["urlhaus"])

    if ioc_type == "domain":
        results["rdap"] = check_rdap(indicator)
        source_status["RDAP"] = bool(results["rdap"])
    else:
        source_status["RDAP"] = None

    results["otx"] = check_otx(indicator, ioc_type)
    source_status["OTX"] = bool(results["otx"])

    ran = {k: v for k, v in source_status.items() if v is not None}
    ok_count = sum(1 for v in ran.values() if v)
    skipped = [k for k, v in source_status.items() if v is None]
    skip_note = f" ({', '.join(skipped)} skipped for {ioc_type.upper()})" if skipped else ""
    console.print(f"\n[dim]Sources: {ok_count}/{len(ran)} returned data{skip_note}[/dim]")

    score, verdict, verdict_color, reasons = calculate_verdict(results)

    reasons_text = "\n".join(f"  • {r}" for r in reasons) if reasons else "  • No threat signals detected"
    console.print(Panel.fit(
        f"[bold {verdict_color}]Verdict: {verdict}[/bold {verdict_color}]\n"
        f"Score  : [{verdict_color}]{score}/100[/{verdict_color}]\n"
        f"\n{reasons_text}",
        border_style=verdict_color,
        title="[bold white]Threat Assessment[/bold white]",
    ))

    return indicator, ioc_type, results, score, verdict, reasons


def main():
    parser = argparse.ArgumentParser(description="OSINT Automation Tool — Threat Intelligence Aggregator")
    parser.add_argument("indicator", nargs="?", help="IP address, domain, or URL to investigate")
    parser.add_argument("--file", help="Path to file with one indicator per line")
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

        combined = []
        for ind in indicators:
            console.print(f"\n[bold blue]{'='*60}[/bold blue]")
            indicator, ioc_type, results, score, verdict, reasons = investigate(ind, args)
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
        indicator, ioc_type, results, score, verdict, reasons = investigate(args.indicator.strip(), args)
        save_report(indicator, ioc_type, results, score=score, verdict=verdict, reasons=reasons)

    else:
        parser.print_help()
        sys.exit(1)

    console.print(Panel.fit(
        "[bold green]Investigation Complete[/bold green]",
        border_style="green"
    ))


if __name__ == "__main__":
    main()