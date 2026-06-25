"""Weighted verdict scoring across all OSINT source results."""

from datetime import datetime, timezone


def calculate_verdict(results: dict) -> tuple:
    """Combine per-source results into a 0-100 weighted score, verdict, color, and reasons list."""
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
