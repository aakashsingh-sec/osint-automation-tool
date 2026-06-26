"""Streamlit dashboard for the OSINT Automation Tool.

Provides a single-indicator lookup view, a bulk-paste mode, a side-by-side
report comparison view, and a timeline of historical scans — all backed by
shelling out to osint.py and reading its JSON output.
"""

import csv
import io
import json
import re
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd
import plotly.graph_objects as go
import pycountry
import streamlit as st
from fpdf import FPDF

sys.path.insert(0, str(Path(__file__).parent))
from osint import validate_indicator  # noqa: E402

MIN_SUBMIT_INTERVAL_SECONDS = 2.0

st.set_page_config(
    page_title="OSINT Threat Intel Dashboard",
    layout="wide",
    page_icon="🔍",
)

TOOL_DIR = Path(__file__).parent
OUTPUT_DIR = TOOL_DIR / "outputs"

VERDICT_COLORS = {"CLEAN": "#2ecc71", "SUSPICIOUS": "#f1c40f", "MALICIOUS": "#e74c3c"}
VERDICT_DOTS = {"CLEAN": "🟢", "SUSPICIOUS": "🟡", "MALICIOUS": "🔴"}

# ---------------------------------------------------------------------------
# Dark mode (session-state driven CSS override)
# ---------------------------------------------------------------------------

if "dark_mode" not in st.session_state:
    st.session_state["dark_mode"] = False

if st.session_state["dark_mode"]:
    st.markdown(
        """
        <style>
        .stApp { background-color: #0e1117; color: #e6e6e6; }
        section[data-testid="stSidebar"] { background-color: #161a23; }
        div[data-testid="stMetricValue"] { color: #e6e6e6; }
        .stTabs [data-baseweb="tab"] { color: #cfcfcf; }
        </style>
        """,
        unsafe_allow_html=True,
    )

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def run_osint(indicator: str, no_shodan: bool = False) -> tuple:
    """Invoke osint.py and return (parsed_json | None, stderr_text)."""
    OUTPUT_DIR.mkdir(exist_ok=True)
    before = set(OUTPUT_DIR.glob("[!batch]*.json"))

    cmd = [sys.executable, "osint.py", indicator]
    if no_shodan:
        cmd.append("--no-shodan")

    proc = subprocess.run(cmd, capture_output=True, text=True, cwd=str(TOOL_DIR))

    after = set(OUTPUT_DIR.glob("[!batch]*.json"))
    new_files = after - before

    if new_files:
        latest = max(new_files, key=lambda f: f.stat().st_mtime)
        with open(latest) as f:
            return json.load(f), proc.stderr
    return None, proc.stderr or proc.stdout


def relative_time(dt: datetime) -> str:
    """Format a datetime as a short relative-time string, e.g. '5m ago'."""
    now = datetime.now(dt.tzinfo) if dt.tzinfo else datetime.now()
    delta = now - dt
    seconds = delta.total_seconds()
    if seconds < 60:
        return "just now"
    if seconds < 3600:
        return f"{int(seconds // 60)}m ago"
    if seconds < 86400:
        return f"{int(seconds // 3600)}h ago"
    days = int(seconds // 86400)
    if days < 30:
        return f"{days}d ago"
    return dt.strftime("%Y-%m-%d")


def parse_report_timestamp(report: dict, fallback_mtime: float = None) -> datetime:
    """Best-effort parse of a report's timestamp field, falling back to file mtime."""
    ts = report.get("timestamp")
    if ts:
        try:
            return datetime.strptime(ts, "%Y%m%d_%H%M%S")
        except ValueError:
            pass
    if fallback_mtime is not None:
        return datetime.fromtimestamp(fallback_mtime)
    return datetime.now()


def load_past_reports() -> list:
    """Load all non-batch past reports as (path, data, parsed_timestamp) tuples."""
    OUTPUT_DIR.mkdir(exist_ok=True)
    items = []
    for f in OUTPUT_DIR.glob("*.json"):
        if f.name.startswith("batch_"):
            continue
        try:
            with open(f) as fh:
                report = json.load(fh)
        except (json.JSONDecodeError, OSError):
            continue
        ts = parse_report_timestamp(report, fallback_mtime=f.stat().st_mtime)
        items.append((f, report, ts))
    return items


def compute_score_breakdown(results: dict) -> list:
    """Mirror osint.scoring weights to produce a per-source point breakdown for charting."""
    breakdown = []

    malicious = results.get("virustotal", {}).get("malicious", 0)
    vt_points = min(malicious * 3, 30)
    if vt_points:
        breakdown.append(("VirusTotal", vt_points))

    abuse_score = results.get("abuseipdb", {}).get("abuseConfidenceScore", 0)
    ab_points = abuse_score * 0.25
    if ab_points:
        breakdown.append(("AbuseIPDB", ab_points))

    pulse_count = results.get("otx", {}).get("pulse_info", {}).get("count", 0)
    otx_points = min(pulse_count, 20)
    if otx_points:
        breakdown.append(("OTX", otx_points))

    if results.get("urlhaus", {}).get("query_status") == "ok":
        breakdown.append(("URLhaus", 15))

    vulns = results.get("shodan", results.get("internetdb", {})).get("vulns", [])
    if vulns:
        breakdown.append(("InternetDB", min(len(vulns) * 2, 10)))

    for event in results.get("rdap", {}).get("events", []):
        if event.get("eventAction") == "registration":
            try:
                created_dt = datetime.fromisoformat(event["eventDate"].replace("Z", "+00:00"))
                age_days = (datetime.now(timezone.utc) - created_dt).days
                if age_days < 30:
                    breakdown.append(("RDAP", 10))
            except ValueError:
                pass
            break

    return breakdown


def _pdf_safe_text(text, max_len: int = 160, break_every: int = 35) -> str:
    """Truncate and insert breakpoints into long unbroken tokens (URLs, hashes,
    base64 blobs) so fpdf2's multi_cell can wrap the line instead of raising
    'Not enough horizontal space to render a single character'."""
    text = str(text)
    if len(text) > max_len:
        text = text[: max_len - 3] + "..."
    return re.sub(rf"(\S{{{break_every}}})(?=\S)", r"\1 ", text)


def _pdf_source_summary(key: str, val: dict) -> list:
    """Build a short list of human-readable lines for one source's results,
    instead of dumping raw JSON (which can contain unwrappable long strings)."""
    lines = []
    if key == "virustotal":
        lines.append(
            f"Malicious: {val.get('malicious', 0)}  |  Suspicious: {val.get('suspicious', 0)}  |  "
            f"Harmless: {val.get('harmless', 0)}  |  Undetected: {val.get('undetected', 0)}"
        )
    elif key == "abuseipdb":
        lines.append(f"Abuse confidence: {val.get('abuseConfidenceScore', 0)}%  |  Total reports: {val.get('totalReports', 0)}")
        lines.append(f"Country: {val.get('countryCode', 'N/A')}  |  ISP: {_pdf_safe_text(val.get('isp', 'N/A'), max_len=60)}")
    elif key == "shodan":
        ports = val.get("ports", [])
        vulns = val.get("vulns", [])
        lines.append(f"Open ports: {_pdf_safe_text(', '.join(map(str, ports)) or 'none', max_len=100)}")
        lines.append(f"Known CVEs: {_pdf_safe_text(', '.join(vulns[:10]) or 'none', max_len=100)}")
    elif key == "urlhaus":
        status = val.get("query_status", "unknown")
        lines.append(f"Query status: {status}  |  URL count: {val.get('url_count', 0)}")
        for entry in val.get("urls", [])[:3]:
            lines.append(f"  - {_pdf_safe_text(entry.get('url', 'N/A'))}  ({entry.get('threat', 'N/A')})")
    elif key == "rdap":
        registrar = "N/A"
        for entity in val.get("entities", []):
            if "registrar" in entity.get("roles", []):
                vcard = entity.get("vcardArray", [])
                if len(vcard) > 1:
                    for field in vcard[1]:
                        if len(field) > 3 and field[0] == "fn":
                            registrar = field[3]
                            break
                break
        lines.append(f"Registrar: {_pdf_safe_text(registrar, max_len=80)}")
        for ev in val.get("events", [])[:4]:
            lines.append(f"  {ev.get('eventAction', '?')}: {ev.get('eventDate', '?')}")
    elif key == "otx":
        pulse_info = val.get("pulse_info", {})
        tags = []
        for pulse in pulse_info.get("pulses", [])[:5]:
            tags.extend(pulse.get("tags", []))
        lines.append(f"Pulses: {pulse_info.get('count', 0)}  |  Reputation: {val.get('reputation', 0)}")
        if tags:
            lines.append(f"Tags: {_pdf_safe_text(', '.join(dict.fromkeys(tags)), max_len=120)}")
    else:
        lines.append(_pdf_safe_text(json.dumps(val), max_len=160))
    return lines


def build_pdf_report(data: dict) -> bytes:
    """Render a one-page PDF summary of a report dict."""
    pdf = FPDF()
    pdf.set_margins(left=15, top=15, right=15)
    pdf.add_page()
    pdf.set_font("Helvetica", "B", 16)
    pdf.cell(0, 10, "OSINT Threat Intelligence Report", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", "", 11)
    pdf.ln(2)

    indicator = data.get("indicator", "N/A")
    ioc_type = data.get("type", "unknown").upper()
    verdict = data.get("verdict", "UNKNOWN")
    score = data.get("score", 0)
    reasons = data.get("reasons", [])

    pdf.cell(0, 8, f"Indicator: {_pdf_safe_text(indicator, max_len=80)}", new_x="LMARGIN", new_y="NEXT")
    pdf.cell(0, 8, f"Type: {ioc_type}", new_x="LMARGIN", new_y="NEXT")
    pdf.cell(0, 8, f"Verdict: {verdict}  (Score: {score}/100)", new_x="LMARGIN", new_y="NEXT")
    pdf.cell(0, 8, f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(4)

    pdf.set_font("Helvetica", "B", 12)
    pdf.cell(0, 8, "Threat signals:", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", "", 11)
    if reasons:
        for r in reasons:
            pdf.multi_cell(0, 7, f"- {_pdf_safe_text(r)}", new_x="LMARGIN", new_y="NEXT")
    else:
        pdf.multi_cell(0, 7, "- No threat signals detected", new_x="LMARGIN", new_y="NEXT")

    pdf.ln(4)
    pdf.set_font("Helvetica", "B", 12)
    pdf.cell(0, 8, "Source results:", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", "", 10)
    for key, val in data.get("results", {}).items():
        if not val:
            continue
        pdf.set_font("Helvetica", "B", 10)
        pdf.cell(0, 6, f"[{key}]", new_x="LMARGIN", new_y="NEXT")
        pdf.set_font("Helvetica", "", 10)
        for line in _pdf_source_summary(key, val):
            pdf.multi_cell(0, 6, line, new_x="LMARGIN", new_y="NEXT")
        pdf.ln(1)

    return bytes(pdf.output())


def build_csv_report(data: dict) -> str:
    """Flatten a single report into a one-row CSV string."""
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["indicator", "type", "score", "verdict", "reasons"])
    writer.writerow([
        data.get("indicator", ""),
        data.get("type", ""),
        data.get("score", ""),
        data.get("verdict", ""),
        "; ".join(data.get("reasons", [])),
    ])
    return buf.getvalue()


# ---------------------------------------------------------------------------
# Per-source renderers
# ---------------------------------------------------------------------------

def render_virustotal(vt: dict):
    malicious = vt.get("malicious", 0)
    suspicious = vt.get("suspicious", 0)
    harmless = vt.get("harmless", 0)
    undetected = vt.get("undetected", 0)

    c1, c2 = st.columns([1, 1])
    with c1:
        m1, m2, m3, m4 = st.columns(4)
        m1.metric("Malicious", malicious)
        m2.metric("Suspicious", suspicious)
        m3.metric("Harmless", harmless)
        m4.metric("Undetected", undetected)
        if malicious > 0:
            st.error(f"{malicious} engine(s) flagged this indicator as malicious.")
        else:
            st.success("No engines flagged this indicator.")
    with c2:
        total = malicious + suspicious + harmless + undetected
        if total > 0:
            fig = go.Figure(data=[go.Pie(
                labels=["Malicious", "Suspicious", "Harmless", "Undetected"],
                values=[malicious, suspicious, harmless, undetected],
                hole=0.55,
                marker=dict(colors=["#e74c3c", "#f1c40f", "#2ecc71", "#95a5a6"]),
            )])
            fig.update_layout(
                margin=dict(t=10, b=10, l=10, r=10), height=220,
                showlegend=True, legend=dict(orientation="h", y=-0.1),
            )
            st.plotly_chart(fig, use_container_width=True)


def render_abuseipdb(ab: dict):
    score = ab.get("abuseConfidenceScore", 0)
    country = ab.get("countryCode", "N/A")
    lat, lon = ab.get("ipv4Latitude") or ab.get("latitude"), ab.get("ipv4Longitude") or ab.get("longitude")

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Abuse Score", f"{score}%")
    c2.metric("Total Reports", ab.get("totalReports", 0))
    c3.metric("Country", country)
    c4.metric("ISP", ab.get("isp", "N/A"))

    extra_cols = st.columns(3)
    extra_cols[0].write(f"**Domain:** {ab.get('domain', 'N/A')}")
    extra_cols[1].write(f"**Whitelisted:** {'Yes' if ab.get('isWhitelisted') else 'No'}")
    extra_cols[2].write(f"**Tor exit node:** {'⚠️ Yes' if ab.get('isTor') else 'No'}")

    reports = ab.get("reports", [])

    # Aggregate distinct reporter countries (alpha-2 -> alpha-3 for Plotly's
    # ISO-3 locationmode). A single-country map adds little value, so only
    # render the choropleth when reports originate from 2+ distinct countries.
    country_counts: dict = {}
    for rep in reports:
        code = rep.get("reporterCountryCode")
        if not code:
            continue
        country_counts[code] = country_counts.get(code, 0) + 1

    iso3_counts: dict = {}
    for alpha2, count in country_counts.items():
        try:
            entry = pycountry.countries.get(alpha_2=alpha2)
            if entry is None:
                continue
            iso3_counts[entry.alpha_3] = iso3_counts.get(entry.alpha_3, 0) + count
        except (LookupError, AttributeError):
            continue

    if len(iso3_counts) >= 2:
        fig = go.Figure(data=go.Choropleth(
            locations=list(iso3_counts.keys()),
            z=list(iso3_counts.values()),
            locationmode="ISO-3",
            colorscale="Reds",
            showscale=True,
            marker_line_color="white",
            colorbar_title="Reports",
        ))
        fig.update_geos(projection_type="natural earth", showcountries=True)
        fig.update_layout(margin=dict(t=10, b=10, l=10, r=10), height=260,
                           title="Abuse report origins by country")
        st.plotly_chart(fig, use_container_width=True)
    elif country and country != "N/A":
        st.caption(f"📍 Indicator located in **{country}** (not enough distinct reporter countries for a map).")


    if reports:
        with st.expander(f"Recent reports ({len(reports)} total)"):
            for rep in reports[:5]:
                st.markdown(
                    f"- `{rep.get('reportedAt', '?')}` — {rep.get('comment', 'no comment')[:120]}"
                    f" *(from {rep.get('reporterCountryCode', '?')})*"
                )


def render_shodan(sh: dict):
    ports = sh.get("ports", [])
    hostnames = sh.get("hostnames", [])
    vulns = sh.get("vulns", [])

    c1, c2 = st.columns(2)
    with c1:
        st.write("**Open Ports**")
        if ports:
            st.code(", ".join(map(str, ports)))
        else:
            st.write("None detected")
    with c2:
        st.write("**Hostnames**")
        if hostnames:
            st.code("\n".join(hostnames))
        else:
            st.write("None")

    if vulns:
        st.error(f"**{len(vulns)} CVE(s) found:** {', '.join(vulns[:5])}"
                 + (f" … +{len(vulns) - 5} more" if len(vulns) > 5 else ""))
    else:
        st.success("No known CVEs")


def render_urlhaus(uh: dict):
    status = uh.get("query_status", "unknown")
    if status == "no_results":
        st.success("No known malicious URLs associated with this indicator.")
        return
    if status != "ok":
        st.info(f"Query status: `{status}`")
        return

    url_count = uh.get("url_count", 0)
    st.error(f"**{url_count}** malicious URL(s) on record.")
    for entry in uh.get("urls", [])[:5]:
        with st.container():
            st.code(entry.get("url", "N/A"))
            cols = st.columns(2)
            cols[0].write(f"Threat: **{entry.get('threat', 'N/A')}**")
            cols[1].write(f"Status: **{entry.get('url_status', 'N/A')}**")


def render_rdap(rd: dict):
    events = rd.get("events", [])
    creation = expiry = None
    for ev in events:
        action = ev.get("eventAction", "")
        if action == "registration":
            creation = ev.get("eventDate")
        elif action == "expiration":
            expiry = ev.get("eventDate")

    registrar = "N/A"
    for entity in rd.get("entities", []):
        if "registrar" in entity.get("roles", []):
            vcard = entity.get("vcardArray", [])
            if len(vcard) > 1:
                for field in vcard[1]:
                    if len(field) > 3 and field[0] == "fn":
                        registrar = field[3]
                        break
            break

    status = rd.get("status", [])
    c1, c2 = st.columns(2)
    c1.write(f"**Registrar:** {registrar}")
    c1.write(f"**Created:** {creation or 'N/A'}")
    c2.write(f"**Expires:** {expiry or 'N/A'}")
    c2.write(f"**Status:** {', '.join(status[:3]) if status else 'N/A'}")

    if creation:
        try:
            created_dt = datetime.fromisoformat(creation.replace("Z", "+00:00"))
            age_days = (datetime.now(timezone.utc) - created_dt).days
            if age_days < 90:
                st.warning(f"⚠️ Newly registered domain — only **{age_days} days** old.")
            else:
                st.info(f"Domain age: **{age_days:,} days** ({age_days / 365.25:.1f} years)")
        except ValueError:
            pass


def render_otx(otx: dict):
    pulse_info = otx.get("pulse_info", {})
    pulse_count = pulse_info.get("count", 0)
    reputation = otx.get("reputation", 0)

    tags: list = []
    for pulse in pulse_info.get("pulses", [])[:5]:
        tags.extend(pulse.get("tags", []))
    unique_tags = list(dict.fromkeys(tags))[:10]

    c1, c2 = st.columns(2)
    c1.metric("Threat Pulses", pulse_count)
    c2.metric("Reputation Score", reputation)

    if pulse_count > 0:
        st.warning(f"This indicator appears in **{pulse_count}** OTX threat pulse(s).")
    else:
        st.success("No OTX threat pulses found.")

    if unique_tags:
        st.write(f"**Tags:** {', '.join(unique_tags)}")

    pulses = pulse_info.get("pulses", [])
    if pulses:
        with st.expander("Pulse details"):
            for p in pulses[:5]:
                st.markdown(f"- **{p.get('name', 'Unnamed')}** — {p.get('description', '')[:100]}")


SOURCE_RENDERERS: dict = {
    "virustotal": ("VirusTotal", render_virustotal),
    "abuseipdb": ("AbuseIPDB", render_abuseipdb),
    "shodan": ("InternetDB (Shodan)", render_shodan),
    "urlhaus": ("URLhaus", render_urlhaus),
    "rdap": ("RDAP", render_rdap),
    "otx": ("AlienVault OTX", render_otx),
}

# Which IOC types each source supports (drives "Not applicable" message in tabs)
SOURCE_APPLIES: dict = {
    "virustotal": {"ip", "domain", "url", "hash"},
    "abuseipdb":  {"ip"},
    "shodan":     {"ip"},
    "urlhaus":    {"ip", "domain", "url", "hash"},
    "rdap":       {"domain"},
    "otx":        {"ip", "domain", "url", "hash"},
}


def render_verdict_card(data: dict):
    """Render a redesigned verdict card: gauge + reasons + key facts."""
    verdict = data.get("verdict", "UNKNOWN")
    score = data.get("score", 0)
    reasons = data.get("reasons", [])
    ioc_type = data.get("type", "unknown").upper()
    ind_value = data.get("indicator", "")
    color = VERDICT_COLORS.get(verdict, "#7f8c8d")
    dot = VERDICT_DOTS.get(verdict, "⚪")

    card_col, gauge_col = st.columns([2, 1])
    with card_col:
        st.markdown(
            f"""
            <div style="border-left: 6px solid {color}; padding: 0.75rem 1rem;
                        border-radius: 6px; background-color: rgba(127,127,127,0.07);">
              <div style="font-size: 1.4rem; font-weight: 700;">{dot} {verdict}</div>
              <div style="opacity: 0.8; margin-top: 0.15rem;">
                <code>{ind_value}</code> &nbsp;·&nbsp; {ioc_type}
              </div>
            </div>
            """,
            unsafe_allow_html=True,
        )
        if reasons:
            with st.expander("Threat signals", expanded=score > 20):
                for r in reasons:
                    st.markdown(f"- {r}")
        else:
            st.caption("No threat signals detected.")
    with gauge_col:
        fig = go.Figure(go.Indicator(
            mode="gauge+number",
            value=score,
            number={"suffix": "/100"},
            gauge={
                "axis": {"range": [0, 100]},
                "bar": {"color": color},
                "steps": [
                    {"range": [0, 20], "color": "rgba(46,204,113,0.25)"},
                    {"range": [20, 50], "color": "rgba(241,196,15,0.25)"},
                    {"range": [50, 100], "color": "rgba(231,76,60,0.25)"},
                ],
            },
        ))
        fig.update_layout(margin=dict(t=10, b=10, l=10, r=10), height=180)
        st.plotly_chart(fig, use_container_width=True)

    breakdown = compute_score_breakdown(data.get("results", {}))
    if breakdown:
        labels = [b[0] for b in breakdown]
        values = [b[1] for b in breakdown]
        fig2 = go.Figure()
        for label, value in zip(labels, values):
            fig2.add_trace(go.Bar(name=label, x=[value], y=["Score"], orientation="h"))
        fig2.update_layout(
            barmode="stack", height=110,
            margin=dict(t=10, b=10, l=10, r=10),
            xaxis_title="Points contributed", showlegend=True,
            legend=dict(orientation="h", y=-0.4),
        )
        st.plotly_chart(fig2, use_container_width=True)


def render_results(data: dict, key_prefix: str = ""):
    """Render the full results view (verdict card + source tabs + raw JSON) for one report."""
    render_verdict_card(data)
    st.divider()

    results = data.get("results", {})
    ioc_type_lower = data.get("type", "unknown")
    tab_labels = [label for _, (label, _) in SOURCE_RENDERERS.items()]
    tab_objects = st.tabs(tab_labels)

    for tab, (key, (_, renderer)) in zip(tab_objects, SOURCE_RENDERERS.items()):
        with tab:
            applicable = ioc_type_lower in SOURCE_APPLIES.get(key, set())
            if not applicable:
                st.info(f"Not applicable for {ioc_type_lower.upper()} indicators.")
            elif key not in results or not results[key]:
                st.warning("No data returned — the API call may have failed or timed out.")
            else:
                try:
                    renderer(results[key])
                except Exception as exc:
                    st.warning(f"Render error: {exc}")
                    st.json(results[key], expanded=False)

    st.divider()
    exp_c1, exp_c2, exp_c3 = st.columns(3)
    with exp_c1:
        st.download_button(
            "⬇️ Export JSON", data=json.dumps(data, indent=2),
            file_name=f"{data.get('indicator', 'report')}.json", mime="application/json",
            key=f"{key_prefix}export_json",
        )
    with exp_c2:
        st.download_button(
            "⬇️ Export CSV", data=build_csv_report(data),
            file_name=f"{data.get('indicator', 'report')}.csv", mime="text/csv",
            key=f"{key_prefix}export_csv",
        )
    with exp_c3:
        try:
            pdf_bytes = build_pdf_report(data)
            st.download_button(
                "⬇️ Export PDF", data=pdf_bytes,
                file_name=f"{data.get('indicator', 'report')}.pdf", mime="application/pdf",
                key=f"{key_prefix}export_pdf",
            )
        except Exception as exc:
            st.caption(f"PDF export unavailable: {exc}")

    with st.expander("Raw JSON"):
        st.json(data, expanded=False)


# ---------------------------------------------------------------------------
# Sidebar — past reports + dark mode
# ---------------------------------------------------------------------------

with st.sidebar:
    st.header("Past Reports")

    sort_choice = st.selectbox("Sort by", ["Newest first", "Oldest first", "Highest score", "Lowest score"])
    limit = st.slider("Show", min_value=5, max_value=100, value=25, step=5)

    past = load_past_reports()
    if sort_choice == "Newest first":
        past.sort(key=lambda item: item[2], reverse=True)
    elif sort_choice == "Oldest first":
        past.sort(key=lambda item: item[2])
    elif sort_choice == "Highest score":
        past.sort(key=lambda item: item[1].get("score", 0), reverse=True)
    else:
        past.sort(key=lambda item: item[1].get("score", 0))
    past = past[:limit]

    if past:
        options = ["— select —"] + [p[0].name for p in past]
        selected = st.selectbox("Load a previous report", options=options)
        if selected != "— select —":
            match = next((p for p in past if p[0].name == selected), None)
            if match:
                st.session_state["loaded_data"] = match[1]
                st.session_state["loaded_name"] = selected

        st.caption("Recent scans")
        for path, report, ts in past[:15]:
            dot = VERDICT_DOTS.get(report.get("verdict", ""), "⚪")
            ind = report.get("indicator", path.stem)
            st.markdown(
                f"{dot} `{ind}` — score {report.get('score', '?')} · {relative_time(ts)}"
            )
    else:
        st.info("No past reports yet.")

    st.divider()
    st.toggle("🌙 Dark mode", key="dark_mode")
    st.divider()
    st.caption("Runs `osint.py` and reads its output JSON.\nAPI keys must be set in `.env`.")

# ---------------------------------------------------------------------------
# Main — tabbed layout
# ---------------------------------------------------------------------------

st.title("🔍 Threat Intel Dashboard")
st.caption("Powered by VirusTotal · AbuseIPDB · Shodan · URLhaus · AlienVault OTX · RDAP")

tab_lookup, tab_bulk, tab_compare, tab_timeline = st.tabs(
    ["🔍 Lookup", "📋 Bulk Paste", "⚖️ Compare", "📈 Timeline"]
)

# --- Lookup tab -------------------------------------------------------------
with tab_lookup:
    with st.form("analyse_form", clear_on_submit=False):
        col1, col2, col3 = st.columns([4, 1, 1])
        with col1:
            indicator = st.text_input(
                "Enter IP, Domain, URL, or file hash (MD5/SHA1/SHA256)",
                placeholder="e.g. 8.8.8.8 or example.com or https://malicious.site/path",
            )
        with col2:
            st.markdown("<br>", unsafe_allow_html=True)
            no_shodan = st.checkbox("Skip Shodan")
        with col3:
            st.markdown("<br>", unsafe_allow_html=True)
            run = st.form_submit_button("Analyse", use_container_width=True, type="primary")

    data = None
    err_text = ""

    if run and indicator.strip():
        now = time.monotonic()
        last_submit = st.session_state.get("last_submit_time", 0.0)
        elapsed = now - last_submit

        if elapsed < MIN_SUBMIT_INTERVAL_SECONDS:
            st.warning(
                f"Please wait {MIN_SUBMIT_INTERVAL_SECONDS - elapsed:.1f}s before submitting again."
            )
        else:
            st.session_state["last_submit_time"] = now
            is_valid, ioc_type = validate_indicator(indicator.strip())
            if not is_valid:
                st.error(
                    "Invalid indicator format. Enter a valid IP, domain, URL, "
                    "or MD5/SHA1/SHA256 hash."
                )
            else:
                with st.spinner("Querying intelligence sources — this may take 15–30 seconds…"):
                    data, err_text = run_osint(indicator.strip(), no_shodan=no_shodan)
                if "loaded_data" in st.session_state:
                    del st.session_state["loaded_data"]
                if data is None:
                    st.error("osint.py did not produce a report. Check that your `.env` API keys are set.")
                    if err_text:
                        with st.expander("Error output"):
                            st.code(err_text)
    elif "loaded_data" in st.session_state:
        data = st.session_state["loaded_data"]
        st.info(f"Showing saved report: `{st.session_state.get('loaded_name', '')}`")

    if data:
        render_results(data, key_prefix="lookup_")

# --- Bulk paste tab ----------------------------------------------------------
with tab_bulk:
    st.write("Paste one indicator per line (IP, domain, URL, or hash).")
    st.caption("Press **Enter** to add a new line — click **Run bulk analysis** below to submit.")
    bulk_text = st.text_area("Indicators", height=160, placeholder="8.8.8.8\nexample.com\nd41d8cd98f00b204e9800998ecf8427e")
    bulk_no_shodan = st.checkbox("Skip Shodan", key="bulk_no_shodan")
    bulk_run = st.button("Run bulk analysis", type="primary")

    if bulk_run:
        lines = [ln.strip() for ln in bulk_text.splitlines() if ln.strip()]
        valid_lines, invalid_lines = [], []
        for ln in lines:
            ok, _ = validate_indicator(ln)
            (valid_lines if ok else invalid_lines).append(ln)

        if invalid_lines:
            st.warning(f"Skipping {len(invalid_lines)} invalid indicator(s): {', '.join(invalid_lines[:5])}"
                       + (" …" if len(invalid_lines) > 5 else ""))

        if not valid_lines:
            st.error("No valid indicators to run.")
        else:
            progress = st.progress(0.0, text="Starting…")
            bulk_results = []
            for i, ind in enumerate(valid_lines):
                progress.progress((i) / len(valid_lines), text=f"Analysing {ind}…")
                res, _ = run_osint(ind, no_shodan=bulk_no_shodan)
                if res:
                    bulk_results.append(res)
                time.sleep(MIN_SUBMIT_INTERVAL_SECONDS)
            progress.progress(1.0, text="Done")

            st.session_state["bulk_results"] = bulk_results

            if bulk_results:
                ts = datetime.now().strftime("%Y%m%d_%H%M%S")
                batch_path = OUTPUT_DIR / f"batch_{ts}.json"
                with open(batch_path, "w") as fh:
                    json.dump({"timestamp": ts, "indicators": bulk_results}, fh, indent=2)
                st.success(f"Batch report saved to `outputs/{batch_path.name}`")

    if st.session_state.get("bulk_results"):
        df = pd.DataFrame([
            {
                "Indicator": r.get("indicator"),
                "Type": r.get("type"),
                "Score": r.get("score"),
                "Verdict": r.get("verdict"),
            }
            for r in st.session_state["bulk_results"]
        ])
        st.dataframe(df, use_container_width=True, hide_index=True)

        pick = st.selectbox(
            "View full report for:",
            ["—"] + [r.get("indicator") for r in st.session_state["bulk_results"]],
            key="bulk_pick",
        )
        if pick != "—":
            chosen = next(r for r in st.session_state["bulk_results"] if r.get("indicator") == pick)
            render_results(chosen, key_prefix="bulk_")

# --- Compare tab --------------------------------------------------------------
with tab_compare:
    all_past = load_past_reports()
    all_past.sort(key=lambda item: item[2], reverse=True)
    names = [p[0].name for p in all_past]

    if len(names) < 2:
        st.info("Need at least two saved reports to compare. Run some lookups first.")
    else:
        c1, c2 = st.columns(2)
        with c1:
            left_name = st.selectbox("Report A", names, index=0, key="cmp_left")
        with c2:
            right_name = st.selectbox("Report B", names, index=1, key="cmp_right")

        left = next(p[1] for p in all_past if p[0].name == left_name)
        right = next(p[1] for p in all_past if p[0].name == right_name)

        col_a, col_b = st.columns(2)
        for col, report in ((col_a, left), (col_b, right)):
            with col:
                dot = VERDICT_DOTS.get(report.get("verdict", ""), "⚪")
                st.markdown(f"### {dot} {report.get('indicator', 'N/A')}")
                st.write(f"**Type:** {report.get('type', 'unknown').upper()}")
                st.write(f"**Verdict:** {report.get('verdict', 'UNKNOWN')}")
                st.write(f"**Score:** {report.get('score', 0)}/100")
                st.progress(min(max(report.get("score", 0), 0), 100) / 100)
                reasons = report.get("reasons", [])
                if reasons:
                    for r in reasons:
                        st.markdown(f"- {r}")
                else:
                    st.caption("No threat signals detected.")

        st.divider()
        rows = []
        for key in SOURCE_RENDERERS:
            rows.append({
                "Source": SOURCE_RENDERERS[key][0],
                left.get("indicator", "A"): "✅ data" if left.get("results", {}).get(key) else "—",
                right.get("indicator", "B"): "✅ data" if right.get("results", {}).get(key) else "—",
            })
        st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)

# --- Timeline tab --------------------------------------------------------------
with tab_timeline:
    all_past = load_past_reports()
    if not all_past:
        st.info("No past reports yet — run some lookups to populate the timeline.")
    else:
        df = pd.DataFrame([
            {
                "Timestamp": ts,
                "Indicator": report.get("indicator", path.stem),
                "Score": report.get("score", 0),
                "Verdict": report.get("verdict", "UNKNOWN"),
                "Type": report.get("type", "unknown"),
            }
            for path, report, ts in all_past
        ]).sort_values("Timestamp")

        fig = go.Figure()
        for verdict, color in VERDICT_COLORS.items():
            subset = df[df["Verdict"] == verdict]
            if subset.empty:
                continue
            fig.add_trace(go.Scatter(
                x=subset["Timestamp"], y=subset["Score"], mode="markers",
                name=verdict, marker=dict(color=color, size=10),
                text=subset["Indicator"], hovertemplate="%{text}<br>Score: %{y}<extra></extra>",
            ))
        fig.update_layout(
            xaxis_title="Time", yaxis_title="Score", height=420,
            margin=dict(t=20, b=20, l=20, r=20),
        )
        st.plotly_chart(fig, use_container_width=True)
        st.datafr