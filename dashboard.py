import json
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import streamlit as st

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

# ---------------------------------------------------------------------------
# Source runners
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


# ---------------------------------------------------------------------------
# Per-source renderers
# ---------------------------------------------------------------------------

def render_virustotal(vt: dict):
    malicious = vt.get("malicious", 0)
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Malicious", malicious)
    c2.metric("Suspicious", vt.get("suspicious", 0))
    c3.metric("Harmless", vt.get("harmless", 0))
    c4.metric("Undetected", vt.get("undetected", 0))
    if malicious > 0:
        st.error(f"{malicious} engine(s) flagged this indicator as malicious.")
    else:
        st.success("No engines flagged this indicator.")


def render_abuseipdb(ab: dict):
    score = ab.get("abuseConfidenceScore", 0)
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Abuse Score", f"{score}%")
    c2.metric("Total Reports", ab.get("totalReports", 0))
    c3.metric("Country", ab.get("countryCode", "N/A"))
    c4.metric("ISP", ab.get("isp", "N/A"))

    extra_cols = st.columns(3)
    extra_cols[0].write(f"**Domain:** {ab.get('domain', 'N/A')}")
    extra_cols[1].write(f"**Whitelisted:** {'Yes' if ab.get('isWhitelisted') else 'No'}")
    extra_cols[2].write(f"**Tor exit node:** {'⚠️ Yes' if ab.get('isTor') else 'No'}")

    reports = ab.get("reports", [])
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

# ---------------------------------------------------------------------------
# Sidebar — past reports
# ---------------------------------------------------------------------------

with st.sidebar:
    st.header("Past Reports")
    OUTPUT_DIR.mkdir(exist_ok=True)
    past_files = sorted(
        [f for f in OUTPUT_DIR.glob("*.json") if not f.name.startswith("batch_")],
        key=lambda f: f.stat().st_mtime,
        reverse=True,
    )

    if past_files:
        options = ["— select —"] + [f.name for f in past_files[:50]]
        selected = st.selectbox("Load a previous report", options=options)
        if selected != "— select —":
            try:
                with open(OUTPUT_DIR / selected) as fh:
                    st.session_state["loaded_data"] = json.load(fh)
                st.session_state["loaded_name"] = selected
            except (json.JSONDecodeError, OSError) as e:
                st.error(f"Could not load `{selected}`: {e}")
    else:
        st.info("No past reports yet.")

    st.divider()
    st.caption("Runs `osint.py` and reads its output JSON.\nAPI keys must be set in `.env`.")

# ---------------------------------------------------------------------------
# Main input
# ---------------------------------------------------------------------------

st.title("🔍 Threat Intel Dashboard")
st.caption("Powered by VirusTotal · AbuseIPDB · Shodan · URLhaus · AlienVault OTX · RDAP")

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

# ---------------------------------------------------------------------------
# Resolve which data to display
# ---------------------------------------------------------------------------

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

# ---------------------------------------------------------------------------
# Results display
# ---------------------------------------------------------------------------

if data:
    verdict = data.get("verdict", "UNKNOWN")
    score = data.get("score", 0)
    reasons = data.get("reasons", [])
    results = data.get("results", {})
    ioc_type = data.get("type", "unknown").upper()
    ind_value = data.get("indicator", "")

    # Verdict banner
    banner = {"CLEAN": st.success, "SUSPICIOUS": st.warning, "MALICIOUS": st.error}.get(
        verdict, st.info
    )
    banner(f"**{verdict}** — Score: {score}/100 | `{ind_value}` ({ioc_type})")
    st.progress(score / 100)

    if reasons:
        with st.expander("Threat signals", expanded=score > 20):
            for r in reasons:
                st.markdown