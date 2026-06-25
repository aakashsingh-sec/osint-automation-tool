"""OSINT Automation Tool — thin CLI entrypoint.

Aggregates threat intelligence on an IP address, domain, URL, or file hash
across six independent OSINT sources (VirusTotal, AbuseIPDB, Shodan
InternetDB, URLhaus, AlienVault OTX, RDAP) and produces a single weighted
verdict (CLEAN / SUSPICIOUS / MALICIOUS).

All actual logic lives in the `osint` package (osint/core.py, scoring.py,
validation.py, throttle.py, io_utils.py, sources/*.py). This file only
parses CLI arguments and drives single / batch / file-mode runs.
"""

import sys
import json
import logging
import argparse
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

from rich.console import Console
from rich.panel import Panel

from osint.core import investigate
from osint.io_utils import save_report

console = Console()
logger = logging.getLogger(__name__)


def _configure_logging(verbose: bool, debug: bool) -> None:
    """Configure root logging level based on --verbose/--debug CLI flags."""
    if debug:
        level = logging.DEBUG
    elif verbose:
        level = logging.INFO
    else:
        level = logging.WARNING
    logging.basicConfig(level=level, format="%(asctime)s %(levelname)-8s %(name)s: %(message)s")


def main() -> None:
    """Parse CLI arguments and run single, batch, or file-mode investigations."""
    parser = argparse.ArgumentParser(
        description="OSINT Automation Tool — Threat Intelligence Aggregator"
    )
    parser.add_argument("indicator", nargs="?", help="IP, domain, URL, or file hash to investigate")
    parser.add_argument("--file", help="Path to file with one indicator per line")
    parser.add_argument(
        "--workers", type=int, default=3,
        help="Max concurrent indicators in --file mode (default: 3)",
    )
    parser.add_argument("--no-urlscan", action="store_true", help="Skip URLScan")
    parser.add_argument("--no-shodan", action="store_true", help="Skip Shodan/InternetDB")
    parser.add_argument("--verbose", action="store_true", help="Enable INFO-level logging")
    parser.add_argument("--debug", action="store_true", help="Enable DEBUG-level logging")
    args = parser.parse_args()

    _configure_logging(args.verbose, args.debug)

    if args.file:
        try:
            with open(args.file) as f:
                indicators = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            logger.error("File not found: %s", args.file)
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
                    logger.error("Fatal error for %s: %s", ind, e)
                    results_map[ind] = (
                        [f"[red]Fatal error for {ind}: {type(e).__name__}: {e}[/red]"],
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
        logger.info("Batch report saved to %s", filename)
        console.print(f"\n[green]Batch report saved to {filename}[/green]")

    elif args.indicator:
        try:
            output_buf, indicator, ioc_type, results, score, verdict, reasons = investigate(
                args.indicator.strip(), args
            )
        except ValueError as e:
            console.print(f"[red]{e}[/red]")
            sys.exit(1)
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
