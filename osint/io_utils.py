"""Report persistence helpers."""

import os
import re
import json
import logging
from datetime import datetime

from rich.console import Console

console = Console()
logger = logging.getLogger(__name__)


def save_report(indicator: str, ioc_type: str, results: dict, score: int = None,
                 verdict: str = None, reasons: list = None) -> None:
    """Write a single-indicator report to outputs/{indicator}_{timestamp}.json."""
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
    os.makedirs("outputs", exist_ok=True)
    with open(filename, "w") as f:
        json.dump(report, f, indent=4)
    logger.info("Report saved to %s", filename)
    console.print(f"\n[green]Report saved to {filename}[/green]")
