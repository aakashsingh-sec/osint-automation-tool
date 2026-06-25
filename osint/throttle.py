"""Rate-limiting helpers shared across source modules."""

import time
import logging
import threading

logger = logging.getLogger(__name__)

# VirusTotal free tier: 4 requests/minute across all threads
_vt_lock = threading.Lock()
_vt_timestamps: list = []


def vt_throttle() -> None:
    """Block the calling thread until a VirusTotal call is within the 4-per-minute budget."""
    while True:
        with _vt_lock:
            now = time.monotonic()
            _vt_timestamps[:] = [t for t in _vt_timestamps if now - t < 60.0]
            if len(_vt_timestamps) < 4:
                _vt_timestamps.append(now)
                return
            wait = 60.0 - (now - _vt_timestamps[0])
        # Sleep outside the lock so other threads can enter and check
        logger.debug("VirusTotal throttle: sleeping %.2fs to stay within rate budget", wait + 0.1)
        time.sleep(wait + 0.1)
