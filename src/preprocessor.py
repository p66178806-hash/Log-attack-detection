import argparse
import gzip
import csv
from collections import defaultdict
from datetime import timedelta
from pathlib import Path
from src.utils import parse_time, valid_ip, safe_json, validate_path


FAIL_RE = "Failed password"


def load_inventory(path):
    inv = {}
    with open(path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)

        # Normalize header names (strip spaces, lowercase)
        if reader.fieldnames:
            reader.fieldnames = [h.strip().lower() for h in reader.fieldnames]

        for r in reader:
            # Normalize row keys too
            r = {k.strip().lower(): v for k, v in r.items() if k is not None}

            host = (r.get("host") or r.get("hostname") or "").strip()
            if not host:
                raise ValueError("Inventory CSV must contain a 'host' (or 'hostname') column")

            inv[host] = r
    return inv


def open_any(path):
    # Ensure path is resolved and safe
    p = validate_path(path)
    return gzip.open(p, "rt", encoding="utf-8", errors="ignore") if p.endswith(".gz") else open(p, "r", encoding="utf-8", errors="ignore")


def extract_src_ip(parts):
    """
    Extract source IP address from a tokenized auth.log line.
    For lines like: ... from 8.8.8.8 port 55555 ssh2
    """
    if "from" in parts:
        i = parts.index("from")
        if i + 1 < len(parts):
            candidate = parts[i + 1]
            if valid_ip(candidate):
                return candidate
    return None


def run(logs, inventory, window, out):
    inv = load_inventory(validate_path(inventory, base_dir=Path(inventory).parent))

    buckets = defaultdict(int)
    starts = {}

    for p in logs:
        # validate each log path
        p_safe = validate_path(p)
        with open_any(p_safe) as f:
            for line in f:
                if FAIL_RE not in line:
                    continue

                parts = line.split()
                if len(parts) < 5:
                    continue

                # Timestamp is first 3 tokens: "Jan 01 10:00:01"
                ts = " ".join(parts[:3])

                # Host is token 4 in typical syslog format
                host = parts[3].strip()

                # Extract IP after "from"
                src = extract_src_ip(parts)
                if not src:
                    continue

                # Parse time
                try:
                    t = parse_time(ts)
                except Exception:
                    continue

                key = (host, src)

                if key not in starts:
                    starts[key] = t

                # If outside the window, reset bucket
                if t - starts[key] > timedelta(seconds=window):
                    starts[key] = t
                    buckets[key] = 0

                buckets[key] += 1

    out_path = validate_path(out, base_dir=Path(out).parent)
    with open(out_path, "w", encoding="utf-8") as o:
        for (host, src), cnt in buckets.items():
            crit = (inv.get(host, {}).get("criticality") or "low").strip().lower()
            threshold = {"low": 5, "high": 3, "critical": 2}.get(crit, 5)
            alert = cnt >= threshold

            o.write(
                safe_json(
                    {
                        "host": host,
                        "src": src,
                        "count": cnt,
                        "criticality": crit,
                        "threshold": threshold,
                        "alert": alert,
                    }
                )
                + "\n"
            )


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--logs", nargs="+", required=True)
    ap.add_argument("--inventory", required=True)
    ap.add_argument("--window", type=int, default=300)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    run(args.logs, args.inventory, args.window, args.out)
