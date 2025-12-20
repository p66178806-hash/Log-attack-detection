
import argparse, gzip, os
from collections import defaultdict
from datetime import timedelta
from utils import parse_time, valid_ip, safe_json
import csv

FAIL_RE = "Failed password"

def load_inventory(path):
    inv = {}
    with open(path, newline="") as f:
        for r in csv.DictReader(f):
            inv[r["host"]] = r
    return inv

def open_any(path):
    return gzip.open(path, "rt") if path.endswith(".gz") else open(path)

def run(logs, inventory, window, out):
    inv = load_inventory(inventory)
    buckets = defaultdict(int)
    starts = {}
    for p in logs:
        with open_any(p) as f:
            for line in f:
                if FAIL_RE in line:
                    parts = line.split()
                    ts = " ".join(parts[:3])
                    host = parts[3]
                    src = parts[-1]
                    if not valid_ip(src): continue
                    t = parse_time(ts)
                    key = (host, src)
                    if key not in starts: starts[key] = t
                    if t - starts[key] > timedelta(seconds=window):
                        starts[key] = t; buckets[key] = 0
                    buckets[key] += 1
    with open(out, "w") as o:
        for (host, src), cnt in buckets.items():
            crit = inv.get(host, {}).get("criticality","low")
            threshold = {"low":5,"high":3,"critical":2}.get(crit,5)
            alert = cnt >= threshold
            o.write(safe_json({
                "host":host,"src":src,"count":cnt,
                "criticality":crit,"threshold":threshold,"alert":alert
            })+"\n")

if __name__=="__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--logs", nargs="+", required=True)
    ap.add_argument("--inventory", required=True)
    ap.add_argument("--window", type=int, default=300)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()
    run(args.logs, args.inventory, args.window, args.out)
