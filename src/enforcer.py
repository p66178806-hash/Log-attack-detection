
import argparse, csv, json, time
from pathlib import Path
from src.utils import valid_ip, validate_path

STATE = {}

def load_inventory(path):
    inv = {}
    p = validate_path(path, base_dir=Path(path).parent)
    with open(p, newline="", encoding="utf-8") as f:
        for r in csv.DictReader(f):
            # normalize host key and strip values
            host = (r.get("host") or r.get("hostname") or "").strip()
            if not host:
                continue
            inv[host] = {k.strip(): (v.strip() if isinstance(v, str) else v) for k, v in r.items()}
    return inv

def apply_control(device, src, ttl=60):
    key = (device, src)
    if key in STATE: return "noop"
    STATE[key] = time.time() + ttl
    return "applied"

def rollback():
    now = time.time()
    for k,v in list(STATE.items()):
        if v <= now: del STATE[k]

def run(inp, inventory):
    inv = load_inventory(inventory)
    inp_path = validate_path(inp)
    with open(inp_path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except Exception:
                continue

            # basic shape validation
            if not isinstance(rec, dict):
                continue
            if not rec.get("alert"):
                continue
            src = rec.get("src")
            host = rec.get("host")
            if not isinstance(src, str) or not isinstance(host, str):
                continue
            if not valid_ip(src):
                continue

            allow = inv.get(host, {}).get("allowlist", "")
            if src == allow:
                continue

            print(apply_control("edge01", src))
    rollback()

if __name__=="__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", required=True)
    ap.add_argument("--inventory", required=True)
    args = ap.parse_args()
    run(args.input, args.inventory)
