
import argparse, csv, json, time
from utils import valid_ip

STATE = {}

def load_inventory(path):
    inv = {}
    with open(path, newline="") as f:
        for r in csv.DictReader(f):
            inv[r["host"]] = r
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
    with open(inp) as f:
        for line in f:
            rec = json.loads(line)
            if not rec.get("alert"): continue
            if not valid_ip(rec["src"]): continue
            host = rec["host"]
            allow = inv.get(host,{}).get("allowlist","")
            if rec["src"] == allow: continue
            print(apply_control("edge01", rec["src"]))
    rollback()

if __name__=="__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", required=True)
    ap.add_argument("--inventory", required=True)
    args = ap.parse_args()
    run(args.input, args.inventory)
