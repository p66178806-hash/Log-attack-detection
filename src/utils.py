
import re, ipaddress, json, time
from datetime import datetime

def valid_ip(ip):
    try:
        ipaddress.ip_address(ip); return True
    except Exception:
        return False

def parse_time(ts):
    return datetime.strptime(ts, "%b %d %H:%M:%S")

def safe_json(obj):
    return json.dumps(obj, separators=(",",":"))
