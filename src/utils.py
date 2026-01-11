
import re, ipaddress, json, time
from datetime import datetime
from pathlib import Path


def valid_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except Exception:
        return False


def validate_path(path, base_dir=None):
    """Resolve and validate a filesystem path to prevent traversal.

    If base_dir is provided, ensure the resolved path is inside it.
    Raises ValueError on invalid paths.
    """
    p = Path(path)
    try:
        rp = p.resolve(strict=False)
    except Exception as e:
        raise ValueError(f"Invalid path: {path}") from e

    if base_dir is not None:
        bd = Path(base_dir).resolve()
        try:
            rp.relative_to(bd)
        except Exception:
            raise ValueError(f"Path {path} is outside of allowed base directory")

    return str(rp)


def parse_time(ts):
    return datetime.strptime(ts, "%b %d %H:%M:%S")


def safe_json(obj):
    return json.dumps(obj, separators=(",",":"))
