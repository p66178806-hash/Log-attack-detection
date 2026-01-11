import json
from unittest.mock import patch
from src import enforcer


def test_enforcer_applies_controls(tmp_path):
    inv = tmp_path / "inv.csv"
    inv.write_text("host,allowlist\nhost1,\nhost2,3.3.3.3\n")

    inp = tmp_path / "in.jsonl"
    lines = []
    lines.append(json.dumps({"host": "host1", "src": "1.2.3.4", "alert": True}))
    lines.append(json.dumps({"host": "host1", "src": "notanip", "alert": True}))
    lines.append(json.dumps({"host": "host2", "src": "3.3.3.3", "alert": True}))
    lines.append(json.dumps({"host": "host1", "src": "5.5.5.5", "alert": False}))
    inp.write_text("\n".join(lines))

    applied = []
    with patch("src.enforcer.apply_control") as mock_apply:
        mock_apply.side_effect = lambda device, src, ttl=60: applied.append((device, src)) or "applied"
        enforcer.run(str(inp), str(inv))

    assert ("edge01", "1.2.3.4") in applied
    # host2 has allowlist equal to src, so it should not be applied
    assert ("edge01", "3.3.3.3") not in applied
