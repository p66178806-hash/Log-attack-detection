import json
from src import preprocessor


def test_extract_src_ip():
    assert preprocessor.extract_src_ip(["foo", "from", "1.2.3.4", "bar"]) == "1.2.3.4"
    assert preprocessor.extract_src_ip(["no", "ip"]) is None


def test_run_threshold_logic(tmp_path):
    inv = tmp_path / "inv.csv"
    inv.write_text("host,criticality\nhost1,high\nhost2,low\n")

    log = tmp_path / "auth.log"
    lines = []
    # host1: 3 failed attempts (high -> threshold 3)
    for i in range(3):
        lines.append(
            f"Jan 01 00:00:0{i} host1 sshd: Failed password for invalid user root from 1.2.3.4 port 22 ssh2"
        )

    # host2: 4 failed attempts (low -> threshold 5)
    for i in range(4):
        lines.append(
            f"Jan 01 00:01:0{i} host2 sshd: Failed password for invalid user root from 2.2.2.2 port 22 ssh2"
        )

    log.write_text("\n".join(lines))
    out = tmp_path / "out.jsonl"

    preprocessor.run([str(log)], str(inv), window=300, out=str(out))

    results = [json.loads(l) for l in out.read_text().splitlines()]
    d = {(r["host"], r["src"]): r for r in results}

    assert d[("host1", "1.2.3.4")]["count"] == 3
    assert d[("host1", "1.2.3.4")]["alert"] is True

    assert d[("host2", "2.2.2.2")]["count"] == 4
    assert d[("host2", "2.2.2.2")]["alert"] is False
