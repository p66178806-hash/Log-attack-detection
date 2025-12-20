
# SIEM Pre-Correlation & Network Enforcement (COM732 AE2)

## Overview
This project detects hostile remote login activity from Linux authentication logs, pre-correlates events to reduce SIEM noise, and enforces reversible network controls via a mocked Cisco IOS XE API.

## Components
- **Preprocessor**: Parses auth logs (incl. rotated/gz), aggregates failures in windows, emits JSON summaries.
- **Inventory**: Minimal asset truth (CSV).
- **Enforcer**: Applies idempotent controls with TTL and rollback.
- **Security & Tests**: Validation, TLS/timeouts, CI-ready tests.

## Quick Start
```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python src/preprocessor.py --logs tests/data/auth.log --inventory data/inventory.csv --out out.jsonl
python src/enforcer.py --input out.jsonl --inventory data/inventory.csv
```

## Demo
Run the preprocessor to generate alerts, then the enforcer to apply controls. TTL-based rollback is automatic.
unzip siem-precorrelator.zip
cd siem-precorrelator
git init
git add .
git commit -m "Initial submission-ready implementation"
git branch -M main
git remote add origin https://github.com/<your-username>/siem-precorrelator-com732.git
git push -u origin main
git