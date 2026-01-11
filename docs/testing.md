# Testing

Overview
- The repository uses pytest for unit tests.
- Tests cover log parsing and threshold logic in `src/preprocessor.py` and policy enforcement in `src/enforcer.py`.

Running tests locally

```bash
python -m pip install -r requirements.txt pytest
PYTHONPATH=. python -m pytest -q
```

Files
- `tests/test_preprocessor.py`: verifies IP extraction, log parsing, window/threshold behavior and alerts.
- `tests/test_enforcer.py`: uses `unittest.mock` to simulate `apply_control` and validate policy decisions and allowlist behavior.

CI
- A GitHub Actions workflow (`.github/workflows/ci.yml`) runs `pytest` on every push.
