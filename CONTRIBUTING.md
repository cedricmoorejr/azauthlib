# Contributing

1. Create a branch from `main`.
2. Install development dependencies with `python -m pip install -e ".[dev]"`.
3. Run `ruff check .`, `ruff format --check .`, `bandit -c pyproject.toml -r src`,
   `pip-audit --skip-editable`, and `pytest`.
4. Add tests for behavior and security boundary changes.
5. Open a pull request and describe compatibility or security implications.

Tests must mock Microsoft identity platform calls. Never use live credentials in pull-request CI.
