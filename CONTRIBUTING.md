# Contributing to rag-firewall

Thanks for your interest. This project is part of the **Production AI, From Zero** series and welcomes contributions that strengthen the defense layers, broaden test coverage, or improve the operator experience.

## Local Setup

```bash
git clone https://github.com/Ramdragneel01/rag-firewall.git
cd rag-firewall
python -m venv .venv && source .venv/bin/activate   # PowerShell: .venv\Scripts\Activate.ps1
pip install -r requirements-dev.txt
pip install -e .
pytest
```

## Branching & Commits

- Branch from `main`: `feat/<short-name>`, `fix/<short-name>`, `docs/<short-name>`.
- Use [Conventional Commits](https://www.conventionalcommits.org/): `feat:`, `fix:`, `docs:`, `test:`, `refactor:`, `chore:`.
- One logical change per PR. No "WIP" merges to `main`.

## What Gets Reviewed

Every PR must:

1. Pass `ruff check src tests` (lint).
2. Pass `pytest` (all tests green).
3. Add or update tests for any behavior change.
4. Update `CHANGELOG.md` under "Unreleased" if the change is user-visible.
5. Keep image size and added latency within the operational targets in `ARCHITECTURE.md`.

## Adding a New Detection

1. Add the pattern / rule to the appropriate detector module in `src/rag_firewall/detectors/`.
2. Add at least one **positive** and one **negative** test in `tests/`.
3. If the rule is heuristic, document its weight and reasoning in a comment.
4. Update `SECURITY.md` if a new attack class enters scope.

## Adding a New Configuration Knob

1. Extend `Settings` in `src/rag_firewall/config.py`.
2. Add the variable to `.env.example` with a default and a one-line comment.
3. Document it in the README configuration table.

## Reporting Bugs

Use the GitHub issue tracker for non-security bugs. For security issues, see [SECURITY.md](SECURITY.md).

## Code of Conduct

Be respectful. Assume good intent. No harassment, period. Maintainer reserves the right to lock or remove threads that violate this.
