# Contributing

See also: [CONTRIBUTING.md](https://github.com/RobertoDeLaCamara/Cognitive-Intrusion-Detection-System/blob/main/CONTRIBUTING.md) in the repository root.

## Development Setup

1. Fork and clone the repository
2. Create a virtual environment and install dependencies:
   ```bash
   python3 -m venv venv && source venv/bin/activate
   pip install -r requirements.txt
   cp .env.example .env
   ```
3. Start infrastructure (optional): `docker-compose up -d`

## Workflow

1. Create a branch: `git checkout -b feature/your-feature` or `git checkout -b fix/issue-description`
2. Make your changes
3. Run tests: `pytest tests/ -v`
4. Commit with a clear message using [conventional commits](https://www.conventionalcommits.org/)
5. Push and open a Pull Request

## Commit Message Prefixes

| Prefix | Use |
|---|---|
| `feat:` | New feature |
| `fix:` | Bug fix |
| `docs:` | Documentation |
| `test:` | Adding or updating tests |
| `refactor:` | Code restructuring |

## Code Style

- Follow PEP 8
- Use type hints for all function signatures
- Add docstrings to public functions and API endpoints
- Use `async/await` for FastAPI route handlers
- Place shared utilities in `src/features/utils.py` — avoid duplicating helpers
- Bound all in-memory dicts/caches with `MAX_TRACKED_IPS` or similar limits — never allow unbounded growth
- Use clear, descriptive variable names

## Issue Templates

The repository includes issue templates for Bug Reports and Feature Requests in `.github/ISSUE_TEMPLATE/`. A Pull Request template is also provided at `.github/PULL_REQUEST_TEMPLATE.md`.

## Code of Conduct

Be respectful, constructive, and inclusive.
