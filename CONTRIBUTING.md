# Contributing to CNDS

Thank you for your interest in contributing! This guide will help you get started.

## Getting Started

1. Fork the repository
2. Clone your fork:
   ```bash
   git clone https://github.com/RobertoDeLaCamara/Cognitive-Intrusion-Detection-System.git
   cd Cognitive-Intrusion-Detection-System
   ```
3. Set up the development environment:
   ```bash
   python3 -m venv venv && source venv/bin/activate
   pip install -r requirements.txt
   cp .env.example .env
   ```
4. Start the infrastructure:
   ```bash
   docker-compose up -d
   ```

## Development Workflow

1. Create a branch: `git checkout -b feature/your-feature` or `git checkout -b fix/issue-description`
2. Make your changes
3. Run tests: `pytest tests/ -v`
4. Commit with a clear message: `git commit -m "feat: add new feature"`
5. Push and open a Pull Request

## Testing

```bash
pytest tests/ -v
pytest tests/ --cov=src --cov-report=term-missing
```

For integration tests, ensure Docker Compose services are running.

All new code should include tests. Aim to maintain or improve coverage.

## Running the Application

- **Main entry point:** `python main.py`
- **Dashboard:** See the `dashboard/` directory
- **Health check:** `GET /health`

## Code Style

- Follow PEP 8
- Use type hints for all function signatures
- Add docstrings to public functions and API endpoints
- Use async/await for FastAPI route handlers
- Follow PyTorch best practices (proper device handling, no silent shape mismatches)
- Use Scapy best practices for packet capture and parsing
- Use clear, descriptive variable names
- Place shared utilities in `src/features/utils.py` (e.g. `byte_entropy`) — avoid duplicating helper functions across modules
- Bound all in-memory dicts/caches with `MAX_TRACKED_IPS` or similar limits — never allow unbounded growth

## Commit Messages

Use [conventional commits](https://www.conventionalcommits.org/):
- `feat:` new feature
- `fix:` bug fix
- `docs:` documentation
- `test:` adding or updating tests
- `refactor:` code restructuring

## Reporting Issues

- Use the issue templates (Bug Report or Feature Request)
- Include steps to reproduce for bugs
- Mention OS, Python, and PyTorch versions when relevant
- Check existing issues before creating a new one

## Code of Conduct

Be respectful, constructive, and inclusive. We're all here to learn and build.
