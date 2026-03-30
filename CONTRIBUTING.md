# Contributing to theaios-agent-auth

Thank you for your interest in contributing! This guide will help you get started.

## Development Setup

```bash
# Clone the repository
git clone https://github.com/Cohorte-ai/agent-auth.git
cd agent-auth

# Create a virtual environment
python -m venv .venv
source .venv/bin/activate  # or .venv\Scripts\activate on Windows

# Install in editable mode with dev dependencies
pip install -e ".[dev]"
```

## Running Tests

```bash
# Run all tests
pytest tests/ -v

# Run only unit tests
pytest tests/ -v --ignore=tests/integration

# Run only integration tests
pytest tests/integration/ -v
```

## Code Quality

We enforce code quality with the following tools:

```bash
# Lint
ruff check src/ tests/

# Format
ruff format src/ tests/

# Type check
mypy src/
```

All three checks must pass before a PR can be merged.

## Pull Request Process

1. Fork the repository and create a branch from `main`.
2. Make your changes. Add or update tests as needed.
3. Ensure all tests pass and code quality checks are clean.
4. Write a clear PR description explaining **what** and **why**.
5. Submit the PR. A maintainer will review it.

## Reporting Issues

- Use [GitHub Issues](https://github.com/Cohorte-ai/agent-auth/issues) to report bugs or request features.
- For security vulnerabilities, see [SECURITY.md](SECURITY.md).

## License

By contributing, you agree that your contributions will be licensed under the Apache 2.0 License.
