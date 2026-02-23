# Contributing to ZeroTrust-AI

Thank you for your interest in contributing to ZeroTrust-AI.

## Development Setup

```bash
git clone https://github.com/cwccie/zerotrust-ai.git
cd zerotrust-ai
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

## Running Tests

```bash
pytest
pytest --cov=zerotrust_ai --cov-report=term-missing
```

## Code Style

We use [Ruff](https://docs.astral.sh/ruff/) for linting:

```bash
ruff check src/ tests/
ruff format src/ tests/
```

## Pull Request Process

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/my-feature`)
3. Write tests for new functionality
4. Ensure all tests pass
5. Submit a pull request with a clear description

## Architecture

- `src/zerotrust_ai/behavioral/` — Behavioral analytics engine
- `src/zerotrust_ai/access/` — Adaptive access control
- `src/zerotrust_ai/microseg/` — Microsegmentation
- `src/zerotrust_ai/lateral/` — Lateral movement detection (GNN-based)
- `src/zerotrust_ai/risk/` — Composite risk scoring
- `src/zerotrust_ai/policy/` — YAML policy engine
- `src/zerotrust_ai/identity/` — Identity registry
- `src/zerotrust_ai/api/` — REST API
- `src/zerotrust_ai/dashboard/` — Web dashboard

## Security

If you discover a security vulnerability, please email corey@coreywade.com directly.
Do not open a public issue.

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
