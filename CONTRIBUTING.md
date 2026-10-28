# Contributing

Thanks for helping. Contributions are accepted under the [Contributor License Agreement](CLA.md).

## Development setup

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
```

## Checks (the same ones CI runs)

```bash
ruff check .
mypy
python -m pytest                      # unit, adversarial, concurrency, CLI, MCP, end-to-end
bandit -c pyproject.toml -r agentauth
pip-audit --skip-editable
```

Redis and PostgreSQL tests are skipped unless you point them at servers (CI always runs them):

```bash
export AGENTAUTH_TEST_REDIS_URL=redis://localhost:6379/0
export AGENTAUTH_TEST_POSTGRES_URL=postgresql://postgres@localhost:5432/agentauth_test
python -m pytest -m "redis or postgres"
```

TypeScript verifier and cross-implementation test vectors:

```bash
python scripts/generate_test_vectors.py --check    # committed vectors match the Python code
cd ts && npm ci && npm test                        # build, then run the vectors and unit tests
```

## Guidelines

- **Security-relevant changes need a negative test**: show the attack being refused, not just the happy path.
- **Fail closed.** If a check can't be completed (a dependency is down, input is ambiguous), refuse.
- **Don't change wire formats silently.** Anything that changes what is signed, or how it's encoded, must update [docs/protocol.md](docs/protocol.md), the [changelog](CHANGELOG.md), and, where it isn't backward compatible, the version strings.
- **Changing a verification rule?** Change `scripts/generate_test_vectors.py` (add a vector for the new rule), regenerate with `python scripts/generate_test_vectors.py`, and update the TypeScript verifier in `ts/` in the same pull request. Never edit `test-vectors/*.json` by hand.
- **Keep docs in step with code**: README, protocol, threat model, operations guide, and `ts/README.md` for anything the TypeScript verifier does.
- Changing dependencies? Regenerate `deploy/requirements.lock` (see [operations](docs/operations.md#the-image)).
