# Changelog

## 1.1.0

- Added AST-based checks for Python `eval`/`exec`, `subprocess` with `shell=True`, and YAML loading without an explicit safe loader.
- Added MCP/agent JSON checks for shell-wrapped server startup, cleartext HTTP endpoints, wildcard tool scopes, token passthrough, disabled approval flags, and likely hardcoded credentials.
- Redacted likely secrets from finding evidence, including evidence attached to unrelated findings in the same scanned file.
- Added a JSON stdout mode and `--fail-on` severity threshold for CI use. JSON agent/MCP configuration is supported; individual files are limited to 10 MiB. Path containment now checks canonical path components instead of string prefixes.
- Corrected the installed console entrypoint and made generic CrewAI `process()`/`kickoff()` detection High rather than inherently Critical.
- Hardened CI with read-only token permissions, immutable action references, Python 3.10/3.12/3.13 coverage, and no unnecessary coverage-upload action.
- Added regression coverage and documented the static-analysis boundary in `docs/THREAT_MODEL.md`.
