# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in `theaios-agent-auth`, please report it responsibly.

**Do not open a public GitHub issue for security vulnerabilities.**

Instead, email **charafeddine@cohorte.co** with:

- A description of the vulnerability
- Steps to reproduce
- Potential impact

We will acknowledge your report within 48 hours and work with you to understand and address the issue before any public disclosure.

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | Yes       |

## Security Design

`theaios-agent-auth` is designed with security in mind:

- **No `eval()`** — policy conditions use a safe expression DSL with an explicit allowlist of operators
- **Atomic writes** — session and delegation state files use temp-file-then-rename to prevent corruption
- **Environment variable safety** — `${ENV_VAR}` interpolation only reads from the process environment, never executes
- **No network calls** — the library is fully local, no external dependencies at runtime beyond PyYAML, Click, and Rich
