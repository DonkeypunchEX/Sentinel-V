# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.x     | :white_check_mark: |

## Reporting a Vulnerability

Please report suspected vulnerabilities privately via
[GitHub Security Advisories](https://github.com/DonkeypunchEX/Sentinel-V/security/advisories/new)
rather than opening a public issue.

Include what you can: affected file or endpoint, reproduction steps, and
impact. You can expect an acknowledgement within a week; fixes land as
patch releases and are noted in the advisory.

## Scope notes

- The Python framework's response engine is simulation-safe by design —
  it logs and recommends actions but never mutates the host or network.
  Reports that it "fails to block" traffic are working as intended.
- `warehouse-app/` is a separate Node service with its own threat model;
  see `warehouse-app/README.md` for its security posture.
