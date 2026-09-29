# Security Policy

## Reporting a vulnerability

Please **do not** open a public GitHub issue for a security vulnerability.

Instead, use GitHub's private vulnerability reporting for this repository:

https://github.com/mechubsec/rustproxmoxmcp/security/advisories/new

Include what you'd include in a bug report — affected version, reproduction steps, and impact — but keep it in the private report, not a public issue, PR, or discussion.

## Scope

This is an MCP server that authorizes and executes actions against Proxmox VE clusters on an operator's behalf. Vulnerability classes we especially want to hear about:

- Bearer-token or scope-check bypass (Stage 1: tool/device scope; Stage 2: guest grant and protection-union checks)
- A protected guest (by `protected_vmids` or `protected_tags`) reachable through a mutating or destructive tool despite the protection gate
- Anything that lets the plan → approve → apply change-set pipeline fire an `apply` without a valid, matching approval — including a digest/fingerprint check that can be bypassed or a stale preview substituted after approval
- TLS/CA-pinning bypass, or anything that weakens the "no insecure-skip-verify at any layer" guarantee
- Config or credential loader issues (`clusters.json`, `tokens.json`, `waivers.json`, secret files) that bypass the intended file-permission/ownership hardening
- Anything that could cause a Proxmox-changing action to fire without the caller's explicit intent

## Response

This is a community-maintained project. There's no guaranteed SLA. A human maintainer is responsible for triaging every report and for all disclosure and fix decisions.
