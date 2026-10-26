# Security policy

AgentGuard is security software, so we treat vulnerabilities in it with priority.

## Reporting a vulnerability

**Do not open a public issue.** Report privately through
[GitHub private vulnerability reporting](https://github.com/Alexm2025/agentguard/security/advisories/new).

Please include the affected version or commit, the component (SDK, MCP gateway, LLM gateway,
control plane, dashboard, `ee/`), reproduction steps, and the impact you observed.

What to expect:

| Step | Target |
|---|---|
| Acknowledgement | 3 business days |
| Initial assessment and severity | 10 business days |
| Fix for critical/high issues | 30 days, coordinated disclosure afterwards |

We credit reporters in the release notes unless you prefer otherwise.

## Scope

In scope: bypasses of policy enforcement or taint tracking that the documented threat model says
AgentGuard prevents; authentication, authorization or tenant-isolation flaws in the control plane
and gateways; audit-log tampering that verification does not detect; secret leakage into logs,
events or exports; injection (SQL, template, header) and CSRF/XSS in the dashboard.

Out of scope: prompt-injection payloads that evade the detectors *without* bypassing a policy rule
(detection is probabilistic; please still share them as ordinary issues so we can improve the
models), denial of service from unrealistic traffic volumes, and issues in third-party dependencies
that have no exploitable path in AgentGuard (report those upstream).

## Supported versions

Only the latest minor release receives security fixes during the 0.x series.

## Hardening checklist for operators

- Set `AGENTGUARD_ENV=production`, a random `AGENTGUARD_SECRET_KEY` (>= 32 chars) and serve over TLS.
- Use scoped API keys (`ingest` for agents and gateways); keep `admin` keys out of agent hosts.
- Run gateways with `auth.mode: static` or `control_plane`; never `none` outside development.
- Use Postgres and Redis in production, and export the audit log (or its head hash) to your SIEM.
