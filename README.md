# Rheono Fleet Check

A read-only security check for your public web/API surface, packaged as an
[agent skill](https://skills.sh) for OpenClaw, Claude Code, Codex, Cursor and
75+ other agents.

It runs a ~30-second reconnaissance pass (GET/HEAD only, 1 rps, ≤300 requests,
same-root scope) and reports what an attacker's first sweep would see:
exposed secrets files, CORS reflection, open redirects, missing HSTS/CSP,
certificate expiry, debug endpoints, version disclosure, DMARC/SPF gaps.

## Consent (read this first)

Only run this on domains **you own or have written authorization to test**.
The probe is low-footprint and read-only, but it is still scanning someone's
infrastructure. The skill enforces a consent check before it runs.

## Install

```sh
# any agent (skills.sh)
npx skills add rheono/fleet-check

# OpenClaw
openclaw skills install @rheono/fleet-check
```

## Use

Ask your agent:

> run the fleet check on example.com

## What it checks

| Area | Checks |
|---|---|
| Secrets exposure | `.env`, `.git/config`, `.aws/credentials`, `.DS_Store`, `package.json` |
| Headers | HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy |
| CORS | `Access-Control-Allow-Origin` reflection |
| Redirects | open redirect on common params |
| TLS | certificate expiry, issuer, http→https |
| Debug surface | `/actuator`, `/debug`, `/graphql`, `/swagger.json`, `/_next/data` |
| DNS | A records, DMARC, SPF |

Findings are graded critical / high / medium / low / info. Output is a
markdown summary plus a `fleet-check-report.json` next to where you ran it.

## Limits

- Recon only: no logins, no auth bypass, no fuzzing, no mutations, no
  third-party hosts.
- A real engagement (deep hunt, full red team, validated findings with PoC)
  is what [Rheono](https://rheono.dev) does — with a written authorization.

## Repo layout

```
skills/fleet-check/SKILL.md           skill definition
skills/fleet-check/scripts/probe.mjs  the probe (zero dependencies, Node 18+)
```
