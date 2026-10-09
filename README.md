# Rheono Security Check

A free, read-only security check for your own web app or API, packaged as an
[agent skill](https://skills.sh) for OpenClaw, Claude Code, Codex, Cursor and
other agents.

Ask your agent to check your site. The skill submits it to
[Rheono](https://rheono.dev), a researcher confirms it, and a report is
emailed to you. No API key, no account, nothing to install on your side.

## Consent

Only run this on domains **you own or have written authorization to test**.
The check is read-only, but it is still scanning live infrastructure — the
skill asks for confirmation before it submits anything.

## Install

```sh
# any agent (skills.sh)
npx skills add rheono/security-check

# OpenClaw
openclaw skills install @rheono/security-check
```

## Use

Ask your agent:

> run a security check on example.com, send the report to me@example.com

The agent confirms you own the domain, then submits one request:

```sh
curl -sS -X POST https://rheono.dev/api/check-request \
  -H 'content-type: application/json' \
  -d '{"domain": "example.com", "email": "me@example.com"}'
```

`{"ok":true,...}` means it's queued; the report arrives by email.

## What it is and is not

- **Is:** a single request to the public `check-request` endpoint. The skill
  carries no scanner, no local probing, no credentials.
- **Is not:** a deep engagement. A continuous standing hunt — validated
  findings, PoC, written scope, re-checks — is what
  [Rheono](https://rheono.dev) runs for customers.

## Repo layout

```
skills/security-check/SKILL.md   the skill
```
