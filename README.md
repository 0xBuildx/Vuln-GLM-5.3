# Vuln

The live engine defaults to **GLM-5.3** (Z.ai) — the cybersecurity-tuned coding model. Each specialist hunts with tools (`read_file`, `grep`, `list_dir`) for several rounds before submitting findings.

No live URL. No crawl. No staging credentials. Point it at **your own folder** or a git remote.

## What you get

- **Create audit** — local path, git URL, or the bundled Harbor Shop demo
- **Fork-join agents** — mapper warms context, specialists hunt in parallel, chain synthesizer and adversarial verifier join
- **Orchestration** — enable, disable, or add custom specialists with their own hunt brief
- **Live activity** — watch agents read, think, and land findings
- **Issues** — severity, CWE, attack path, code evidence, remediation
- **Threat model** — services, trust boundaries, hunt leads
- **Markdown report** for each assessment
- **CLI** for CI / headless runs

Vuln complements SAST. It does not replace a live pentest (TLS, rate limits, DOM XSS as rendered).

## Quick start

```bash
cd /home/agent/vuln
# uv is easiest; python3 -m venv works if python3-venv is installed
uv venv && source .venv/bin/activate && uv pip install -r requirements.txt
# or, if the packages are already on your PYTHONPATH:
#   python3 -m pip install -r requirements.txt

# Demo — no API key. Audits the planted Harbor Shop vulns.
python -m vuln demo

# Console
python -m vuln serve
# open http://127.0.0.1:4173
```

Click **Run Harbor Shop demo** on the home screen, or create an audit with source `demo`.

## Live hunts (GLM-5.3)

Copy `.env.example` to `.env` and set a key from [api.z.ai](https://api.z.ai):

```bash
ZAI_API_KEY=...
ZAI_MODEL=glm-5.3
# Coding Plan endpoint (optional):
# ZAI_BASE_URL=https://api.z.ai/api/coding/paas/v4
```

Or paste the key in the console **Settings** page. Then:

```bash
python -m vuln audit /path/to/your/code --mode live --focus "multi-tenant isolation and billing"
python -m vuln serve   # Browse a folder → GLM hunts it
```

SpaceXAI / xAI is an optional fallback (`XAI_API_KEY`). Provider is Auto: GLM if keyed, else Grok.

## Orchestrate agents

Built-in pipeline:

| Phase | Agent | Job |
| --- | --- | --- |
| map | Mapper | Attack surface + threat model |
| specialist | Access control | Missing guards, privilege escalation |
| specialist | IDOR / BOLA | Object reads without owner/tenant scope |
| specialist | Business logic | Price tamper, workflow skip, webhooks |
| specialist | Auth & sessions | JWT pitfalls, hardcoded secrets |
| specialist | Injection | Reachable SQL/command/SSTI |
| specialist | Files, SSRF & uploads | Traversal, SSRF, pickle |
| specialist | Crypto & secrets | Weak crypto, real secrets in source |
| specialist | Agentic risks | Prompt injection / tool abuse, if present |
| join | Chain synthesizer | Multi-step privilege paths |
| join | Adversarial verifier | Drop findings the code does not prove |

On **Agents**, toggle any of those or add a specialist:

- `id` — slug (`billing-webhooks`)
- `focus` — the hunt brief the model sees

Custom agents run in the specialist fork with the same packed source and threat model.

## CLI

```bash
python -m vuln serve --port 4173
python -m vuln audit ./my-repo
python -m vuln audit https://github.com/org/repo --agents access,idor,logic --json
python -m vuln demo
```

## How it differs from SAST

SAST matches patterns (tainted param, risky API). Vuln follows references across files: a route that authenticates, a service that looks up by primary key only, an admin helper that exists and is never called. Findings are written as attacker paths with file:line evidence.

## Harbor Shop

`fixtures/harbor-shop` is a small multi-tenant store with planted, cross-file bugs (order IDOR, unused `require_admin`, client-supplied price, `alg=none`, path traversal, SQLi, unsigned webhook, mass assignment). Demo mode indexes the real tree and resolves evidence locators against those files.

## Layout

```
vuln/          orchestrator, ingest, agents, API
web/           audit console
fixtures/      Harbor Shop
data/          sqlite + cloned repos (gitignored)
```
