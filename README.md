# ai-security-pipeline

A generic, standalone security-scanning pipeline for Node/TypeScript projects.
Runs dependency-vulnerability and leaked-secret scans, then uses an LLM agent
(with a deterministic rule-based fallback) to triage findings by priority and
suggest remediations — as a CLI and as a drop-in GitHub Action.

## Why

Most CI security tooling produces a wall of findings with no prioritization.
This project adds an AI triage layer on top of standard scans so a team can
act on the top few critical/high items first, without requiring an LLM
provider to be configured (it degrades gracefully to severity-based rules).

## Features

- **Dependency audit** — wraps `npm audit` and normalizes results.
- **Secret scan** — lightweight pattern-based scan for common leaked
  credential formats (AWS keys, GitHub tokens, Slack tokens, private keys,
  generic API key assignments).
- **AI triage** — when `OPENAI_API_KEY` is set, an LLM re-ranks findings and
  writes a concise remediation suggestion per finding. Without a key, a
  rule-based fallback still ranks by severity so the pipeline always works.
- **Markdown report** — human-readable output for terminals, CI logs, or PR
  comments.
- **CI gate** — configurable `--fail-on <severity>` exit code for blocking
  merges on critical findings.

## Usage

```bash
npm install
npm run build

# Scan the current directory
node dist/cli.js scan

# Scan another path, write to a file, only fail on "high" or above
node dist/cli.js scan --path ../some-project --output report.md --fail-on high
```

### As a GitHub Action

See `.github/workflows/security-scan.yml` — runs on every pull request,
posts the Markdown report as a PR comment, and fails the check if a blocking
finding is present. Set the `OPENAI_API_KEY` repository secret to enable
LLM-based triage; omit it to use the rule-based fallback.

## Programmatic API

```ts
import { runDependencyAudit, runSecretScan, triageFindings, renderMarkdownReport } from "ai-security-pipeline";

const findings = [...(await runDependencyAudit(".")), ...(await runSecretScan("."))];
const triaged = await triageFindings(findings);
console.log(renderMarkdownReport(triaged, new Date().toISOString()));
```

## Development

```bash
npm install
npm run dev -- scan   # run the CLI via tsx without building
npm test              # vitest
npm run lint          # eslint
```

## Roadmap

- [ ] Auto-open remediation PRs for simple dependency bumps
- [ ] Pluggable scanners (Semgrep, Trivy, gitleaks) alongside the built-in ones
- [ ] SARIF output for GitHub code scanning integration

## License

MIT
