# ai-security-pipeline

A generic, standalone security-scanning pipeline for Node/TypeScript projects.
Runs dependency-vulnerability, leaked-secret, and risky-code-pattern scans, then uses an LLM agent
(with a deterministic rule-based fallback) to triage findings by priority and
suggest remediations — as a CLI and as a reusable GitHub workflow.

## Why

Most CI security tooling produces a wall of findings with no prioritization.
This project adds an AI triage layer on top of standard scans so a team can
act on the top few critical/high items first, without requiring an LLM
provider to be configured (it degrades gracefully to severity-based rules).

## Features

- **Dependency audit** — wraps `npm audit`, `pnpm audit`, or `yarn audit` (Yarn 1),
  picked from the project's lockfile, and normalizes results with a concrete fix
  version where one exists. Use `--omit-dev` to audit production dependencies only.
  If the audit cannot run (no lockfile, no network, unsupported Yarn 2+), the report
  says so instead of looking clean.
- **Secret scan** — lightweight pattern-based scan for common leaked credentials:
  AWS keys, private keys (PKCS#1/#8, OpenSSH, PGP), GitHub tokens (classic and
  fine-grained), Slack, OpenAI, Anthropic, Stripe live keys, Google API keys, npm
  tokens, JWTs, and generic API key assignments. Matched values are never echoed.
- **Code pattern scan** — original, in-house static analysis rules (not a
  wrapper around a third-party SAST tool) for risky JS/TS patterns: `eval()`
  / `new Function()`, command injection via interpolated or concatenated
  `exec`/`spawn` commands, disabled TLS verification, SQL built via string
  interpolation (UPPERCASE keywords anywhere, or lowercase at the start of the
  template literal, so UI text like `Select an option from ${list}` is not flagged),
  weak hashing (MD5/SHA1), and `Math.random()` used for tokens/secrets/sessions. Test files, minified bundles, and comment lines are skipped.
- **AI triage** — when `OPENAI_API_KEY` is set, an LLM re-ranks findings and
  writes a concise remediation suggestion per finding (model: `AI_SECURITY_MODEL`,
  default `gpt-4o-mini`; any OpenAI-compatible endpoint via `OPENAI_BASE_URL`).
  Without a key, or if the model call fails or returns invalid output, a
  rule-based fallback ranks by severity; the report states which was used.
  Priority is advisory only — the CI gate uses scanner-assigned severity, so the
  model can never hide a finding.
- **Reports** — Markdown (terminals, CI logs, PR comments), JSON, or SARIF 2.1.0
  (`--format sarif`, e.g. for GitHub code scanning). Findings include file and line.
- **CI gate** — configurable `--fail-on <severity>`.

### What gets scanned

Inside a git work tree, every tracked file plus untracked files that are not
gitignored. Outside git, the whole tree except `node_modules`, `.git`, and
`dist`/`build`/`coverage`/`.next` at the project root. Binary files and files
over 1 MiB are skipped.

### Suppressing findings

- **Inline:** add `ai-security-ignore` in a comment on the matching line or the
  line above it.
- **Ignore file:** list finding ids (shown under each finding in the report),
  one per line, in `.ai-security-ignore` at the scanned project's root (or pass
  `--ignore-file <file>`). `#` starts a comment. The report shows how many
  findings were suppressed.

Both can be used to hide real problems, so review changes to them like any
other security-sensitive code (e.g. with CODEOWNERS).

## Usage

```bash
npm install
npm run build

# Scan the current directory
node dist/cli.js scan

# Scan another path, write to a file, only fail on "high" or above
node dist/cli.js scan --path ../some-project --output report.md --fail-on high

# SARIF for code scanning, production dependencies only
node dist/cli.js scan --format sarif --output results.sarif --omit-dev
```

Exit codes: `0` no blocking findings, `1` a finding at or above `--fail-on`,
`2` the scan itself failed (bad arguments, unreadable path, …).

Requires Node.js 22 or later.

### As a reusable workflow (drop into any pipeline)

`.github/workflows/security-scan.yml` is a reusable workflow, so any repo can
use it as a security gate without copying code:

```yaml
# .github/workflows/security.yml in ANY other repo
name: Security
on: [pull_request]

jobs:
  ai-security-scan:
    # Pin to a commit SHA (or tag), and pass the same ref as pipeline-ref.
    uses: kg-ng/ai-security-pipeline/.github/workflows/security-scan.yml@<sha>
    permissions:
      contents: read
      pull-requests: write # to post the report comment
    with:
      pipeline-ref: <sha>
      path: "."
      fail-on: "high"
      # omit-dev: true
      # comment-on-pr: false
    secrets:
      OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}
```

The workflow writes the report to the job summary, uploads it as the
`ai-security-report` artifact, and posts it as a single PR comment that is
updated on every push (skipped for fork PRs, whose token is read-only). Set the
`OPENAI_API_KEY` secret to enable LLM-based triage; omit it to use the
rule-based fallback.

This repository's own CI (`.github/workflows/ci.yml`) runs typecheck, tests, and
build, then calls the reusable workflow with the scanner code from the commit
under test.

## Programmatic API

```ts
import {
  listProjectFiles,
  runDependencyAudit,
  runSecretScan,
  runCodePatternScan,
  triageFindings,
  renderMarkdownReport,
  hasBlockingFinding,
} from "ai-security-pipeline";

const files = await listProjectFiles(".");
const findings = [
  ...(await runDependencyAudit(".")),
  ...(await runSecretScan(".", { files })),
  ...(await runCodePatternScan(".", { files })),
];
const triaged = await triageFindings(findings);
console.log(renderMarkdownReport(triaged, new Date().toISOString()));
if (hasBlockingFinding(triaged, "high")) process.exitCode = 1;
```

## Development

```bash
npm install
npm run dev -- scan   # run the CLI via tsx without building
npm test              # vitest
npm run typecheck     # tsc --noEmit
```

## Roadmap

- [ ] Auto-open remediation PRs for simple dependency bumps
- [ ] More native code-pattern rules (path traversal, insecure deserialization, SSRF)
- [x] SARIF output (`--format sarif`)
- [ ] Upload SARIF to GitHub code scanning from the reusable workflow
- [ ] Yarn 2+ (Berry) dependency audit

## License

MIT
