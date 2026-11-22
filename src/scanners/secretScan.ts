import { join } from "node:path";
import type { Finding, Severity } from "../types.js";
import { describeLines, listProjectFiles, matchLines, readTextFile, type ScanOptions } from "./files.js";

// Test files are scanned too: real tokens are often pasted into tests. Fixtures that
// need a fake secret should build it at runtime (e.g. "AKIA" + "...") so the source
// file itself does not contain a match.

interface SecretPattern {
  key: string;
  name: string;
  regex: RegExp;
  severity: Severity;
}

/**
 * Common high-signal secret patterns; intentionally conservative to limit false positives.
 * Length quantifiers are fixed or bounded: a pattern only needs to see a token's prefix, and
 * unbounded runs could backtrack quadratically on adversarial input.
 */
const SECRET_PATTERNS: SecretPattern[] = [
  { key: "aws-access-key", name: "AWS Access Key ID", regex: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g, severity: "critical" },
  {
    key: "private-key",
    name: "Private Key",
    // PKCS#1 (RSA/EC/DSA), PKCS#8 (plain and encrypted), OpenSSH, and PGP key blocks.
    regex: /-----BEGIN (?:(?:RSA|EC|DSA|OPENSSH|ENCRYPTED|PGP) )?PRIVATE KEY(?: BLOCK)?-----/g,
    severity: "critical",
  },
  { key: "github-token", name: "GitHub Token", regex: /\bgh[pousr]_[A-Za-z0-9]{36}/g, severity: "critical" },
  { key: "github-fine-grained-pat", name: "GitHub Fine-Grained Token", regex: /\bgithub_pat_[A-Za-z0-9_]{40}/g, severity: "critical" },
  { key: "slack-token", name: "Slack Token", regex: /\bxox[baprs]-[A-Za-z0-9-]{10}/g, severity: "critical" },
  {
    key: "openai-api-key",
    name: "OpenAI API Key",
    regex: /\bsk-(?:(?:proj|svcacct|admin)-[A-Za-z0-9_-]{40}|[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20})/g,
    severity: "critical",
  },
  { key: "anthropic-api-key", name: "Anthropic API Key", regex: /\bsk-ant-[a-z]{1,10}\d{2}-[A-Za-z0-9_-]{40}/g, severity: "critical" },
  { key: "stripe-live-key", name: "Stripe Live Secret Key", regex: /\b[rs]k_live_[A-Za-z0-9]{20}/g, severity: "critical" },
  { key: "google-api-key", name: "Google API Key", regex: /\bAIza[0-9A-Za-z_-]{35}/g, severity: "critical" },
  { key: "npm-token", name: "npm Access Token", regex: /\bnpm_[A-Za-z0-9]{36}\b/g, severity: "critical" },
  {
    key: "jwt",
    name: "JSON Web Token",
    regex: /\beyJ[A-Za-z0-9_-]{10,4096}\.eyJ[A-Za-z0-9_-]{10,4096}\.[A-Za-z0-9_-]{10}/g,
    severity: "high",
  },
  {
    key: "generic-api-key",
    name: "Generic API Key Assignment",
    regex: /(?:api[_-]?key|secret|token)\s*[:=]\s*["'][A-Za-z0-9_\-/+]{20,4096}["']/gi,
    severity: "critical",
  },
];

/**
 * Flags text that matches known secret patterns. This is a lightweight heuristic
 * scan (no entropy analysis) meant to catch obvious leaked credentials, not a
 * replacement for a dedicated secret-scanning tool like gitleaks/trufflehog.
 * Binary files and files over `MAX_FILE_BYTES` are skipped.
 */
export async function runSecretScan(cwd: string, options: ScanOptions = {}): Promise<Finding[]> {
  const files = options.files ?? (await listProjectFiles(cwd));

  const findings: Finding[] = [];
  for (const file of files) {
    const content = await readTextFile(join(cwd, file));
    if (content === null) continue;

    for (const { key, name, regex, severity } of SECRET_PATTERNS) {
      const lines = matchLines(content, regex);
      if (lines.length === 0) continue;
      findings.push({
        id: `secret-${file}-${key}`,
        source: "secret-scan",
        ruleId: `secret/${key}`,
        title: `Potential ${name} committed to source`,
        // Never include the matched value: the report is posted publicly on PRs.
        description: `Found ${lines.length} match(es) resembling a ${name} on ${describeLines(lines)}.`,
        severity,
        location: `${file}:${lines[0]}`,
        file,
        line: lines[0],
        recommendation:
          "Rotate the exposed credential immediately, remove it from git history, and load it from a secret store or environment variable.",
      });
    }
  }

  return findings;
}
