import { readFile, readdir } from "node:fs/promises";
import { join, relative } from "node:path";
import type { Finding } from "../types.js";

const IGNORED_DIRS = new Set(["node_modules", ".git", "dist", "build", "coverage", ".next", ".ai-security-pipeline"]);

/**
 * Test files intentionally contain "bad" fixtures to exercise the scanners
 * themselves — scanning them would make this tool perpetually fail its own
 * CI, so they're excluded by default.
 */
const TEST_FILE_PATTERN = /\.(?:test|spec)\.[jt]sx?$|(?:^|\/)__tests__\//;

/** Common high-signal secret patterns; intentionally conservative to limit false positives. */
const SECRET_PATTERNS: Array<{ name: string; regex: RegExp }> = [
  { name: "AWS Access Key ID", regex: /AKIA[0-9A-Z]{16}/g },
  { name: "Generic Private Key", regex: /-----BEGIN (?:RSA|EC|OPENSSH|PGP) PRIVATE KEY-----/g },
  { name: "GitHub Token", regex: /gh[pousr]_[A-Za-z0-9]{36,}/g },
  { name: "Slack Token", regex: /xox[baprs]-[A-Za-z0-9-]{10,}/g },
  { name: "Generic API Key Assignment", regex: /(?:api[_-]?key|secret|token)\s*[:=]\s*["'][A-Za-z0-9_\-/+]{20,}["']/gi },
];

async function collectFiles(dir: string, root: string, acc: string[]): Promise<void> {
  const entries = await readdir(dir, { withFileTypes: true });
  for (const entry of entries) {
    if (IGNORED_DIRS.has(entry.name)) continue;
    const fullPath = join(dir, entry.name);
    if (entry.isDirectory()) {
      await collectFiles(fullPath, root, acc);
    } else if (entry.isFile() && !TEST_FILE_PATTERN.test(fullPath)) {
      acc.push(fullPath);
    }
  }
}

/**
 * Walks the target directory and flags text that matches known secret
 * patterns. This is a lightweight heuristic scan (no entropy analysis) meant
 * to catch obvious leaked credentials, not a replacement for a dedicated
 * secret-scanning tool like gitleaks/trufflehog.
 */
export async function runSecretScan(cwd: string): Promise<Finding[]> {
  const files: string[] = [];
  await collectFiles(cwd, cwd, files);

  const findings: Finding[] = [];
  for (const file of files) {
    let content: string;
    try {
      content = await readFile(file, "utf8");
    } catch {
      continue; // binary or unreadable file
    }

    for (const { name, regex } of SECRET_PATTERNS) {
      const matches = content.match(regex);
      if (matches && matches.length > 0) {
        findings.push({
          id: `secret-${relative(cwd, file)}-${name}`,
          source: "secret-scan",
          title: `Potential ${name} committed to source`,
          description: `Found ${matches.length} match(es) resembling a ${name} in tracked source.`,
          severity: "critical",
          location: relative(cwd, file),
        });
      }
    }
  }

  return findings;
}
