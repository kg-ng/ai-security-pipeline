import { readFile, readdir } from "node:fs/promises";
import { join, relative, extname } from "node:path";
import type { Finding, Severity } from "../types.js";

const IGNORED_DIRS = new Set([
  "node_modules",
  ".git",
  "dist",
  "build",
  "coverage",
  ".next",
  ".ai-security-pipeline",
]);
const SCANNABLE_EXTENSIONS = new Set([".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"]);

/**
 * Test files intentionally contain "bad" fixtures to exercise the scanners
 * themselves — scanning them would make this tool perpetually fail its own
 * CI, so they're excluded by default.
 */
const TEST_FILE_PATTERN = /\.(?:test|spec)\.[jt]sx?$|(?:^|\/)__tests__\//;

interface CodeRule {
  name: string;
  severity: Severity;
  regex: RegExp;
  recommendation: string;
}

/**
 * Original, in-house static analysis rules for risky JS/TS patterns — not a
 * wrapper around a third-party SAST tool. Kept intentionally small and
 * high-signal to limit false positives; each rule targets a specific,
 * well-known vulnerability class.
 */
const CODE_RULES: CodeRule[] = [
  {
    name: "Dynamic code execution (eval-style) — arbitrary code execution risk",
    severity: "high",
    regex: /\beval\s*\(|new\s+Function\s*\(/g,
    recommendation: "Avoid dynamic code execution helpers; parse/validate input explicitly instead of executing it as code.",
  },
  {
    name: "Command execution with interpolated input — possible command injection",
    severity: "critical",
    regex: /\b(?:exec|execSync|spawn)\s*\(\s*`[^`]*\$\{/g,
    recommendation: "Avoid building shell commands via string interpolation; pass arguments as an array (e.g. execFile) instead.",
  },
  {
    name: "TLS certificate verification disabled",
    severity: "critical",
    regex: /rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['"]?0['"]?/g,
    recommendation: "Never disable TLS verification in production code; fix the underlying certificate issue instead.",
  },
  {
    name: "SQL query built via string interpolation — possible SQL injection",
    severity: "high",
    regex: /`[^`]*\b(?:SELECT|INSERT|UPDATE|DELETE)\b[^`]*\$\{[^`]*`/gi,
    recommendation: "Use parameterized queries / prepared statements instead of interpolating values into SQL strings.",
  },
  {
    name: "Weak hashing algorithm (MD5/SHA1) used for security-sensitive data",
    severity: "medium",
    regex: /createHash\s*\(\s*['"](?:md5|sha1)['"]\s*\)/g,
    recommendation: "Use a modern algorithm (SHA-256+ for integrity, bcrypt/argon2/scrypt for passwords).",
  },
  {
    name: "Math.random() used in a security-sensitive context",
    severity: "medium",
    regex: /(?:token|secret|password|session|nonce|apikey|api_key)[A-Za-z0-9_]*\s*=[^;\n]*Math\.random\(\)/gi,
    recommendation: "Math.random() is not cryptographically secure; use crypto.randomBytes()/randomUUID() for secrets, tokens, or sessions.",
  },
];

async function collectFiles(dir: string, acc: string[]): Promise<void> {
  const entries = await readdir(dir, { withFileTypes: true });
  for (const entry of entries) {
    if (IGNORED_DIRS.has(entry.name)) continue;
    const fullPath = join(dir, entry.name);
    if (entry.isDirectory()) {
      await collectFiles(fullPath, acc);
    } else if (
      entry.isFile() &&
      SCANNABLE_EXTENSIONS.has(extname(entry.name)) &&
      !TEST_FILE_PATTERN.test(fullPath)
    ) {
      acc.push(fullPath);
    }
  }
}

/**
 * Walks the target directory's JS/TS source and flags risky code patterns
 * using a small set of original, hand-written detection rules (see
 * CODE_RULES above). This is a lightweight heuristic scanner, not a
 * full-blown SAST engine — it favors precision over exhaustive coverage.
 */
export async function runCodePatternScan(cwd: string): Promise<Finding[]> {
  const files: string[] = [];
  await collectFiles(cwd, files);

  const findings: Finding[] = [];
  for (const file of files) {
    let content: string;
    try {
      content = await readFile(file, "utf8");
    } catch {
      continue;
    }

    for (const rule of CODE_RULES) {
      const matches = content.match(rule.regex);
      if (matches && matches.length > 0) {
        findings.push({
          id: `code-${relative(cwd, file)}-${rule.name}`,
          source: "code-pattern-scan",
          title: rule.name,
          description: `Found ${matches.length} match(es) in ${relative(cwd, file)}. ${rule.recommendation}`,
          severity: rule.severity,
          location: relative(cwd, file),
        });
      }
    }
  }

  return findings;
}
