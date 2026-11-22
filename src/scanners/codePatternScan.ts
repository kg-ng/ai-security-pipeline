import { join } from "node:path";
import type { Finding, Severity } from "../types.js";
import { describeLines, listProjectFiles, matchLines, readTextFile, type ScanOptions } from "./files.js";

const SCANNABLE_FILE = /\.(?:[cm]?[jt]s|[jt]sx)$/;

/** Minified bundles are generated code; findings in them are not actionable. */
const MINIFIED_FILE = /\.min\.[cm]?js$/;

/**
 * Test files intentionally contain "bad" fixtures to exercise the scanners
 * themselves — scanning them would make this tool perpetually fail its own
 * CI, so they're excluded by default. Paths are always `/`-separated.
 */
const TEST_FILE_PATTERN = /\.(?:test|spec)\.[cm]?[jt]sx?$|(?:^|\/)__tests__\//;

/** A match on a line that is only a comment is not executable code. */
const COMMENT_LINE = /^\s*(?:\/\/|\/\*|\*)/;

interface CodeRule {
  key: string;
  name: string;
  severity: Severity;
  regex: RegExp;
  /** Optional second-stage check on each regex match. */
  accept?: (match: string) => boolean;
  recommendation: string;
}

// SQL statement shapes. Quantifiers are bounded so a huge literal cannot cause quadratic backtracking.
const sqlStatement = (kw: (word: string) => string) =>
  `(?:${kw("SELECT")}\\s[^\`;]{1,500}?\\s${kw("FROM")}|${kw("INSERT")}\\s+${kw("INTO")}|` +
  `${kw("UPDATE")}\\s+[^\\s\`]{1,100}\\s+${kw("SET")}|${kw("DELETE")}\\s+${kw("FROM")})\\b`;
const SQL_UPPERCASE = new RegExp(`\\b${sqlStatement((w) => w)}`);
const SQL_LOWERCASE_LEADING = new RegExp(`^\`\\s*${sqlStatement((w) => w.toLowerCase())}`);

/**
 * True for a template literal that interpolates values into SQL. To avoid flagging UI text
 * such as `Select an option from ${list}`, keywords must be UPPERCASE anywhere in the literal,
 * or lowercase only when the literal starts with the statement.
 */
function isInterpolatedSql(literal: string): boolean {
  return literal.includes("${") && (SQL_UPPERCASE.test(literal) || SQL_LOWERCASE_LEADING.test(literal));
}

/**
 * Original, in-house static analysis rules for risky JS/TS patterns — not a
 * wrapper around a third-party SAST tool. Kept intentionally small and
 * high-signal to limit false positives; each rule targets a specific,
 * well-known vulnerability class.
 */
const CODE_RULES: CodeRule[] = [
  {
    key: "dynamic-code-execution",
    name: "Dynamic code execution (eval-style) — arbitrary code execution risk",
    severity: "high",
    // Not preceded by `.`/identifier chars, so `foo.eval(` and `myeval(` are not flagged.
    regex: /(?<![.\w$])eval\s*\(|\bnew\s+Function\s*\(/g,
    recommendation: "Avoid dynamic code execution helpers; parse/validate input explicitly instead of executing it as code.",
  },
  {
    key: "command-injection",
    name: "Command execution with interpolated input — possible command injection",
    severity: "critical",
    regex: /\b(?:exec|execSync)\s*\(\s*(?:`[^`]*\$\{|["'][^"'\n]*["']\s*\+)|\bspawn\s*\(\s*`[^`]*\$\{/g,
    recommendation: "Avoid building shell commands from strings; pass arguments as an array (e.g. execFile) instead.",
  },
  {
    key: "tls-verification-disabled",
    name: "TLS certificate verification disabled",
    severity: "critical",
    regex: /rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['"]?0['"]?/g,
    recommendation: "Never disable TLS verification in production code; fix the underlying certificate issue instead.",
  },
  {
    key: "sql-injection",
    name: "SQL query built via string interpolation — possible SQL injection",
    severity: "high",
    // Each template literal (linear scan); `isInterpolatedSql` then checks its contents.
    regex: /`[^`]*`/g,
    accept: isInterpolatedSql,
    recommendation: "Use parameterized queries / prepared statements instead of interpolating values into SQL strings.",
  },
  {
    key: "weak-hash",
    name: "Weak hashing algorithm (MD5/SHA1) used for security-sensitive data",
    severity: "medium",
    regex: /createHash\s*\(\s*['"](?:md5|sha1)['"]\s*\)/g,
    recommendation: "Use a modern algorithm (SHA-256+ for integrity, bcrypt/argon2/scrypt for passwords).",
  },
  {
    key: "insecure-randomness",
    name: "Math.random() used in a security-sensitive context",
    severity: "medium",
    regex: /(?:token|secret|password|session|nonce|apikey|api_key)[A-Za-z0-9_]{0,50}\s*=[^;\n]{0,200}Math\.random\(\)/gi,
    recommendation: "Math.random() is not cryptographically secure; use crypto.randomBytes()/randomUUID() for secrets, tokens, or sessions.",
  },
];

/**
 * Scans JS/TS source for risky code patterns using a small set of original,
 * hand-written detection rules (see CODE_RULES above). This is a lightweight
 * heuristic scanner, not a full-blown SAST engine — it favors precision over
 * exhaustive coverage. Test files, minified bundles, and comment lines are skipped.
 */
export async function runCodePatternScan(cwd: string, options: ScanOptions = {}): Promise<Finding[]> {
  const files = (options.files ?? (await listProjectFiles(cwd))).filter(
    (f) => SCANNABLE_FILE.test(f) && !MINIFIED_FILE.test(f) && !TEST_FILE_PATTERN.test(f),
  );

  const findings: Finding[] = [];
  for (const file of files) {
    const content = await readTextFile(join(cwd, file));
    if (content === null) continue;

    for (const rule of CODE_RULES) {
      const lines = matchLines(content, rule.regex, {
        skipLine: (line) => COMMENT_LINE.test(line),
        accept: rule.accept,
      });
      if (lines.length === 0) continue;
      findings.push({
        id: `code-${file}-${rule.key}`,
        source: "code-pattern-scan",
        ruleId: `code/${rule.key}`,
        title: rule.name,
        description: `Found ${lines.length} match(es) on ${describeLines(lines)} of ${file}.`,
        severity: rule.severity,
        location: `${file}:${lines[0]}`,
        file,
        line: lines[0],
        recommendation: rule.recommendation,
      });
    }
  }

  return findings;
}
