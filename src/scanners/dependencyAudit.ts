import { execFile } from "node:child_process";
import { promisify } from "node:util";
import type { Finding, Severity } from "../types.js";

const execFileAsync = promisify(execFile);

interface NpmAuditVulnerability {
  name: string;
  severity: string;
  via: Array<string | { title?: string; url?: string }>;
  range: string;
  fixAvailable?: boolean | { name: string; version: string };
}

/** npm audit reports "moderate" where our internal model uses "medium". */
function normalizeSeverity(raw: string): Severity {
  if (raw === "moderate") return "medium";
  if (raw === "critical" || raw === "high" || raw === "medium" || raw === "low" || raw === "info") {
    return raw;
  }
  return "info";
}

interface NpmAuditReport {
  vulnerabilities?: Record<string, NpmAuditVulnerability>;
}

/**
 * Runs `npm audit --json` against the target project and normalizes the
 * output into our internal Finding shape. Returns an empty list (rather than
 * throwing) when the project has no lockfile or no vulnerabilities, since
 * `npm audit` exits non-zero whenever vulnerabilities are found.
 */
export async function runDependencyAudit(cwd: string): Promise<Finding[]> {
  let stdout = "";
  try {
    const result = await execFileAsync("npm", ["audit", "--json"], { cwd, maxBuffer: 1024 * 1024 * 20 });
    stdout = result.stdout;
  } catch (err) {
    // npm audit exits with a non-zero code when it finds vulnerabilities —
    // the JSON report is still on stdout in that case.
    const maybeStdout = (err as { stdout?: string }).stdout;
    if (typeof maybeStdout === "string" && maybeStdout.length > 0) {
      stdout = maybeStdout;
    } else {
      return [];
    }
  }

  let report: NpmAuditReport;
  try {
    report = JSON.parse(stdout);
  } catch {
    return [];
  }

  const vulnerabilities = report.vulnerabilities ?? {};
  return Object.entries(vulnerabilities).map(([name, vuln]) => {
    const advisoryTitles = vuln.via
      .map((v) => (typeof v === "string" ? v : v.title))
      .filter((title): title is string => Boolean(title));

    return {
      id: `dep-${name}`,
      source: "dependency-audit",
      title: `Vulnerable dependency: ${name}`,
      description:
        advisoryTitles.length > 0
          ? advisoryTitles.join("; ")
          : `${name}@${vuln.range} has known vulnerabilities.`,
      severity: normalizeSeverity(vuln.severity),
      location: `package.json (${name})`,
    } satisfies Finding;
  });
}
