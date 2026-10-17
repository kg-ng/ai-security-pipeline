import { execFile } from "node:child_process";
import { existsSync } from "node:fs";
import { join } from "node:path";
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
  error?: { code?: string; summary?: string };
}

/**
 * A scan that could not run must not look like a clean scan. This surfaces the
 * failure in the report (medium: visible, but does not block unless the caller
 * lowers `--fail-on`), instead of returning an empty list that reads as "no findings".
 */
function auditUnavailable(reason: string): Finding[] {
  return [
    {
      id: "dep-audit-unavailable",
      source: "dependency-audit",
      title: "Dependency audit could not run",
      description: `${reason} Vulnerable dependencies were NOT checked.`,
      severity: "medium",
      location: "package.json",
    },
  ];
}

/**
 * Runs `npm audit --json` against the target project and normalizes the
 * output into our internal Finding shape. `npm audit` exits non-zero whenever
 * vulnerabilities are found, so a non-zero exit with a JSON report is normal.
 * A project without a package.json is not a Node project and is skipped; any
 * other reason the audit could not run is reported as a finding.
 */
export async function runDependencyAudit(cwd: string): Promise<Finding[]> {
  if (!existsSync(join(cwd, "package.json"))) return [];

  let stdout = "";
  try {
    const result = await execFileAsync("npm", ["audit", "--json"], {
      cwd,
      maxBuffer: 1024 * 1024 * 20,
      shell: process.platform === "win32", // npm is npm.cmd on Windows; the args are constants
    });
    stdout = result.stdout;
  } catch (err) {
    const maybeStdout = (err as { stdout?: string }).stdout;
    if (typeof maybeStdout === "string" && maybeStdout.length > 0) {
      stdout = maybeStdout;
    } else {
      return auditUnavailable(`npm audit failed to run (${(err as Error).message.split("\n")[0]}).`);
    }
  }

  let report: NpmAuditReport;
  try {
    report = JSON.parse(stdout);
  } catch {
    return auditUnavailable("npm audit did not return valid JSON.");
  }

  if (report.error) {
    const why = report.error.summary ?? report.error.code ?? "unknown error";
    return auditUnavailable(`npm audit reported: ${why}`);
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
