import { execFile } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { promisify } from "node:util";
import type { Finding, Severity } from "../types.js";

const execFileAsync = promisify(execFile);

const SEVERITY_RANK: Record<Severity, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

export interface DependencyAuditOptions {
  /** Only audit production dependencies (skip devDependencies). */
  omitDev?: boolean;
}

interface NpmAuditVulnerability {
  name: string;
  severity: string;
  via: Array<string | { title?: string; url?: string }>;
  range: string;
  fixAvailable?: boolean | { name: string; version: string; isSemVerMajor?: boolean };
}

interface NpmAuditReport {
  vulnerabilities?: Record<string, NpmAuditVulnerability>;
  error?: { code?: string; summary?: string };
}

/** The npm v6 advisory shape, still emitted by `pnpm audit --json` and `yarn audit --json` (Yarn 1). */
interface LegacyAdvisory {
  module_name: string;
  severity: string;
  title?: string;
  patched_versions?: string;
}

/** npm audit reports "moderate" where our internal model uses "medium". */
function normalizeSeverity(raw: string): Severity {
  if (raw === "moderate") return "medium";
  if (raw === "critical" || raw === "high" || raw === "medium" || raw === "low" || raw === "info") {
    return raw;
  }
  return "info";
}

/**
 * A scan that could not run must not look like a clean scan. This surfaces the
 * failure in the report (medium: visible, but does not block unless the caller
 * lowers `--fail-on`), instead of returning an empty list that reads as "no findings".
 */
function auditUnavailable(reason: string, recommendation: string): Finding[] {
  return [
    {
      id: "dep-audit-unavailable",
      source: "dependency-audit",
      ruleId: "dependency/audit-unavailable",
      title: "Dependency audit could not run",
      description: `${reason} Vulnerable dependencies were NOT checked.`,
      severity: "medium",
      location: "package.json",
      file: "package.json",
      recommendation,
    },
  ];
}

const FIX_SETUP_HINT =
  "Commit a lockfile (package-lock.json, pnpm-lock.yaml, or yarn.lock), make sure the registry is reachable from CI, and re-run the scan.";

/** Runs a command and returns its stdout. Audit tools exit non-zero when vulnerabilities exist, so that is not an error. */
async function runAuditCommand(cmd: string, args: string[], cwd: string): Promise<{ stdout: string } | { error: string }> {
  try {
    const result = await execFileAsync(cmd, args, {
      cwd,
      maxBuffer: 1024 * 1024 * 50,
      shell: process.platform === "win32", // npm/pnpm/yarn are .cmd shims on Windows; the args are constants
    });
    return { stdout: result.stdout };
  } catch (err) {
    const maybeStdout = (err as { stdout?: string }).stdout;
    if (typeof maybeStdout === "string" && maybeStdout.length > 0) return { stdout: maybeStdout };
    if ((err as { code?: string }).code === "ENOENT") return { error: `\`${cmd}\` is not installed.` };
    return { error: `\`${cmd} ${args[0]}\` failed to run (${(err as Error).message.split("\n")[0]}).` };
  }
}

function npmRecommendation(vuln: NpmAuditVulnerability): string {
  const fix = vuln.fixAvailable;
  if (fix && typeof fix === "object") {
    const major = fix.isSemVerMajor ? " (a semver-major upgrade — check for breaking changes)" : "";
    return `Upgrade ${fix.name} to ${fix.version}${major}, then re-scan.`;
  }
  if (fix === true) return "Run `npm audit fix` to update the vulnerable package within its allowed range, then re-scan.";
  return `No fix is available for ${vuln.name} yet; replace the package or mitigate the advisory, and track it for a patch.`;
}

async function runNpmAudit(cwd: string, omitDev: boolean): Promise<Finding[]> {
  const result = await runAuditCommand("npm", ["audit", "--json", ...(omitDev ? ["--omit=dev"] : [])], cwd);
  if ("error" in result) return auditUnavailable(result.error, FIX_SETUP_HINT);

  let report: NpmAuditReport;
  try {
    report = JSON.parse(result.stdout);
  } catch {
    return auditUnavailable("npm audit did not return valid JSON.", FIX_SETUP_HINT);
  }

  if (report.error) {
    const why = report.error.summary ?? report.error.code ?? "unknown error";
    return auditUnavailable(`npm audit reported: ${why}`, FIX_SETUP_HINT);
  }

  return Object.entries(report.vulnerabilities ?? {}).map(([name, vuln]) => {
    const advisoryTitles = vuln.via
      .map((v) => (typeof v === "string" ? v : v.title))
      .filter((title): title is string => Boolean(title));

    return dependencyFinding(
      name,
      normalizeSeverity(vuln.severity),
      advisoryTitles.length > 0 ? advisoryTitles.join("; ") : `${name}@${vuln.range} has known vulnerabilities.`,
      npmRecommendation(vuln),
    );
  });
}

function dependencyFinding(name: string, severity: Severity, description: string, recommendation: string): Finding {
  return {
    id: `dep-${name}`,
    source: "dependency-audit",
    ruleId: "dependency/vulnerable-package",
    title: `Vulnerable dependency: ${name}`,
    description,
    severity,
    location: `package.json (${name})`,
    file: "package.json",
    recommendation,
  };
}

/** `>=1.2.3` and `>=1.4.0` collapse to `>=1.4.0`; anything more complex is listed as-is. */
function combinePatchedRanges(ranges: string[]): string {
  const minimums = ranges.map((r) => /^>=\s*(\d+)\.(\d+)\.(\d+)$/.exec(r.trim()));
  if (minimums.some((m) => m === null)) return ranges.join(" and ");
  const highest = (minimums as RegExpExecArray[])
    .map((m) => [Number(m[1]), Number(m[2]), Number(m[3])])
    .reduce((a, b) => (a[0] - b[0] || a[1] - b[1] || a[2] - b[2]) >= 0 ? a : b);
  return `>=${highest.join(".")}`;
}

/** Groups legacy advisories into one finding per package, at the package's worst severity. */
export function findingsFromLegacyAdvisories(advisories: LegacyAdvisory[]): Finding[] {
  const byPackage = new Map<string, LegacyAdvisory[]>();
  for (const advisory of advisories) {
    byPackage.set(advisory.module_name, [...(byPackage.get(advisory.module_name) ?? []), advisory]);
  }

  return [...byPackage].map(([name, list]) => {
    const severity = list
      .map((a) => normalizeSeverity(a.severity))
      .reduce((worst, s) => (SEVERITY_RANK[s] < SEVERITY_RANK[worst] ? s : worst), "info" as Severity);
    const titles = [...new Set(list.map((a) => a.title).filter((t): t is string => Boolean(t)))];
    const patched = [...new Set(list.map((a) => a.patched_versions).filter((p): p is string => Boolean(p) && p !== "<0.0.0"))];
    const hasUnpatched = list.some((a) => !a.patched_versions || a.patched_versions === "<0.0.0");
    return dependencyFinding(
      name,
      severity,
      titles.length > 0 ? titles.join("; ") : `${name} has known vulnerabilities.`,
      patched.length === 0 || hasUnpatched
        ? `No fix is available for every advisory on ${name} yet; replace the package or mitigate the advisory.`
        : `Upgrade ${name} to a version matching ${combinePatchedRanges(patched)}, then re-scan.`,
    );
  });
}

async function runPnpmAudit(cwd: string, omitDev: boolean): Promise<Finding[]> {
  const result = await runAuditCommand("pnpm", ["audit", "--json", ...(omitDev ? ["--prod"] : [])], cwd);
  if ("error" in result) return auditUnavailable(result.error, FIX_SETUP_HINT);

  let report: { advisories?: Record<string, LegacyAdvisory>; error?: { code?: string; message?: string } };
  try {
    report = JSON.parse(result.stdout);
  } catch {
    return auditUnavailable("pnpm audit did not return valid JSON.", FIX_SETUP_HINT);
  }
  if (report.error || !report.advisories) {
    return auditUnavailable(`pnpm audit reported: ${report.error?.message ?? report.error?.code ?? "no advisory data"}`, FIX_SETUP_HINT);
  }
  return findingsFromLegacyAdvisories(Object.values(report.advisories));
}

async function runYarnClassicAudit(cwd: string, omitDev: boolean): Promise<Finding[]> {
  const result = await runAuditCommand("yarn", ["audit", "--json", ...(omitDev ? ["--groups", "dependencies"] : [])], cwd);
  if ("error" in result) return auditUnavailable(result.error, FIX_SETUP_HINT);

  const advisories: LegacyAdvisory[] = [];
  let sawSummary = false;
  for (const line of result.stdout.split("\n")) {
    if (!line.trim()) continue;
    try {
      const event = JSON.parse(line) as { type?: string; data?: { advisory?: LegacyAdvisory } };
      if (event.type === "auditAdvisory" && event.data?.advisory) advisories.push(event.data.advisory);
      if (event.type === "auditSummary") sawSummary = true;
    } catch {
      // yarn mixes in non-JSON progress lines
    }
  }
  if (!sawSummary) return auditUnavailable("yarn audit did not return an audit summary.", FIX_SETUP_HINT);
  return findingsFromLegacyAdvisories(advisories);
}

/**
 * Audits the target project's dependencies with the package manager its lockfile
 * belongs to (npm, pnpm, or Yarn 1) and normalizes the output into Findings.
 * A project without a package.json is not a Node project and is skipped; any
 * other reason the audit could not run is reported as a finding.
 */
export async function runDependencyAudit(cwd: string, options: DependencyAuditOptions = {}): Promise<Finding[]> {
  if (!existsSync(join(cwd, "package.json"))) return [];
  const omitDev = options.omitDev ?? false;

  if (existsSync(join(cwd, "package-lock.json")) || existsSync(join(cwd, "npm-shrinkwrap.json"))) {
    return runNpmAudit(cwd, omitDev);
  }
  if (existsSync(join(cwd, "pnpm-lock.yaml"))) {
    return runPnpmAudit(cwd, omitDev);
  }
  const yarnLock = join(cwd, "yarn.lock");
  if (existsSync(yarnLock)) {
    if (readFileSync(yarnLock, "utf8").includes("# yarn lockfile v1")) return runYarnClassicAudit(cwd, omitDev);
    return auditUnavailable(
      "Yarn 2+ (Berry) projects are not supported yet.",
      "Run `yarn npm audit` in CI for this project, or open an issue to add Yarn Berry support.",
    );
  }
  // No lockfile: let npm explain (it reports ENOLOCK), which surfaces as "could not run".
  return runNpmAudit(cwd, omitDev);
}
