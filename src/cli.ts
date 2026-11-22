#!/usr/bin/env node
import { Command, CommanderError, Option } from "commander";
import { writeFile } from "node:fs/promises";
import { createRequire } from "node:module";
import { join, resolve } from "node:path";
import { runDependencyAudit } from "./scanners/dependencyAudit.js";
import { runSecretScan } from "./scanners/secretScan.js";
import { runCodePatternScan } from "./scanners/codePatternScan.js";
import { listProjectFiles } from "./scanners/files.js";
import { triageFindings } from "./triage.js";
import { renderMarkdownReport } from "./report.js";
import { renderSarifReport } from "./sarif.js";
import { IGNORE_FILE_NAME, applyIgnoreList, loadIgnoreFile } from "./ignore.js";
import { SEVERITIES, hasBlockingFinding, parseFailOn } from "./gate.js";

/** Exit codes: 0 = passed, 1 = blocking findings, 2 = the scan itself failed. */
const EXIT_BLOCKING = 1;
const EXIT_ERROR = 2;

const { version } = createRequire(import.meta.url)("../package.json") as { version: string };

interface ScanCommandOptions {
  path: string;
  output?: string;
  format: "markdown" | "json" | "sarif";
  failOn: string;
  omitDev?: boolean;
  ignoreFile?: string;
}

const program = new Command();
program.exitOverride();

program
  .name("ai-security-pipeline")
  .description(
    "Scans a project for vulnerable dependencies, leaked secrets, and risky code patterns, then uses " +
      "an LLM (or a rule-based fallback) to triage findings and suggest fixes.",
  )
  .version(version);

program
  .command("scan")
  .description("Run the security scan and print/write a report.")
  .option("-p, --path <path>", "path to the project to scan", ".")
  .option("-o, --output <file>", "write the report to a file instead of stdout")
  .addOption(new Option("-f, --format <format>", "report format").choices(["markdown", "json", "sarif"]).default("markdown"))
  .addOption(
    new Option("--fail-on <severity>", "exit 1 if a finding at/above this severity is present")
      .choices([...SEVERITIES])
      .default("critical"),
  )
  .option("--omit-dev", "skip devDependencies in the dependency audit")
  .option("--ignore-file <file>", `file of finding ids to suppress (default: <path>/${IGNORE_FILE_NAME})`)
  .action(async (opts: ScanCommandOptions) => {
    const failOn = parseFailOn(opts.failOn);
    const cwd = resolve(opts.path);

    const files = await listProjectFiles(cwd);
    const [dependencyFindings, secretFindings, codePatternFindings] = await Promise.all([
      runDependencyAudit(cwd, { omitDev: opts.omitDev }),
      runSecretScan(cwd, { files }),
      runCodePatternScan(cwd, { files }),
    ]);

    const ignored = await loadIgnoreFile(opts.ignoreFile ? resolve(opts.ignoreFile) : join(cwd, IGNORE_FILE_NAME));
    const { kept, suppressed } = applyIgnoreList(
      [...dependencyFindings, ...secretFindings, ...codePatternFindings],
      ignored,
    );

    const triaged = await triageFindings(kept);
    const scannedAt = new Date().toISOString();
    const report =
      opts.format === "sarif"
        ? renderSarifReport(triaged, version)
        : opts.format === "json"
          ? JSON.stringify({ scannedAt, suppressed: suppressed.map((f) => f.id), findings: triaged }, null, 2)
          : renderMarkdownReport(triaged, scannedAt, { suppressed: suppressed.length });

    if (opts.output) {
      await writeFile(opts.output, report, "utf8");
    } else {
      console.log(report);
    }

    if (hasBlockingFinding(triaged, failOn)) {
      process.exitCode = EXIT_BLOCKING;
    }
  });

try {
  await program.parseAsync(process.argv);
} catch (err) {
  if (err instanceof CommanderError) {
    // Commander already printed the message; --help/--version exit 0.
    process.exitCode = err.exitCode === 0 ? 0 : EXIT_ERROR;
  } else {
    console.error(`ai-security-pipeline: ${err instanceof Error ? err.message : String(err)}`);
    process.exitCode = EXIT_ERROR;
  }
}
