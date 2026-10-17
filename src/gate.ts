import type { Finding, Severity } from "./types.js";

/** Ordered most to least severe. */
export const SEVERITIES: readonly Severity[] = ["critical", "high", "medium", "low", "info"];

/**
 * Validates a user-supplied `--fail-on` value. An unknown value must be an error:
 * silently treating it as "no threshold" would let a typo disable the CI gate.
 */
export function parseFailOn(value: string): Severity {
  const match = SEVERITIES.find((s) => s === value);
  if (!match) {
    throw new Error(`Invalid --fail-on "${value}". Expected one of: ${SEVERITIES.join(", ")}.`);
  }
  return match;
}

/** True when any finding is at or above the threshold severity. */
export function hasBlockingFinding(findings: Pick<Finding, "severity">[], failOn: Severity): boolean {
  const limit = SEVERITIES.indexOf(failOn);
  return findings.some((f) => SEVERITIES.indexOf(f.severity) <= limit);
}
