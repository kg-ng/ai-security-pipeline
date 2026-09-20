import { z } from "zod";
import type { Finding, TriagedFinding } from "./types.js";

const SEVERITY_PRIORITY: Record<Finding["severity"], number> = {
  critical: 1,
  high: 2,
  medium: 3,
  low: 4,
  info: 5,
};

/** Schema for the LLM's JSON response — guards against malformed or hallucinated output. */
const TriageResponseSchema = z.array(
  z.object({
    id: z.string(),
    priority: z.number().int().min(1).max(5),
    recommendation: z.string().min(1),
  }),
);

/** Rule-based triage used whenever no LLM provider is configured, or as a fallback if the call fails. */
function ruleBasedTriage(findings: Finding[]): TriagedFinding[] {
  return findings.map((finding) => ({
    ...finding,
    priority: SEVERITY_PRIORITY[finding.severity],
    recommendation:
      finding.source === "dependency-audit"
        ? "Run `npm audit fix` (or bump the dependency manually) and re-scan."
        : finding.source === "secret-scan"
          ? "Rotate the exposed credential immediately and remove it from git history."
          : "Review and remediate the flagged code pattern before merging.",
  }));
}

/**
 * Triages findings by severity/priority and attaches a remediation
 * suggestion. Uses an LLM (OpenAI) when `OPENAI_API_KEY` is set for more
 * nuanced recommendations; otherwise falls back to deterministic
 * rule-based triage so the pipeline works with zero external dependencies.
 *
 * The LLM's response is validated against a strict schema — any malformed,
 * incomplete, or hallucinated output for a given finding falls back to the
 * rule-based recommendation for just that finding, rather than failing the
 * whole scan or silently trusting bad data.
 */
export async function triageFindings(findings: Finding[]): Promise<TriagedFinding[]> {
  if (findings.length === 0) return [];

  const apiKey = process.env.OPENAI_API_KEY;
  if (!apiKey) {
    return ruleBasedTriage(findings);
  }

  try {
    const { default: OpenAI } = await import("openai");
    const client = new OpenAI({ apiKey });

    const prompt = [
      "You are a security triage assistant. Given a JSON list of findings, return a JSON array",
      "(same order, same length) of objects with fields: id, priority (1-5, 1 = fix now), recommendation",
      "(one concise, actionable sentence). Only return the JSON array, no prose.",
      "",
      JSON.stringify(findings, null, 2),
    ].join("\n");

    const response = await client.chat.completions.create({
      model: process.env.AI_SECURITY_MODEL ?? "gpt-4o-mini",
      messages: [{ role: "user", content: prompt }],
      temperature: 0,
    });

    const raw = response.choices[0]?.message?.content ?? "[]";
    const parsedJson: unknown = JSON.parse(raw);
    const validation = TriageResponseSchema.safeParse(parsedJson);

    // If the LLM returned a shape we don't trust, fall back entirely rather
    // than mixing validated and unvalidated data.
    if (!validation.success) {
      return ruleBasedTriage(findings);
    }

    const byId = new Map(validation.data.map((p) => [p.id, p]));
    const fallback = ruleBasedTriage(findings);
    const fallbackById = new Map(fallback.map((f) => [f.id, f]));

    return findings.map((finding) => {
      const triage = byId.get(finding.id);
      const ruleBased = fallbackById.get(finding.id)!;
      return {
        ...finding,
        priority: triage?.priority ?? ruleBased.priority,
        recommendation: triage?.recommendation ?? ruleBased.recommendation,
      };
    });
  } catch {
    // Any LLM/network/parsing failure should never break the pipeline — fall back.
    return ruleBasedTriage(findings);
  }
}
