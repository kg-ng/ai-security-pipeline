import { readFile } from "node:fs/promises";
import type { Finding } from "./types.js";

/** Default ignore file name, looked up in the root of the scanned project. */
export const IGNORE_FILE_NAME = ".ai-security-ignore";

/**
 * Reads an ignore file: one finding id per line (as shown in the report), `#` starts a comment.
 * A missing file means "ignore nothing".
 */
export async function loadIgnoreFile(path: string): Promise<Set<string>> {
  let content: string;
  try {
    content = await readFile(path, "utf8");
  } catch (err) {
    if ((err as { code?: string }).code === "ENOENT") return new Set();
    throw err;
  }
  return new Set(
    content
      .split(/\r?\n/)
      .map((line) => line.replace(/(^|\s)#.*$/, "").trim())
      .filter((line) => line.length > 0),
  );
}

/** Splits findings into those to report and those suppressed by the ignore list. */
export function applyIgnoreList<T extends Finding>(findings: T[], ignored: Set<string>): { kept: T[]; suppressed: T[] } {
  const kept: T[] = [];
  const suppressed: T[] = [];
  for (const f of findings) (ignored.has(f.id) ? suppressed : kept).push(f);
  return { kept, suppressed };
}
