// Which node an agent's request speaks for.

import type { Env } from "./types.ts";

function sameSecret(a: string, b: string): boolean {
  const x = new TextEncoder().encode(a);
  const y = new TextEncoder().encode(b);
  if (x.length !== y.length) return false;
  let diff = 0;
  for (let i = 0; i < x.length; i++) diff |= x[i]! ^ y[i]!;
  return diff === 0;
}

// Which node a bearer token speaks for. Every entry is compared, so the time taken
// does not say which one matched.
export function nodeFor(env: Partial<Pick<Env, "AGENT_TOKENS">>, header: string | null): string | null {
  const token = /^Bearer (.+)$/.exec(header ?? "")?.[1];
  if (!token) return null;
  let node: string | null = null;
  for (const [known, name] of Object.entries(JSON.parse(env.AGENT_TOKENS || "{}") as Record<string, string>)) {
    if (sameSecret(known, token)) node = name;
  }
  return node;
}
