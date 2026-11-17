// The Worker's HTTP surface: who is asking, and which of the pipeline's three questions
// it is. `pipeline` is the Durable Object's stub (src/index.ts) or, under `node --test`,
// the Pipeline itself.
//
//   POST /webhook/github   GitHub's deliveries, checked against the App's webhook secret
//   POST /agent/sync       a node's report, answered with what it should run; a bearer
//                          token per node (AGENT_TOKENS), held open while nothing changes
//   POST /agent/token      the same bearer token; answered with read-only installation
//                          tokens for the site's repositories (src/access.ts). The body
//                          is not read: nothing a node says decides what it may read.

import type { TokensAnswer } from "./access.ts";
import { nodeFor } from "./auth.ts";
import type { Report, SyncAnswer } from "./core.ts";
import { verifySignature } from "./github.ts";
import type { Env, Thrown } from "./types.ts";

// The pipeline as it is asked here: the Durable Object's stub, or the Pipeline.
export interface Asked {
  webhook(event: string | null, payload: unknown): Promise<string>;
  sync(node: string, report: Report): Promise<SyncAnswer>;
  tokens(node: string): Promise<TokensAnswer>;
}

const json = (body: unknown, status = 200) => Response.json(body, { status });

export async function handle(
  request: Request,
  env: Partial<Pick<Env, "GITHUB_WEBHOOK_SECRET" | "AGENT_TOKENS">>,
  pipeline: Asked,
): Promise<Response> {
  const { pathname } = new URL(request.url);
  if (request.method !== "POST") return json({ error: "not found" }, 404);

  if (pathname === "/webhook/github") {
    const body = await request.text();
    if (!(await verifySignature(env.GITHUB_WEBHOOK_SECRET, body, request.headers.get("X-Hub-Signature-256")))) {
      return json({ error: "bad signature" }, 401);
    }
    const event = request.headers.get("X-GitHub-Event");
    let payload: unknown;
    try {
      payload = JSON.parse(body);
    } catch {
      return json({ error: "not JSON" }, 400);
    }
    return json({ ok: true, result: await pipeline.webhook(event, payload) });
  }

  if (pathname === "/agent/sync" || pathname === "/agent/token") {
    const node = nodeFor(env, request.headers.get("Authorization"));
    if (!node) return json({ error: "unauthorized" }, 401);
    if (pathname === "/agent/sync") {
      // A node's report is read field by field: anything but an object is refused here,
      // where reading it would throw.
      const report: unknown = await request.json().catch(() => undefined);
      if (typeof report !== "object" || report === null || Array.isArray(report)) return json({ error: "not a report" }, 400);
      return json(await pipeline.sync(node, report as Report));
    }
    try {
      return json(await pipeline.tokens(node));
    } catch (e) {
      // GitHub away, or the Worker not told which repository is the site's. The node
      // keeps the tokens it has.
      return json({ error: String((e as Thrown | null | undefined)?.message ?? e) }, 502);
    }
  }

  return json({ error: "not found" }, 404);
}
