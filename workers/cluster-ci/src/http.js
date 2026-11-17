// The Worker's HTTP surface: who is asking, and which of the pipeline's three questions
// it is. `pipeline` is the Durable Object's stub (src/index.js) or, under `node --test`,
// the Pipeline itself.
//
//   POST /webhook/github   GitHub's deliveries, checked against the App's webhook secret
//   POST /agent/sync       a node's report, answered with what it should run; a bearer
//                          token per node (AGENT_TOKENS), held open while nothing changes
//   POST /agent/token      the same bearer token; answered with read-only installation
//                          tokens for the site's repositories (src/access.js). The body
//                          is not read: nothing a node says decides what it may read.

import { nodeFor } from "./auth.js";
import { verifySignature } from "./github.js";

const json = (body, status = 200) => Response.json(body, { status });

export async function handle(request, env, pipeline) {
  const { pathname } = new URL(request.url);
  if (request.method !== "POST") return json({ error: "not found" }, 404);

  if (pathname === "/webhook/github") {
    const body = await request.text();
    if (!(await verifySignature(env.GITHUB_WEBHOOK_SECRET, body, request.headers.get("X-Hub-Signature-256")))) {
      return json({ error: "bad signature" }, 401);
    }
    const event = request.headers.get("X-GitHub-Event");
    return json({ ok: true, result: await pipeline.webhook(event, JSON.parse(body)) });
  }

  if (pathname === "/agent/sync" || pathname === "/agent/token") {
    const node = nodeFor(env, request.headers.get("Authorization"));
    if (!node) return json({ error: "unauthorized" }, 401);
    if (pathname === "/agent/sync") return json(await pipeline.sync(node, await request.json()));
    try {
      return json(await pipeline.tokens(node));
    } catch (e) {
      // GitHub away, or the Worker not told which repository is the site's. The node
      // keeps the tokens it has.
      return json({ error: String(e?.message ?? e) }, 502);
    }
  }

  return json({ error: "not found" }, 404);
}
