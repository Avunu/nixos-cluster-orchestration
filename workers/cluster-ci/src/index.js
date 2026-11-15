// cluster-ci — the GitHub App's endpoint, and what the nodes' agents ask.
//
//   POST /webhook/github   GitHub's deliveries, checked against the App's webhook secret
//   POST /agent/sync       a node's report, answered with what it should run; a bearer
//                          token per node (AGENT_TOKENS), held open while nothing changes
//
// The Worker authenticates; everything it then does is src/core.js, in one Durable
// Object, so that no two requests decide about one preview at once.

import { DurableObject } from "cloudflare:workers";
import { nodeFor } from "./auth.js";
import { Cloudflare } from "./cloudflare.js";
import { Pipeline } from "./core.js";
import { GitHub, verifySignature } from "./github.js";

// Longer than this and Cloudflare may close an idle request before it is answered.
const HOLD_MS = 25_000;

const json = (body, status = 200) => Response.json(body, { status });

export class PipelineObject extends DurableObject {
  constructor(ctx, env) {
    super(ctx, env);
    this.pipeline = new Pipeline({
      storage: ctx.storage,
      github: new GitHub({ appId: env.GITHUB_APP_ID, privateKey: env.GITHUB_APP_PRIVATE_KEY }),
      cloudflare: new Cloudflare({ token: env.CF_API_TOKEN, accountId: env.CF_ACCOUNT_ID, zoneId: env.CF_ZONE_ID }),
      config: { domain: env.PREVIEW_DOMAIN, workflow: env.FLAKE_UPDATE_WORKFLOW || "flake-update.yml" },
    });
  }

  webhook(event, payload) {
    return this.pipeline.webhook(event, payload);
  }

  sync(node, report) {
    return this.pipeline.sync(node, report, HOLD_MS);
  }
}

export default {
  async fetch(request, env) {
    const { pathname } = new URL(request.url);
    if (request.method !== "POST") return json({ error: "not found" }, 404);
    const pipeline = env.PIPELINE.get(env.PIPELINE.idFromName("site"));

    if (pathname === "/webhook/github") {
      const body = await request.text();
      if (!(await verifySignature(env.GITHUB_WEBHOOK_SECRET, body, request.headers.get("X-Hub-Signature-256")))) {
        return json({ error: "bad signature" }, 401);
      }
      const event = request.headers.get("X-GitHub-Event");
      return json({ ok: true, result: await pipeline.webhook(event, JSON.parse(body)) });
    }

    if (pathname === "/agent/sync") {
      const node = nodeFor(env, request.headers.get("Authorization"));
      if (!node) return json({ error: "unauthorized" }, 401);
      return json(await pipeline.sync(node, await request.json()));
    }

    return json({ error: "not found" }, 404);
  },
};
