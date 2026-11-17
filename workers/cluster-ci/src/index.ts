// cluster-ci — the GitHub App's endpoint, and what the nodes' agents ask.
//
// The Worker authenticates and routes (src/http.ts); everything it then does is
// src/core.ts and src/access.ts, in one Durable Object, so that no two requests decide
// about one preview at once, and one token serves every node that asks.

import { DurableObject } from "cloudflare:workers";
import { Cloudflare } from "./cloudflare.ts";
import { Pipeline } from "./core.ts";
import type { Report } from "./core.ts";
import { GitHub } from "./github.ts";
import { handle } from "./http.ts";
import type { Env } from "./types.ts";

// Longer than this and Cloudflare may close an idle request before it is answered.
const HOLD_MS = 25_000;

export class PipelineObject extends DurableObject<Env> {
  declare pipeline: Pipeline;

  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);
    this.pipeline = new Pipeline({
      storage: ctx.storage,
      github: new GitHub({ appId: env.GITHUB_APP_ID, privateKey: env.GITHUB_APP_PRIVATE_KEY }),
      cloudflare: new Cloudflare({ token: env.CF_API_TOKEN, accountId: env.CF_ACCOUNT_ID, zoneId: env.CF_ZONE_ID }),
      config: {
        domain: env.PREVIEW_DOMAIN,
        workflow: env.FLAKE_UPDATE_WORKFLOW || "flake-update.yml",
        // The site's repository, as topology.deploy.flakeUrl names it. The Worker's own
        // word for it: a node's report of its flake decides nothing.
        site: env.SITE_FLAKE,
      },
    });
  }

  webhook(event: string | null, payload: unknown) {
    return this.pipeline.webhook(event, payload);
  }

  sync(node: string, report: Report) {
    return this.pipeline.sync(node, report, HOLD_MS);
  }

  tokens() {
    return this.pipeline.tokens();
  }
}

export default {
  fetch(request: Request, env: Env) {
    return handle(request, env, env.PIPELINE.get(env.PIPELINE.idFromName("site")));
  },
};
