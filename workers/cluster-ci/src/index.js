// cluster-ci — the GitHub App's endpoint, and what the nodes' agents ask.
//
// The Worker authenticates and routes (src/http.js); everything it then does is
// src/core.js and src/access.js, in one Durable Object, so that no two requests decide
// about one preview at once, and one token serves every node that asks.

import { DurableObject } from "cloudflare:workers";
import { Cloudflare } from "./cloudflare.js";
import { Pipeline } from "./core.js";
import { GitHub } from "./github.js";
import { handle } from "./http.js";

// Longer than this and Cloudflare may close an idle request before it is answered.
const HOLD_MS = 25_000;

export class PipelineObject extends DurableObject {
  constructor(ctx, env) {
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

  webhook(event, payload) {
    return this.pipeline.webhook(event, payload);
  }

  sync(node, report) {
    return this.pipeline.sync(node, report, HOLD_MS);
  }

  tokens() {
    return this.pipeline.tokens();
  }
}

export default {
  fetch(request, env) {
    return handle(request, env, env.PIPELINE.get(env.PIPELINE.idFromName("site")));
  },
};
