// The pipeline's decisions, with storage, GitHub and Cloudflare handed in, so that
// `node --test` runs the real thing (test/pipeline.test.js) and src/index.js only adapts
// it to a Durable Object.
//
// Two things come in. GitHub's webhooks say what should exist: a preview per app and
// branch while a pull request is open on it, and a deploy when a tracked branch moves.
// Each node's agent (modules/ci-agent.nix) says what does exist, and takes away what it
// should make of that. Nodes accept nothing inbound, so the agent asks, and its request
// is held open until there is something to say.
//
//   previews[<app>/<branch>]   one record per preview; its tunnel is made here, its
//                              container on the node whose agent offers the app
//   agents[<node>]             what the node last offered: its flake, and its apps
//                              that take previews
//   deploySeq                  counts pushes to the branch the nodes rebuild from

import { previewHost, previewLabel } from "./slug.js";

// What the agent reports -> the commit status GitHub shows.
const STATUS = {
  queued: "pending",
  building: "pending",
  seeding: "pending",
  starting: "pending",
  live: "success",
  failed: "failure",
  "no-capacity": "error",
};

const LABEL = {
  queued: "Queued",
  building: "Building",
  seeding: "Copying the production database",
  starting: "Starting, and migrating the copy",
  live: "Live",
  failed: "Failed",
  "no-capacity": "Waiting: every preview slot of this app is in use",
  closed: "Removed",
};

const WRITERS = ["OWNER", "MEMBER", "COLLABORATOR"];
const sameRepo = (a, b) => typeof a === "string" && typeof b === "string" && a.toLowerCase() === b.toLowerCase();

// `github:owner/repo` or `github:owner/repo/ref`: what topology.deploy.flakeUrl is.
export function parseFlakeUrl(url) {
  const m = /^github:([^/?#]+)\/([^/?#]+)(?:\/([^?#]+))?/.exec(url ?? "");
  return m ? { repo: `${m[1]}/${m[2]}`, ref: m[3] ?? null } : null;
}

// The root inputs of a flake.lock that follow `branch` of `repo`. An input pinned to a
// revision follows nothing, and one that follows another input is that input's business.
export function trackingInputs(lock, repo, branch, defaultBranch) {
  const root = lock.nodes?.[lock.root]?.inputs ?? {};
  return Object.entries(root)
    .filter(([, ref]) => typeof ref === "string")
    .filter(([, ref]) => {
      const o = lock.nodes[ref]?.original ?? {};
      if (o.rev) return false;
      const named =
        o.type === "github"
          ? `${o.owner}/${o.repo}`
          : o.type === "git"
            ? (/github\.com[/:]([^/]+\/[^/?#]+?)(?:\.git)?(?:[?#]|$)/.exec(o.url ?? "")?.[1] ?? null)
            : null;
      return sameRepo(named, repo) && (o.ref ?? defaultBranch) === branch;
    })
    .map(([name]) => name)
    .sort();
}

export function renderComment(r) {
  const state = r.closing ? "closed" : r.state;
  const rows = [
    ["Status", LABEL[state] ?? state],
    ["Preview", r.closing ? "removed" : `https://${r.host}`],
    ["Commit", `\`${r.sha.slice(0, 7)}\``],
    ["Database", "a copy of production, migrated by this branch"],
  ];
  const detail = (r.detail ?? "").replaceAll("```", "'''").trim();
  return [
    `<!-- cluster-ci:${r.id} -->`,
    `### Preview of \`${r.app}\``,
    "",
    "| | |",
    "| --- | --- |",
    ...rows.map(([k, v]) => `| **${k}** | ${v} |`),
    ...(detail && !r.closing ? ["", "```", detail, "```"] : []),
    "",
    r.closing
      ? "The branch's last pull request closed, so its container, database copy and hostname are gone."
      : "Outgoing mail and scheduled jobs are off in a preview. Comment `/preview reset` to start again from a fresh copy of production.",
  ].join("\n");
}

export class Pipeline {
  constructor({ storage, github, cloudflare, config, now = Date.now, log = console.error }) {
    Object.assign(this, { storage, github, cloudflare, config, now, log });
    this.state = null;
    this.tail = Promise.resolve();
    this.waiters = new Set();
  }

  async load() {
    this.state ??= (await this.storage.get("state")) ?? { version: 1, deploySeq: 0, agents: {}, previews: {} };
    return this.state;
  }

  // One change at a time. A Durable Object lets a second request in whenever the first
  // awaits GitHub or Cloudflare, and two webhooks for one branch would each make it a tunnel.
  locked(fn) {
    const run = this.tail.then(async () => {
      await this.load();
      try {
        return await fn(this.state);
      } finally {
        await this.storage.put("state", this.state);
      }
    });
    this.tail = run.catch(() => {});
    return run;
  }

  bump() {
    this.state.version += 1;
    for (const wake of [...this.waiters]) wake();
  }

  wait(ms) {
    return new Promise((resolve) => {
      const done = () => {
        clearTimeout(timer);
        this.waiters.delete(done);
        resolve();
      };
      const timer = setTimeout(done, ms);
      this.waiters.add(done);
    });
  }

  // ── what GitHub says ─────────────────────────────────────────────────────

  webhook(event, p) {
    return this.locked(() => {
      switch (event) {
        case "pull_request":
          return this.pullRequest(p);
        case "push":
          return this.push(p);
        case "delete":
          return p.ref_type === "branch" ? this.release(p.repository.full_name, p.ref, null) : "ignored";
        case "issue_comment":
          return this.comment(p);
        default:
          return "ignored";
      }
    });
  }

  // Every app that previews this repository, each on one node. Every node offers every
  // app (each has a copy of its data), so the node is the one with the fewest previews
  // now, counting the ones this call gives it; a tie goes to the name that sorts first.
  // A preview that exists keeps its node, whatever this says (`want`).
  targets(repo) {
    const load = {};
    for (const r of Object.values(this.state.previews)) load[r.node] = (load[r.node] ?? 0) + 1;
    const offers = new Map();
    for (const node of Object.keys(this.state.agents).sort()) {
      for (const a of this.state.agents[node].apps ?? []) {
        if (!sameRepo(a.repo, repo) || !(a.slots > 0)) continue;
        if (!offers.has(a.app)) offers.set(a.app, []);
        offers.get(a.app).push(node);
      }
    }
    const out = [];
    for (const [app, nodes] of offers) {
      const node = nodes.reduce((best, n) => ((load[n] ?? 0) < (load[best] ?? 0) ? n : best));
      load[node] = (load[node] ?? 0) + 1;
      out.push({ node, app });
    }
    return out;
  }

  async pullRequest(p) {
    const pr = p.pull_request;
    const repo = p.repository.full_name;
    if (p.action === "closed") return this.release(repo, pr.head.ref, pr.number);
    if (!["opened", "reopened", "synchronize"].includes(p.action)) return "ignored";
    // A preview runs the branch's code beside a copy of production's data, with the
    // app's own secrets. Pushing to a branch of the repository takes write access to
    // it; opening a pull request from a fork takes nothing. So a fork gets no preview,
    // and nothing here can be configured to give it one.
    if (!sameRepo(pr.head.repo?.full_name, repo)) return "ignored: fork";
    const targets = this.targets(repo);
    if (!targets.length) return "ignored: no app previews this repository";
    for (const t of targets) await this.want(t, repo, pr);
    this.bump();
    return "preview";
  }

  async want({ node, app }, repo, pr) {
    const branch = pr.head.ref;
    const id = `${app}/${branch}`;
    const previews = this.state.previews;
    const r = (previews[id] ??= {
      id,
      app,
      node,
      repo,
      branch,
      prs: [],
      comments: {},
      seed: 1,
      tunnel: null,
      host: await previewHost(app, branch, this.config.domain),
      createdAt: this.now(),
    });
    // Reopened before its teardown finished: the node starts it again, from a new copy.
    r.closing = false;
    r.sha = pr.head.sha;
    if (!r.prs.includes(pr.number)) r.prs.push(pr.number);
    r.detail = "";
    r.state = "queued";
    if (!r.tunnel) {
      try {
        const tunnel = await this.cloudflare.createTunnel(`preview-${await previewLabel(app, branch)}`);
        r.tunnel = { ...tunnel, dns: await this.cloudflare.routeDns(r.host, tunnel.id) };
      } catch (e) {
        this.log(`cluster-ci: ${id}: ${e.message}`);
        if (r.tunnel === null) r.state = "failed";
        r.detail = "Its hostname could not be set up at Cloudflare. The next push tries again.";
      }
    }
    r.updatedAt = this.now();
    await this.feedback(r);
  }

  // A pull request closed (`number`), or the branch was deleted (null). The preview is
  // the branch's, so it goes when the last pull request on the branch does.
  async release(repo, branch, number) {
    let released = 0;
    for (const r of Object.values(this.state.previews)) {
      if (!sameRepo(r.repo, repo) || r.branch !== branch || r.closing) continue;
      const closed = number === null ? [...r.prs] : r.prs.filter((n) => n === number);
      const open = r.prs.filter((n) => !closed.includes(n));
      if (open.length) {
        r.prs = open;
        continue;
      }
      r.closing = true;
      r.updatedAt = this.now();
      await this.feedback(r);
      released += 1;
      // Nothing was made for it anywhere, so no node has anything to report gone.
      if (!r.tunnel) delete this.state.previews[r.id];
    }
    if (released) this.bump();
    return released ? "released" : "ignored";
  }

  // `/preview reset` on the pull request, from someone who could have pushed to it.
  async comment(p) {
    if (p.action !== "created" || !p.issue?.pull_request) return "ignored";
    if (p.comment.body.trim() !== "/preview reset") return "ignored";
    if (!WRITERS.includes(p.comment.author_association)) return "ignored: not a collaborator";
    let reset = 0;
    for (const r of Object.values(this.state.previews)) {
      if (!sameRepo(r.repo, p.repository.full_name) || !r.prs.includes(p.issue.number) || r.closing) continue;
      r.seed += 1;
      r.state = "queued";
      r.detail = "";
      await this.feedback(r);
      reset += 1;
    }
    if (reset) this.bump();
    return reset ? "reset" : "ignored";
  }

  sites() {
    const out = new Map();
    for (const agent of Object.values(this.state.agents)) {
      const site = parseFlakeUrl(agent.flake);
      if (site) out.set(`${site.repo.toLowerCase()}@${site.ref ?? ""}`, site);
    }
    return [...out.values()];
  }

  // A branch moved. If the nodes rebuild from it, they are told now and not at their
  // next timer. If the site's lock follows it, the site's own workflow updates the lock:
  // that takes Nix, and the result still has to pass the site's merge gate, whose merge
  // is the push that lands in the first case.
  async push(p) {
    if (!p.ref?.startsWith("refs/heads/") || p.deleted) return "ignored";
    const branch = p.ref.slice("refs/heads/".length);
    const repo = p.repository.full_name;
    const done = [];
    for (const site of this.sites()) {
      try {
        if (sameRepo(site.repo, repo)) {
          if ((site.ref ?? p.repository.default_branch) !== branch) continue;
          this.state.deploySeq += 1;
          this.bump();
          done.push("deploy");
          continue;
        }
        const ref = site.ref ?? (await this.github.api(site.repo, "GET", "")).default_branch;
        const lock = JSON.parse(await this.github.readFile(site.repo, "flake.lock", ref));
        const inputs = trackingInputs(lock, repo, branch, p.repository.default_branch);
        if (!inputs.length) continue;
        await this.github.dispatchWorkflow(site.repo, this.config.workflow, ref, { inputs: inputs.join(" ") });
        done.push(`update ${inputs.join(" ")}`);
      } catch (e) {
        this.log(`cluster-ci: push to ${repo}@${branch}, site ${site.repo}: ${e.message}`);
        done.push("error");
      }
    }
    return done.length ? done.join(", ") : "ignored";
  }

  // The pull request's comment and the commit's status. GitHub being down must not
  // lose what was decided: the next change of state writes both again.
  async feedback(r) {
    for (const pr of r.prs) {
      try {
        r.comments[pr] = await this.github.upsertComment(r.repo, pr, r.comments[pr], renderComment(r));
      } catch (e) {
        this.log(`cluster-ci: ${r.id}: comment on #${pr}: ${e.message}`);
      }
    }
    if (r.closing) return;
    try {
      await this.github.setStatus(r.repo, r.sha, {
        state: STATUS[r.state] ?? "pending",
        context: `preview/${r.app}`,
        description: LABEL[r.state] ?? r.state,
        targetUrl: `https://${r.host}`,
      });
    } catch (e) {
      this.log(`cluster-ci: ${r.id}: status on ${r.sha}: ${e.message}`);
    }
  }

  // ── what a node says ─────────────────────────────────────────────────────

  // The node's report in, what it should run out. Held open up to `waitMs` when the
  // node already knows everything, and answered as soon as that stops being true.
  async sync(node, report, waitMs = 0) {
    const fresh = await this.locked((s) => this.report(s, node, report));
    if (!fresh && waitMs > 0 && report.version === this.state.version) await this.wait(waitMs);
    const s = this.state;
    return {
      version: s.version,
      deploySeq: s.deploySeq,
      previews: Object.values(s.previews)
        .filter((r) => r.node === node && !r.closing && r.tunnel)
        .sort((a, b) => a.createdAt - b.createdAt)
        .map(({ id, app, repo, branch, sha, seed, host, tunnel }) => ({
          id, app, repo, branch, sha, seed, host,
          tunnel: { id: tunnel.id, account: tunnel.account, secret: tunnel.secret },
        })),
    };
  }

  async report(s, node, report) {
    const offer = { flake: report.flake ?? null, apps: report.apps ?? [] };
    const known = s.agents[node];
    const changed = !known || JSON.stringify({ flake: known.flake, apps: known.apps }) !== JSON.stringify(offer);
    s.agents[node] = { ...offer, at: this.now() };
    const said = new Map((report.previews ?? []).map((p) => [p.id, p]));
    for (const r of Object.values(s.previews)) {
      if (r.node !== node) continue;
      const p = said.get(r.id);
      if (r.closing) {
        // The node holds nothing of it any more: now its hostname and tunnel can go.
        if (!p) await this.finish(r);
        continue;
      }
      // A report about an earlier commit or copy says nothing about this one.
      if (!p || p.sha !== r.sha || p.seed !== r.seed || !(p.state in STATUS)) continue;
      const detail = String(p.detail ?? "").slice(0, 4000);
      if (p.state === r.state && detail === (r.detail ?? "")) continue;
      r.state = p.state;
      r.detail = detail;
      r.updatedAt = this.now();
      await this.feedback(r);
    }
    return changed;
  }

  async finish(r) {
    try {
      if (r.tunnel?.dns) await this.cloudflare.deleteDns(r.tunnel.dns);
      if (r.tunnel?.id) await this.cloudflare.deleteTunnel(r.tunnel.id);
      delete this.state.previews[r.id];
    } catch (e) {
      // Kept as closing, so the node's next report tries again.
      this.log(`cluster-ci: ${r.id}: teardown: ${e.message}`);
    }
  }
}
