// The pipeline's decisions, with storage, GitHub and Cloudflare handed in, so that
// `node --test` runs the real thing (test/pipeline.test.ts) and src/index.ts only adapts
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
//   agents[<node>]             what the node last offered: its apps that take
//                              previews (and its flake, which is only kept)
//   deploySeq                  counts pushes to the branch the nodes rebuild from
//
// The App is public: anyone can install it on anything, and GitHub then delivers that
// repository's events here. Which repository is the site's is the Worker's own
// configuration (SITE_FLAKE), never a node's report, and a repository the site does not
// use (src/access.ts) gets nothing: no preview, no lock update, no token.

import { Access } from "./access.ts";
import type { AccessGitHub, FlakeLock, FlakeRef, TokensAnswer } from "./access.ts";
import type { MadeTunnel } from "./cloudflare.ts";
import type { RepositoryAnswer, Status } from "./github.ts";
import { previewHost, previewLabel } from "./slug.ts";
import type { Storage, Thrown } from "./types.ts";

// What is asked of GitHub and Cloudflare here (src/github.ts, src/cloudflare.ts), which
// the tests stand in for.
export interface PipelineGitHub extends AccessGitHub {
  upsertComment(repo: string, pr: number, commentId: number | null | undefined, body: string): Promise<number>;
  setStatus(repo: string, sha: string, status: Status): Promise<unknown>;
  dispatchWorkflow(repo: string, workflow: string, ref: string, inputs: Record<string, string>): Promise<unknown>;
}
export interface PipelineCloudflare {
  createTunnel(name: string): Promise<MadeTunnel>;
  routeDns(hostname: string, tunnelId: string): Promise<string>;
  deleteDns(recordId: string): Promise<void>;
  deleteTunnel(id: string): Promise<void>;
}

export interface PipelineConfig {
  domain: string;
  workflow: string;
  // SITE_FLAKE, as it is set or not.
  site: string | null | undefined;
}

export interface PipelineOptions {
  storage: Storage;
  github: PipelineGitHub;
  cloudflare: PipelineCloudflare;
  config: PipelineConfig;
  now?: () => number;
  log?: (message: string) => void;
  access?: Access;
}

// The site's repository, and the branch the nodes deploy (null: its default branch).
export interface Site {
  repo: string;
  ref: string | null;
}

// GitHub's webhook deliveries, as far as they are read. The signature says GitHub sent
// them and the event's name says which of these one is; nothing checks the shape.
export interface Repository {
  full_name: string;
  default_branch?: string;
}
export interface PullRequest {
  number: number;
  head: { ref: string; sha: string; repo?: { full_name?: string } | null };
}
export interface PullRequestEvent {
  action: string;
  repository: Repository;
  pull_request: PullRequest;
}
export interface PushEvent {
  ref?: string;
  deleted?: boolean;
  repository: Repository;
}
export interface DeleteEvent {
  ref_type: string;
  ref: string;
  repository: Repository;
}
export interface IssueCommentEvent {
  action: string;
  repository: Repository;
  issue?: { number: number; pull_request?: unknown };
  comment: { body: string; author_association: string };
}

// What a node's agent says (POST /agent/sync), and what it is answered.
export type PreviewState = "queued" | "building" | "seeding" | "starting" | "live" | "failed" | "no-capacity";
export interface Offer {
  app: string;
  repo: string;
  slots: number;
}
export interface ReportedPreview {
  id: string;
  sha: string;
  seed: number;
  state: string;
  detail?: unknown;
}
export interface Report {
  version?: number;
  flake?: string | null;
  apps?: Offer[];
  previews?: ReportedPreview[];
}
export interface WantedPreview {
  id: string;
  app: string;
  repo: string;
  branch: string;
  sha: string;
  seed: number;
  host: string;
  tunnel: MadeTunnel;
}
export interface SyncAnswer {
  version: number;
  deploySeq: number;
  previews: WantedPreview[];
}

// What is kept in the Durable Object's storage, under "state".
export interface PreviewTunnel extends MadeTunnel {
  dns: string;
}
export interface PreviewRecord {
  id: string;
  app: string;
  node: string;
  repo: string;
  branch: string;
  prs: number[];
  // pull request -> the id of its comment
  comments: Record<number, number>;
  seed: number;
  tunnel: PreviewTunnel | null;
  host: string;
  createdAt: number;
  closing: boolean;
  sha: string;
  detail: string;
  state: PreviewState;
  updatedAt: number;
}
export interface AgentRecord {
  flake: string | null;
  apps: Offer[];
  at: number;
}
export interface PipelineState {
  version: number;
  deploySeq: number;
  agents: Record<string, AgentRecord>;
  previews: Record<string, PreviewRecord>;
}

// What a comment is rendered from: a preview's record, or as much of one.
export type Rendered = Pick<PreviewRecord, "id" | "app" | "sha" | "host" | "state"> &
  Partial<Pick<PreviewRecord, "closing" | "detail">>;

interface Target {
  node: string;
  app: string;
}

// What the agent reports -> the commit status GitHub shows.
const STATUS: Record<PreviewState, string> = {
  queued: "pending",
  building: "pending",
  seeding: "pending",
  starting: "pending",
  live: "success",
  failed: "failure",
  "no-capacity": "error",
};

const LABEL: Record<PreviewState | "closed", string> = {
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
const sameRepo = (a: unknown, b: unknown) => typeof a === "string" && typeof b === "string" && a.toLowerCase() === b.toLowerCase();

// `github:owner/repo` or `github:owner/repo/ref`: what topology.deploy.flakeUrl is.
export function parseFlakeUrl(url: string | null | undefined): Site | null {
  const m = /^github:([^/?#]+)\/([^/?#]+)(?:\/([^?#]+))?/.exec(url ?? "");
  return m ? { repo: `${m[1]}/${m[2]}`, ref: m[3] ?? null } : null;
}

// The root inputs of a flake.lock that follow `branch` of `repo`. An input pinned to a
// revision follows nothing, and one that follows another input is that input's business.
export function trackingInputs(lock: FlakeLock, repo: string, branch: string, defaultBranch: string | undefined): string[] {
  const root = lock.nodes?.[lock.root]?.inputs ?? {};
  return Object.entries(root)
    .filter(([, ref]) => typeof ref === "string")
    .filter(([, ref]) => {
      // The filter before this one left the inputs that name a node, and a lock with
      // inputs has nodes.
      const o: FlakeRef = lock.nodes![ref as string]?.original ?? {};
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

export function renderComment(r: Rendered): string {
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

// The events whose handlers read `repository.full_name`, and what else each reads first.
const REPOSITORY_EVENTS = new Set(["pull_request", "push", "delete", "issue_comment"]);
const isObject = (v: unknown): v is Record<string, unknown> => typeof v === "object" && v !== null;
function wellFormed(event: string | null, p: unknown): boolean {
  if (!isObject(p) || !isObject(p.repository) || typeof p.repository.full_name !== "string") return false;
  if (event === "pull_request") return isObject(p.pull_request) && isObject(p.pull_request.head);
  if (event === "issue_comment") return isObject(p.issue) && isObject(p.comment);
  return true;
}

export class Pipeline {
  declare storage: Storage;
  declare github: PipelineGitHub;
  declare cloudflare: PipelineCloudflare;
  declare config: PipelineConfig;
  declare now: () => number;
  declare log: (message: string) => void;
  declare site: Site | null;
  declare access: Access;
  // Null until the first request loads it; every method but the constructor runs after that.
  declare state: PipelineState | null;
  declare tail: Promise<unknown>;
  declare waiters: Set<() => void>;

  constructor({ storage, github, cloudflare, config, now = Date.now, log = console.error, access }: PipelineOptions) {
    Object.assign(this, { storage, github, cloudflare, config, now, log });
    this.site = parseFlakeUrl(config.site);
    this.access = access ?? new Access({ storage, github, site: this.site, now, log });
    this.state = null;
    this.tail = Promise.resolve();
    this.waiters = new Set();
  }

  async load(): Promise<PipelineState> {
    this.state ??= (await this.storage.get<PipelineState>("state")) ?? { version: 1, deploySeq: 0, agents: {}, previews: {} };
    return this.state;
  }

  // One change at a time. A Durable Object lets a second request in whenever the first
  // awaits GitHub or Cloudflare, and two webhooks for one branch would each make it a tunnel.
  locked<T>(fn: (s: PipelineState) => T | Promise<T>): Promise<T> {
    const run = this.tail.then(async () => {
      await this.load();
      try {
        return await fn(this.state!);
      } finally {
        await this.storage.put("state", this.state);
      }
    });
    this.tail = run.catch(() => {});
    return run;
  }

  bump() {
    this.state!.version += 1;
    for (const wake of [...this.waiters]) wake();
  }

  wait(ms: number): Promise<void> {
    return new Promise<void>((resolve) => {
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

  webhook(event: string | null, p: unknown): Promise<string> {
    return this.locked<string>(() => {
      // The signature says GitHub sent it, not what is in it: a delivery without the
      // fields its event is read by is passed over, where reading them would throw.
      if (REPOSITORY_EVENTS.has(event ?? "") && !wellFormed(event, p)) return "ignored: malformed";
      switch (event) {
        case "pull_request":
          return this.pullRequest(p as PullRequestEvent);
        case "push":
          return this.push(p as PushEvent);
        case "delete":
          return (p as DeleteEvent).ref_type === "branch"
            ? this.release((p as DeleteEvent).repository.full_name, (p as DeleteEvent).ref, null)
            : "ignored";
        case "issue_comment":
          return this.comment(p as IssueCommentEvent);
        case "installation":
        case "installation_repositories":
          // Someone installed the App, or changed what an installation covers: the
          // next token is made from what is covered now.
          return this.access.invalidate("cover").then(() => "noted");
        default:
          return "ignored";
      }
    });
  }

  // Every app that previews this repository, each on one node. Every node offers every
  // app (each has a copy of its data), so the node is the one with the fewest previews
  // now, counting the ones this call gives it; a tie goes to the name that sorts first.
  // A preview that exists keeps its node, whatever this says (`want`).
  targets(repo: string): Target[] {
    const load: Record<string, number> = {};
    for (const r of Object.values(this.state!.previews)) load[r.node] = (load[r.node] ?? 0) + 1;
    const offers = new Map<string, string[]>();
    for (const node of Object.keys(this.state!.agents).sort()) {
      for (const a of this.state!.agents[node]!.apps ?? []) {
        if (!sameRepo(a.repo, repo) || !(a.slots > 0)) continue;
        if (!offers.has(a.app)) offers.set(a.app, []);
        offers.get(a.app)!.push(node);
      }
    }
    const out: Target[] = [];
    for (const [app, nodes] of offers) {
      const node = nodes.reduce((best, n) => ((load[n] ?? 0) < (load[best] ?? 0) ? n : best));
      load[node] = (load[node] ?? 0) + 1;
      out.push({ node, app });
    }
    return out;
  }

  async pullRequest(p: PullRequestEvent): Promise<string> {
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
    // A node offered the app; that the repository is one of the site's is read from
    // the site, so no node can point a preview at a stranger's installation.
    if (!(await this.access.allows(repo))) return "ignored: not a repository of this site";
    for (const t of targets) await this.want(t, repo, pr);
    this.bump();
    return "preview";
  }

  async want({ node, app }: Target, repo: string, pr: PullRequest): Promise<void> {
    const branch = pr.head.ref;
    const id = `${app}/${branch}`;
    const previews = this.state!.previews;
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
      // closing, sha, detail, state and updatedAt are set below, before anything reads them.
    } as Partial<PreviewRecord> as PreviewRecord);
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
        this.log(`cluster-ci: ${id}: ${(e as Thrown).message}`);
        if (r.tunnel === null) r.state = "failed";
        r.detail = "Its hostname could not be set up at Cloudflare. The next push tries again.";
      }
    }
    r.updatedAt = this.now();
    await this.feedback(r);
  }

  // A pull request closed (`number`), or the branch was deleted (null). The preview is
  // the branch's, so it goes when the last pull request on the branch does.
  async release(repo: string, branch: string, number: number | null): Promise<string> {
    let released = 0;
    for (const r of Object.values(this.state!.previews)) {
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
      if (!r.tunnel) delete this.state!.previews[r.id];
    }
    if (released) this.bump();
    return released ? "released" : "ignored";
  }

  // `/preview reset` on the pull request, from someone who could have pushed to it.
  async comment(p: IssueCommentEvent): Promise<string> {
    if (p.action !== "created" || !p.issue?.pull_request) return "ignored";
    if (p.comment.body.trim() !== "/preview reset") return "ignored";
    if (!WRITERS.includes(p.comment.author_association)) return "ignored: not a collaborator";
    let reset = 0;
    for (const r of Object.values(this.state!.previews)) {
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

  // A branch moved. If the nodes rebuild from it, they are told now and not at their
  // next timer. If the site's lock follows it, the site's own workflow updates the lock:
  // that takes Nix, and the result still has to pass the site's merge gate, whose merge
  // is the push that lands in the first case. A push anywhere else, which for a public
  // App is anywhere at all, is answered from what is already known of the site.
  async push(p: PushEvent): Promise<string> {
    if (!p.ref?.startsWith("refs/heads/") || p.deleted) return "ignored";
    const branch = p.ref.slice("refs/heads/".length);
    const repo = p.repository.full_name;
    const site = this.site;
    if (!site) return "ignored: SITE_FLAKE is not set";
    if (sameRepo(site.repo, repo)) {
      if ((site.ref ?? p.repository.default_branch) !== branch) return "ignored";
      // Its lock, and what it fetches outside it, may have changed with it.
      await this.access.invalidate("allow");
      this.state!.deploySeq += 1;
      this.bump();
      return "deploy";
    }
    try {
      if (!(await this.access.allows(repo))) return "ignored: not a repository of this site";
      const ref = site.ref ?? ((await this.github.api(site.repo, "GET", "")) as RepositoryAnswer).default_branch;
      const lock = JSON.parse(await this.github.readFile(site.repo, "flake.lock", ref)) as FlakeLock;
      const inputs = trackingInputs(lock, repo, branch, p.repository.default_branch);
      if (!inputs.length) return "ignored";
      await this.github.dispatchWorkflow(site.repo, this.config.workflow, ref, { inputs: inputs.join(" ") });
      return `update ${inputs.join(" ")}`;
    } catch (e) {
      this.log(`cluster-ci: push to ${repo}@${branch}, site ${site.repo}: ${(e as Thrown).message}`);
      return "error";
    }
  }

  // The pull request's comment and the commit's status. GitHub being down must not
  // lose what was decided: the next change of state writes both again.
  async feedback(r: PreviewRecord): Promise<void> {
    for (const pr of r.prs) {
      try {
        r.comments[pr] = await this.github.upsertComment(r.repo, pr, r.comments[pr], renderComment(r));
      } catch (e) {
        this.log(`cluster-ci: ${r.id}: comment on #${pr}: ${(e as Thrown).message}`);
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
      this.log(`cluster-ci: ${r.id}: status on ${r.sha}: ${(e as Thrown).message}`);
    }
  }

  // ── what a node says ─────────────────────────────────────────────────────

  // Read access to the site's repositories, for an hour (src/access.ts). Any node of
  // the site gets the same answer: what it may read is the site's, not the node's.
  tokens(): Promise<TokensAnswer> {
    return this.access.tokens();
  }

  // The node's report in, what it should run out. Held open up to `waitMs` when the
  // node already knows everything, and answered as soon as that stops being true.
  async sync(node: string, report: Report, waitMs = 0): Promise<SyncAnswer> {
    const fresh = await this.locked((s) => this.report(s, node, report));
    if (!fresh && waitMs > 0 && report.version === this.state!.version) await this.wait(waitMs);
    const s = this.state!;
    return {
      version: s.version,
      deploySeq: s.deploySeq,
      previews: Object.values(s.previews)
        .filter((r) => r.node === node && !r.closing && r.tunnel)
        .sort((a, b) => a.createdAt - b.createdAt)
        .map(({ id, app, repo, branch, sha, seed, host, tunnel }) => ({
          id, app, repo, branch, sha, seed, host,
          // The filter above left the previews that have a tunnel.
          tunnel: { id: tunnel!.id, account: tunnel!.account, secret: tunnel!.secret },
        })),
    };
  }

  async report(s: PipelineState, node: string, report: Report): Promise<boolean> {
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
      if (!p || p.sha !== r.sha || p.seed !== r.seed || !Object.hasOwn(STATUS, p.state)) continue;
      const detail = String(p.detail ?? "").slice(0, 4000);
      if (p.state === r.state && detail === (r.detail ?? "")) continue;
      // One of STATUS's, by the test two lines up.
      r.state = p.state as PreviewState;
      r.detail = detail;
      r.updatedAt = this.now();
      await this.feedback(r);
    }
    return changed;
  }

  async finish(r: PreviewRecord): Promise<void> {
    try {
      if (r.tunnel?.dns) await this.cloudflare.deleteDns(r.tunnel.dns);
      if (r.tunnel?.id) await this.cloudflare.deleteTunnel(r.tunnel.id);
      delete this.state!.previews[r.id];
    } catch (e) {
      // Kept as closing, so the node's next report tries again.
      this.log(`cluster-ci: ${r.id}: teardown: ${(e as Thrown).message}`);
    }
  }
}
