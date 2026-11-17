// What both test files stand the Worker's two neighbours in with.

import { Pipeline } from "../src/core.js";

export const REPO = "acme/shop";
export const SITE = "acme/cluster";

const LOCK = {
  root: "root",
  nodes: {
    root: { inputs: { shop: "shop", nixpkgs: ["cluster", "nixpkgs"], pinned: "pinned", other: "other" } },
    shop: { original: { type: "git", url: "https://github.com/acme/shop.git", ref: "main", submodules: true } },
    pinned: { original: { type: "github", owner: "acme", repo: "shop", rev: "abc" } },
    other: { original: { type: "github", owner: "acme", repo: "other" } },
  },
};

// The pipeline with GitHub and Cloudflare stood in for. `installs` is which account has
// installed the App (login -> installation id), `uncoveredRepos` the repositories an
// installation was not given, `extra` the site's github-repos.json (null: no such file).
export function harness({
  failTunnel = false,
  site = `github:${SITE}`,
  installs = { acme: 1 },
  uncoveredRepos = [],
  extra = null,
  lock = LOCK,
} = {}) {
  const calls = [];
  const stored = {};
  let comments = 100;
  let tunnels = 0;
  const clock = { t: 1000 };
  const fail = { site: false, mint: false };
  const state = { lock, extra, installs, mints: 0 };
  const github = {
    upsertComment: async (repo, pr, id, body) => (calls.push(["comment", repo, pr, id ?? null, body]), id ?? ++comments),
    setStatus: async (repo, sha, s) => void calls.push(["status", repo, sha, s.state, s.context]),
    api: async (repo, method, path) => (calls.push(["api", repo, method, path]), { default_branch: "main" }),
    readFile: async (repo, path, ref) => {
      calls.push(["read", repo, path, ref]);
      if (fail.site) throw new Error("GitHub GET: HTTP 503");
      if (path === "flake.lock") return JSON.stringify(state.lock);
      if (path === "github-repos.json" && state.extra !== null) return JSON.stringify(state.extra);
      throw Object.assign(new Error(`GitHub GET ${path}: HTTP 404`), { status: 404 });
    },
    installations: async () => {
      calls.push(["installations"]);
      return Object.entries(state.installs).map(([login, id]) => ({ id, account: { login } }));
    },
    repoInstallation: async (repo) => {
      calls.push(["covers", repo]);
      if (uncoveredRepos.includes(repo)) return null;
      return state.installs[repo.split("/")[0].toLowerCase()] ?? null;
    },
    scopedToken: async (id, repositories, permissions) => {
      if (fail.mint) throw new Error("GitHub POST access_tokens: HTTP 500");
      calls.push(["mint", id, repositories, permissions]);
      return { token: `ghs_${id}_${++state.mints}`, expiresAt: clock.t + 60 * 60 * 1000 };
    },
    dispatchWorkflow: async (repo, wf, ref, inputs) => void calls.push(["dispatch", repo, wf, ref, inputs]),
  };
  const cloudflare = {
    createTunnel: async (name) => {
      if (failTunnel) throw new Error("no");
      calls.push(["tunnel", name]);
      return { id: `t${++tunnels}`, secret: "s3cret", account: "acct" };
    },
    routeDns: async (host, id) => (calls.push(["dns", host, id]), `d-${id}`),
    deleteDns: async (id) => void calls.push(["undns", id]),
    deleteTunnel: async (id) => void calls.push(["untunnel", id]),
  };
  const pipeline = new Pipeline({
    storage: { get: async (k) => stored[k], put: async (k, v) => void (stored[k] = structuredClone(v)) },
    github,
    cloudflare,
    config: { domain: "preview.example.com", workflow: "flake-update.yml", site },
    now: () => clock.t,
    log: () => {},
  });
  const agent = (previews = [], version = 0, node = "node1", repo = REPO) =>
    pipeline.sync(node, {
      version,
      flake: `github:${SITE}`,
      apps: [{ app: "shop", repo, slots: 2 }],
      previews,
    });
  const pr = (action, { number = 7, ref = "feat-x", sha = "a".repeat(40), fork = false, repo = REPO } = {}) =>
    pipeline.webhook("pull_request", {
      action,
      repository: { full_name: repo, default_branch: "main" },
      pull_request: { number, head: { ref, sha, repo: { full_name: fork ? "mallory/shop" : repo } } },
    });
  const push = (repo, ref = "refs/heads/main") =>
    pipeline.webhook("push", { ref, repository: { full_name: repo, default_branch: "main" } });
  return { pipeline, calls, stored, agent, pr, push, clock, fail, state, of: (kind) => calls.filter((c) => c[0] === kind) };
}
