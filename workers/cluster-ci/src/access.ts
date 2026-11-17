// What a node may read at GitHub, and the tokens that let it.
//
// The App's key is here and on no node. A node asks, with its own bearer token, and is
// handed installation tokens GitHub itself has narrowed: contents and metadata, read,
// on named repositories, for an hour. Which repositories is never the node's to say.
// It is read from the site's repository, at the branch the nodes deploy:
//
//   the site's repository itself
//   flake.lock           every node of it that is a github.com repository
//   github-repos.json    what the site fetches outside the lock (a WordPress site's
//                        content, a preview's repository, a private submodule). The
//                        library renders it from the site's configuration and the
//                        site's merge gate fails when the committed file differs
//                        (lib/github-repos.nix), so it changes only by a merge.
//
// The App is public, so anyone can install it anywhere. An installation is only ever
// looked at for a repository in that set, and a token is only ever minted for the
// repositories of the set an installation covers. The same set says which
// repositories' webhooks mean anything (src/core.ts).
//
// Kept in the Durable Object's storage, under its own key: the set (re-read when the
// site's branch moves, and every few minutes regardless), which installation covers
// which repository, and one token per owner, replaced when it has under half an hour
// left or when the repositories it should name change.

import type { Site } from "./core.ts";
import type { Installation, RepositoryAnswer, ScopedToken } from "./github.ts";
import type { Storage, Thrown } from "./types.ts";

// A flake reference as flake.lock writes it (a node's `locked` or `original`), as far
// as it is read.
export interface FlakeRef {
  type?: string;
  host?: string;
  owner?: string;
  repo?: string;
  url?: string;
  ref?: string;
  rev?: string;
  [other: string]: unknown;
}
export interface FlakeLockNode {
  inputs?: Record<string, string | string[]>;
  locked?: FlakeRef;
  original?: FlakeRef;
}
export interface FlakeLock {
  root: string;
  nodes?: Record<string, FlakeLockNode>;
}

// What is asked of GitHub here (src/github.ts, GitHub), which the tests stand in for.
export interface AccessGitHub {
  api(repo: string, method: string, path: string): Promise<unknown>;
  readFile(repo: string, path: string, ref?: string): Promise<string>;
  installations(): Promise<Installation[]>;
  repoInstallation(repo: string): Promise<number | null>;
  scopedToken(installation: number, repositories: string[], permissions: Record<string, string>): Promise<ScopedToken>;
}

// What is kept in the Durable Object's storage, under "access".
export interface Allow {
  at: number;
  ref: string;
  repos: string[];
  stale?: boolean;
}
export interface Cover {
  at: number;
  by: Record<string, number>;
  stale?: boolean;
}
export interface HeldToken {
  names: string;
  token: string;
  expiresAt: number;
}
export interface AccessState {
  allow: Allow | null;
  cover: Cover | null;
  tokens: Record<string, HeldToken>;
}

// What POST /agent/token answers.
export interface NodeToken {
  owner: string;
  token: string;
  expires_at: string;
  repositories: string[];
}
export interface TokensAnswer {
  site: string;
  ref: string;
  tokens: NodeToken[];
  uncovered: string[];
  errors: { owner: string; error: string }[];
}

export interface AccessOptions {
  storage: Storage;
  github: AccessGitHub;
  site: Site | null;
  now?: () => number;
  log?: (message: string) => void;
}

const NAME = /^[A-Za-z0-9_.-]+$/;
const lc = (s: string) => s.toLowerCase();

// What nodes are given. GitHub refuses a permission the App does not have, and these
// two it has.
export const PERMISSIONS = { contents: "read", metadata: "read" };

// A token handed out has at least this long left: a node refreshes every ten minutes,
// so it always holds one good for a build.
export const MIN_LEFT_MS = 30 * 60 * 1000;
// A token that could not be replaced is still handed out down to this.
export const FLOOR_LEFT_MS = 15 * 60 * 1000;
// How long the site's set, and what the installations cover, are believed without a
// webhook saying they changed. A push the Worker never heard of is the reason.
export const ALLOW_TTL_MS = 5 * 60 * 1000;
export const COVER_TTL_MS = 10 * 60 * 1000;

function named(owner?: unknown, repo?: unknown): string | null {
  if (typeof owner !== "string" || typeof repo !== "string") return null;
  repo = repo.replace(/\.git$/, "");
  // A string by the line above: TypeScript does not narrow an `unknown` it sees assigned.
  return NAME.test(owner) && NAME.test(repo as string) && repo !== "." && repo !== ".." ? `${owner}/${repo}` : null;
}

// The github.com repository a flake reference (a lock node's `locked` or `original`)
// names, or null. `github:`, git over https or ssh, and GitHub's own tarballs.
export function githubRepo(ref: FlakeRef | null | undefined): string | null {
  if (!ref || typeof ref !== "object") return null;
  if (ref.type === "github") return (ref.host ?? "github.com") === "github.com" ? named(ref.owner, ref.repo) : null;
  if (ref.type !== "git" && ref.type !== "tarball") return null;
  const m =
    /^(?:git\+)?(?:https|ssh|git):\/\/(?:[^@/]+@)?(?:github\.com|api\.github\.com\/repos)\/([^/?#]+)\/([^/?#]+)/.exec(ref.url ?? "") ??
    /^(?:[^@/]+@)?github\.com:([^/?#]+)\/([^/?#]+)/.exec(ref.url ?? "");
  return m ? named(m[1], m[2]) : null;
}

// Every repository the site uses: sorted, each once, spelled as first written. GitHub
// does not tell `Acme/Shop` from `acme/shop`; Nix does, so the spelling is kept.
export function siteRepos(site: string, lock: Pick<FlakeLock, "nodes"> | null | undefined, extra: unknown[] = []): string[] {
  const out = new Map<string, string>();
  const add = (name: string | null) => {
    if (name && !out.has(lc(name))) out.set(lc(name), name);
  };
  // A tuple for the spread: anything past the second part is not looked at.
  add(named(...(site.split("/") as [string?, string?])));
  for (const node of Object.values(lock?.nodes ?? {})) {
    add(githubRepo(node.locked));
    add(githubRepo(node.original));
  }
  for (const name of extra) {
    if (typeof name !== "string" || name.split("/").length !== 2) continue;
    add(named(...(name.split("/") as [string?, string?])));
  }
  return [...out.values()].sort((a, b) => (lc(a) < lc(b) ? -1 : 1));
}

export class Access {
  declare storage: Storage;
  declare github: AccessGitHub;
  declare site: Site | null;
  declare now: () => number;
  declare log: (message: string) => void;
  declare state: AccessState | null;
  declare tail: Promise<unknown>;

  // `site` is { repo, ref } (src/core.ts, parseFlakeUrl) or null: the Worker's own
  // configuration, SITE_FLAKE, and never what a node reported.
  constructor({ storage, github, site, now = Date.now, log = console.error }: AccessOptions) {
    Object.assign(this, { storage, github, site, now, log });
    this.state = null;
    this.tail = Promise.resolve();
  }

  // One at a time, apart from the pipeline's own lock: minting waits on GitHub, and a
  // webhook must not wait on that.
  locked<T>(fn: (s: AccessState) => T | Promise<T>): Promise<T> {
    const run = this.tail.then(async () => {
      this.state ??= (await this.storage.get<AccessState>("access")) ?? { allow: null, cover: null, tokens: {} };
      try {
        return await fn(this.state);
      } finally {
        await this.storage.put("access", this.state);
      }
    });
    this.tail = run.catch(() => {});
    return run;
  }

  // The site's branch moved (`allow`), or an installation changed (`cover`): read again
  // at the next question.
  invalidate(what: "allow" | "cover"): Promise<void> {
    return this.locked((s) => {
      if (s[what]) s[what].stale = true;
    });
  }

  async readAllow(s: AccessState): Promise<Allow> {
    if (!this.site) throw new Error("SITE_FLAKE is not set: the Worker does not know which repository is the site's");
    if (s.allow && !s.allow.stale && this.now() - s.allow.at < ALLOW_TTL_MS) return s.allow;
    try {
      const { repo } = this.site;
      const ref = this.site.ref ?? ((await this.github.api(repo, "GET", "")) as RepositoryAnswer).default_branch;
      const lock = JSON.parse(await this.github.readFile(repo, "flake.lock", ref)) as FlakeLock;
      let extra: unknown[] = [];
      try {
        // A list is what the next line holds it to.
        extra = JSON.parse(await this.github.readFile(repo, "github-repos.json", ref)) as unknown[];
        if (!Array.isArray(extra)) throw new Error("github-repos.json is not a list");
      } catch (e) {
        // A site that fetches nothing outside its lock has no such file.
        if ((e as Thrown).status !== 404) throw e;
      }
      const repos = siteRepos(repo, lock, extra);
      if (!s.allow || repos.join(" ") !== s.allow.repos.join(" ")) s.cover = null;
      s.allow = { at: this.now(), ref, repos };
    } catch (e) {
      // GitHub being away must not take a set that was read and merged with it. A set
      // never read is no set.
      if (!s.allow) throw new Error(`the site's repositories could not be read: ${(e as Thrown).message}`);
      this.log(`cluster-ci: the site's repositories could not be read again: ${(e as Thrown).message}`);
    }
    return s.allow;
  }

  // Whether `repo` is one the site uses. What a webhook about any other repository
  // causes is nothing.
  allows(repo: string | null | undefined): Promise<boolean> {
    return this.locked(async (s) => (await this.readAllow(s)).repos.some((r) => lc(r) === lc(repo ?? "")));
  }

  // repository (lower case) -> the id of the installation that covers it. Only owners
  // with an installation are asked about, so a lock full of public repositories costs
  // one request.
  async readCover(s: AccessState, allow: Allow): Promise<Record<string, number>> {
    if (s.cover && !s.cover.stale && this.now() - s.cover.at < COVER_TTL_MS) return s.cover.by;
    try {
      const owners = new Set((await this.github.installations()).map((i) => lc(i.account?.login ?? "")));
      const by: Record<string, number> = {};
      await Promise.all(
        allow.repos
          .filter((r) => owners.has(lc(r.split("/")[0]!)))
          .map(async (r) => {
            const id = await this.github.repoInstallation(r);
            if (id) by[lc(r)] = id;
          }),
      );
      s.cover = { at: this.now(), by };
    } catch (e) {
      if (!s.cover) throw new Error(`the App's installations could not be read: ${(e as Thrown).message}`);
      this.log(`cluster-ci: the App's installations could not be read again: ${(e as Thrown).message}`);
    }
    return s.cover.by;
  }

  // What a node is handed. One token per owner; a repository of the set that no
  // installation covers is named, since a public one needs no token and a private one
  // is waiting for its owner to install the App.
  tokens(): Promise<TokensAnswer> {
    return this.locked(async (s) => {
      const allow = await this.readAllow(s);
      const by = await this.readCover(s, allow);
      const owners = new Map<string, { owner: string; installation: number; repositories: string[] }>();
      for (const r of allow.repos) {
        const id = by[lc(r)];
        if (!id) continue;
        const key = `${lc(r.split("/")[0]!)}#${id}`;
        if (!owners.has(key)) owners.set(key, { owner: r.split("/")[0]!, installation: id, repositories: [] });
        owners.get(key)!.repositories.push(r);
      }
      // readAllow has answered, so there is a site.
      const out: TokensAnswer = { site: this.site!.repo, ref: allow.ref, tokens: [], uncovered: allow.repos.filter((r) => !by[lc(r)]), errors: [] };
      const kept: Record<string, HeldToken> = {};
      for (const [key, want] of owners) {
        const names = want.repositories.join(" ");
        let held = s.tokens[key]?.names === names ? s.tokens[key] : null;
        if (!held || held.expiresAt - this.now() < MIN_LEFT_MS) {
          try {
            const made = await this.github.scopedToken(
              want.installation,
              want.repositories.map((r) => r.split("/")[1]!),
              PERMISSIONS,
            );
            held = { names, token: made.token, expiresAt: made.expiresAt };
          } catch (e) {
            this.log(`cluster-ci: a token for ${want.owner}: ${(e as Thrown).message}`);
            out.errors.push({ owner: want.owner, error: (e as Thrown).message });
            if (held && held.expiresAt - this.now() < FLOOR_LEFT_MS) held = null;
          }
        }
        if (!held) continue;
        kept[key] = held;
        out.tokens.push({
          owner: want.owner,
          token: held.token,
          expires_at: new Date(held.expiresAt).toISOString(),
          repositories: want.repositories,
        });
      }
      s.tokens = kept;
      return out;
    });
  }
}
