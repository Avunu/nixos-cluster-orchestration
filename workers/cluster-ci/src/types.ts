// The shapes more than one module reads. Types only: every import of this file is an
// `import type`, so it is in no bundle and is never loaded.

import type { PipelineObject } from "./index.ts";

// wrangler.toml's [vars] and Durable Object binding, and the secrets it lists.
export interface Env {
  CLUSTER_NAME: string;
  PREVIEW_DOMAIN: string;
  CF_ACCOUNT_ID: string;
  CF_ZONE_ID: string;
  GITHUB_APP_ID: string;
  SITE_FLAKE?: string;
  FLAKE_UPDATE_WORKFLOW?: string;
  GITHUB_APP_PRIVATE_KEY: string;
  GITHUB_WEBHOOK_SECRET: string;
  CF_API_TOKEN: string;
  // JSON: {"<token>": "<node>"}.
  AGENT_TOKENS: string;
  PIPELINE: DurableObjectNamespace<PipelineObject>;
}

// What is used of a Durable Object's storage, which the tests stand in for. `T` is
// what the caller put there; nothing checks it.
export interface Storage {
  get<T>(key: string): Promise<T | undefined>;
  put(key: string, value: unknown): Promise<void>;
}

// `fetch` as GitHub and Cloudflare are called with it, which is also what a test's
// stand-in is handed.
export interface FetchInit {
  method: string;
  headers: { Authorization: string } & Record<string, string>;
  body: string | undefined;
}
export type Fetch = (url: string, init: FetchInit) => Promise<Response>;

// What a `catch` reads of what was thrown. Everything thrown here is an Error;
// GitHubError, CloudflareError and the tests' stand-ins add the HTTP status.
export type Thrown = Error & { status?: number };
