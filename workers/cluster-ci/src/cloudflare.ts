// What a preview needs from Cloudflare: a tunnel of its own and one DNS record.
//
// A tunnel per preview, like a tunnel per app (README, "Ingress"): connectors on one
// tunnel must serve identical routes, so two previews sharing one would serve each
// other's traffic. The tunnel is locally configured: the node writes the ingress rule
// beside the credentials, and this Worker never learns a socket path.

import type { Fetch, Thrown } from "./types.ts";

// Cloudflare's answers, as far as they are read.
interface Answer<T> {
  result: T;
}
interface Tunnel {
  id: string;
}
interface DnsRecord {
  id: string;
}

// What createTunnel hands back: all the connector's credentials file holds.
export interface MadeTunnel {
  id: string;
  secret: string;
  account: string;
}

export interface CloudflareOptions {
  token: string;
  accountId: string;
  zoneId: string;
  fetch?: Fetch;
  apiBase?: string;
}

export class CloudflareError extends Error {
  declare status: number;

  constructor(status: number, method: string, path: string, body: string) {
    super(`Cloudflare ${method} ${path}: HTTP ${status} ${body.slice(0, 200)}`);
    this.status = status;
  }
}

export class Cloudflare {
  declare token: string;
  declare accountId: string;
  declare zoneId: string;
  declare fetch: Fetch;
  declare apiBase: string;

  constructor({ token, accountId, zoneId, fetch: f = (...a) => fetch(...a), apiBase = "https://api.cloudflare.com/client/v4" }: CloudflareOptions) {
    Object.assign(this, { token, accountId, zoneId, fetch: f, apiBase });
  }

  // `T` is what the caller reads of Cloudflare's `result`; nothing checks it.
  async call<T>(method: string, path: string, body?: unknown): Promise<T> {
    const res = await this.fetch(`${this.apiBase}${path}`, {
      method,
      headers: { Authorization: `Bearer ${this.token}`, "Content-Type": "application/json" },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    const text = await res.text();
    if (!res.ok) throw new CloudflareError(res.status, method, path, text);
    return (JSON.parse(text) as Answer<T>).result;
  }

  // The secret is made here, so the credentials file the connector reads
  // ({AccountTag, TunnelID, TunnelSecret}) needs no second request. A tunnel left under
  // this name by a preview whose teardown never finished is removed first: names are
  // unique among live tunnels.
  async createTunnel(name: string): Promise<MadeTunnel> {
    const tunnels = `/accounts/${this.accountId}/cfd_tunnel`;
    for (const old of await this.call<Tunnel[]>("GET", `${tunnels}?name=${encodeURIComponent(name)}&is_deleted=false`)) {
      await this.deleteTunnel(old.id);
    }
    const secret = btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(32))));
    const made = await this.call<Tunnel>("POST", tunnels, { name, tunnel_secret: secret, config_src: "local" });
    return { id: made.id, secret, account: this.accountId };
  }

  // Connections first: Cloudflare refuses to delete a tunnel that still has any, and a
  // connector can outlive its container by a moment.
  async deleteTunnel(id: string): Promise<void> {
    const tunnel = `/accounts/${this.accountId}/cfd_tunnel/${id}`;
    try {
      await this.call("DELETE", `${tunnel}/connections`);
      await this.call("DELETE", tunnel);
    } catch (e) {
      if ((e as Thrown).status !== 404) throw e;
    }
  }

  async routeDns(hostname: string, tunnelId: string): Promise<string> {
    const records = `/zones/${this.zoneId}/dns_records`;
    const record = { type: "CNAME", name: hostname, content: `${tunnelId}.cfargotunnel.com`, proxied: true };
    const [old] = await this.call<DnsRecord[]>("GET", `${records}?type=CNAME&name=${encodeURIComponent(hostname)}`);
    if (old) return (await this.call<DnsRecord>("PUT", `${records}/${old.id}`, record)).id;
    return (await this.call<DnsRecord>("POST", records, record)).id;
  }

  async deleteDns(recordId: string): Promise<void> {
    try {
      await this.call("DELETE", `/zones/${this.zoneId}/dns_records/${recordId}`);
    } catch (e) {
      if ((e as Thrown).status !== 404) throw e;
    }
  }
}
