// Preview hostnames. One DNS label, <branch>-<app>, so a single-level wildcard
// certificate on the preview zone covers every preview.

const LABEL_MAX = 63;

export function slug(s) {
  return s
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "");
}

async function shortHash(s) {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s));
  return [...new Uint8Array(digest).slice(0, 3)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

// The branch as it is when it is already a label and fits. Otherwise what is left of it
// plus a hash of the real name: `feat/x` and `feat-x` are two branches, and so are two
// long names that agree in their first fifty characters.
export async function previewLabel(app, branch) {
  const base = slug(branch);
  if (base === branch && base.length + 1 + app.length <= LABEL_MAX) return `${base}-${app}`;
  const hash = await shortHash(branch);
  const room = LABEL_MAX - app.length - hash.length - 2;
  const head = base.slice(0, Math.max(room, 0)).replace(/-+$/, "");
  return [head, hash, app].filter(Boolean).join("-");
}

export async function previewHost(app, branch, domain) {
  return `${await previewLabel(app, branch)}.${domain}`;
}
