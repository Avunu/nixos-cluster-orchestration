"""Cloud: the buckets, keys, tunnels and DNS records the site needs from its providers,
made by OpenTofu from the flake's `cloud` output (lib/cloud.nix).

It runs here, on the operator's machine, and nowhere else: the providers' API
credentials are vars no node holds (`cloud-ovh`, `cloudflare/provision-token`), and
they reach OpenTofu in its environment for the length of one command. Its state is
`cloud/terraform.tfstate` in the repository, encrypted with `cloud-state/passphrase`,
because it holds every key the providers issued; it is committed like any other change.

    avc cloud plan      what would change, and nothing done
    avc cloud apply     the same, then done, and what the providers handed back put
                        where the site reads it: S3 key pairs into their vars, a new
                        tunnel's id into apps/<app>.json and its credentials into the
                        app's var. Then shipped, like every change.
    avc cloud tofu "…"  OpenTofu itself, with the same configuration, state and
                        credentials: `import`, `state list`, `output`.

A plan that deletes anything is refused unless asked for by name (`--destroy`):
a bucket that left the topology is client data, not garbage.
"""

from __future__ import annotations

import json
import os
import shlex
from pathlib import Path
from typing import TYPE_CHECKING, Any

from avc import ui
from avc.actions import Arg, action
from avc.core import proc, ship
from avc.core import vars as clanvars
from avc.errors import AvcError

if TYPE_CHECKING:
    from avc.context import Ctx

DIR = "cloud"
STATE = "terraform.tfstate"
PLAN = "plan.bin"
# Everything OpenTofu leaves beside the state is rebuilt from the flake: only the state
# is the site's.
GITIGNORE = "*\n!.gitignore\n!terraform.tfstate\n"


def load(ctx: Ctx) -> dict[str, Any]:
    cloud = json.loads(proc.out(["nix", "eval", "--json", f"{ctx.root}#cloud"], cwd=ctx.root))
    if not cloud.get("enabled"):
        raise AvcError("topology.cloud names no provider, so there is nothing for OpenTofu to make")
    return cloud


def encryption(passphrase: str) -> str:
    """OpenTofu's state and plan encryption, as it reads it from TF_ENCRYPTION. Enforced:
    with the passphrase missing or wrong it stops, and never writes a state in the clear."""
    if len(passphrase) < 16 or '"' in passphrase or "\\" in passphrase or "\n" in passphrase:
        raise AvcError("cloud-state/passphrase is not what its generator makes; refusing to use it")
    return (
        f'key_provider "pbkdf2" "site" {{\n  passphrase = "{passphrase}"\n}}\n'
        'method "aes_gcm" "site" {\n  keys = key_provider.pbkdf2.site\n}\n'
        "state {\n  method   = method.aes_gcm.site\n  enforced = true\n}\n"
        "plan {\n  method   = method.aes_gcm.site\n  enforced = true\n}\n"
    )


def environment(ctx: Ctx, cloud: dict[str, Any]) -> dict[str, str]:
    """The process environment for OpenTofu: this one's, and the secrets, which are
    read from the vars each time and written nowhere."""
    machine = cloud["writeback"]["machine"]

    def var(var_id: str) -> str:
        value = clanvars.get_value(ctx.root, machine, var_id).strip()
        if not value:
            raise AvcError(f"{var_id} has no value; `clan vars generate {machine}` asks for it")
        return value

    env = dict(os.environ)
    env.update(TF_IN_AUTOMATION="1", TF_INPUT="0", TF_ENCRYPTION=encryption(var("cloud-state/passphrase")))
    providers = cloud["config"]["terraform"]["required_providers"]
    if "ovh" in providers:
        env.update(
            OVH_APPLICATION_KEY=var("cloud-ovh/application-key"),
            OVH_APPLICATION_SECRET=var("cloud-ovh/application-secret"),
            OVH_CONSUMER_KEY=var("cloud-ovh/consumer-key"),
        )
    if "cloudflare" in providers:
        env["CLOUDFLARE_API_TOKEN"] = var("cloudflare/provision-token")
    return env


def workdir(ctx: Ctx, cloud: dict[str, Any]) -> Path:
    d = ctx.root / DIR
    d.mkdir(exist_ok=True)
    (d / ".gitignore").write_text(GITIGNORE)
    (d / "main.tf.json").write_text(json.dumps(cloud["config"], indent=2, sort_keys=True) + "\n")
    return d


def tofu(d: Path, env: dict[str, str], *args: str, capture: bool = False) -> str:
    import subprocess

    try:
        p = subprocess.run(["tofu", *args], cwd=d, env=env, text=True, capture_output=capture)
    except FileNotFoundError as e:
        raise AvcError("tofu: not found on PATH; run avc from `nix run .#avc` or the devShell") from e
    if p.returncode != 0:
        detail = (p.stderr or p.stdout or "").strip() if capture else ""
        raise AvcError(f"tofu {args[0]} failed ({p.returncode})" + (f":\n{detail}" if detail else ""))
    return p.stdout or ""


def changes(plan: dict[str, Any]) -> dict[str, list[str]]:
    """Resource addresses by what the plan does to them, from `tofu show -json`."""
    out: dict[str, list[str]] = {"create": [], "update": [], "delete": [], "replace": [], "import": []}
    for rc in plan.get("resource_changes", []):
        change = rc.get("change", {})
        actions = change.get("actions", [])
        if "delete" in actions and "create" in actions:
            out["replace"].append(rc["address"])
        elif "delete" in actions:
            out["delete"].append(rc["address"])
        elif "create" in actions:
            out["create"].append(rc["address"])
        elif "update" in actions:
            out["update"].append(rc["address"])
        if change.get("importing"):
            out["import"].append(rc["address"])
    return {k: sorted(v) for k, v in out.items()}


def refused(ch: dict[str, list[str]], allowed: list[str]) -> list[str]:
    """What the plan would destroy that nobody asked for by name."""
    return sorted(a for a in [*ch["delete"], *ch["replace"]] if a not in allowed)


def make_plan(ctx: Ctx, cloud: dict[str, Any]) -> tuple[Path, dict[str, str], dict[str, list[str]]]:
    env = environment(ctx, cloud)
    d = workdir(ctx, cloud)
    for host in cloud["writeback"]["unmanagedHosts"]:
        ui.warn(f"{host} is in no zone of topology.cloud.cloudflare.zones: its DNS record is not made here")
    tofu(d, env, "init", "-input=false", capture=True)
    tofu(d, env, "plan", "-input=false", f"-out={PLAN}")
    ch = changes(json.loads(tofu(d, env, "show", "-json", PLAN, capture=True)))
    return d, env, ch


def credentials_file(account: str, tunnel_id: str, secret: str) -> str:
    """What `cloudflared tunnel create` writes, and what the connector reads."""
    return json.dumps({"AccountTag": account, "TunnelID": tunnel_id, "TunnelSecret": secret})


def set_tunnel_id(root: Path, app: str, tunnel_id: str) -> Path:
    """Into apps/<app>.json, which merges with the app's .nix: the place tooling writes."""
    path = root / "apps" / f"{app}.json"
    data = json.loads(path.read_text()) if path.exists() else {}
    data.setdefault("tunnel", {})["id"] = tunnel_id
    path.write_text(json.dumps(data, indent=2) + "\n")
    return path


def write_back(ctx: Ctx, cloud: dict[str, Any], outputs: dict[str, Any]) -> list[str]:
    """Put what the providers issued where the site reads it. Returns what changed."""
    wb = cloud["writeback"]
    machine = wb["machine"]
    done: list[str] = []
    # Tunnels first: an app's credentials generator exists once the app has an id.
    for app, t in sorted(wb["tunnels"].items()):
        if t["known"]:
            continue  # adopted: its id and its secret are the ones it already had
        made = outputs[t["output"]]["value"]
        path = set_tunnel_id(ctx.root, app, made["id"])
        # clan evaluates the flake as git has it.
        proc.run(["git", "add", "--", str(path.relative_to(ctx.root))], cwd=ctx.root)
        clanvars.set_value(ctx.root, machine, t["credentials"], credentials_file(t["accountId"], made["id"], made["secret"]))
        done.append(f"{app}: tunnel {made['id']}, in apps/{app}.json and {t['credentials']}")
    for output, var_id in sorted(wb["vars"].items()):
        value = outputs[output]["value"]
        current = proc.run(["clan", "vars", "get", machine, var_id], cwd=ctx.root, check=False).stdout or ""
        if current.strip() != value:
            clanvars.set_value(ctx.root, machine, var_id, value)
            done.append(f"{var_id}: the key the provider issued")
    return done


def show(ch: dict[str, list[str]]) -> None:
    rows = [[verb, a] for verb in ("import", "create", "update", "replace", "delete") for a in ch[verb]]
    if rows:
        ui.table("OpenTofu's plan", ["", "resource"], rows)
    else:
        ui.ok("the providers have everything the topology and the apps call for")


@action("cloud", "plan", "What would change at the providers")
def plan(ctx: Ctx) -> None:
    _d, _env, ch = make_plan(ctx, load(ctx))
    show(ch)
    for address in refused(ch, []):
        ui.warn(f"{address} would be destroyed: `avc cloud apply` refuses that unless it is named with --destroy")


@action(
    "cloud",
    "apply",
    "Make the providers match, and ship what they issue",
    Arg("destroy", "Resource addresses that may be destroyed, comma-separated", option=True),
)
def apply(ctx: Ctx, destroy: str | None) -> None:
    cloud = load(ctx)
    d, env, ch = make_plan(ctx, cloud)
    show(ch)
    allowed = [a.strip() for a in (destroy or "").split(",") if a.strip()]
    doomed = refused(ch, allowed)
    if doomed:
        raise AvcError(
            "the plan destroys what nobody named:\n  " + "\n  ".join(doomed) + "\n"
            "A bucket or a tunnel that left the topology still holds or carries client data. "
            "If it is meant, name each with --destroy."
        )
    if not any(ch.values()):
        ui.info("nothing to apply")
    elif not ui.confirm("Apply this at the providers?"):
        return
    else:
        tofu(d, env, "apply", "-input=false", PLAN)
    (d / PLAN).unlink(missing_ok=True)
    outputs = json.loads(tofu(d, env, "output", "-json", capture=True) or "{}")
    for line in write_back(ctx, cloud, outputs):
        ui.ok(line)
    ship.ship(ctx, "chore(cloud): what the providers hold, and what they issued", paths=[f"{DIR}/", "apps/", "vars/", "secrets/"])


@action("cloud", "tofu", "Run OpenTofu itself (import, state, output)", Arg("args", 'Arguments, as one string: "state list"'))
def passthrough(ctx: Ctx, args: str) -> None:
    cloud = load(ctx)
    env = environment(ctx, cloud)
    d = workdir(ctx, cloud)
    tofu(d, env, "init", "-input=false", capture=True)
    tofu(d, env, *shlex.split(args))
