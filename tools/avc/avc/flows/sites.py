"""WordPress sites.

Phase 1 delegates each step to site-provisioner, an optional provisioning tool that is
NOT part of this library: it owns the Cloudflare/GitHub provisioning and its
resumable state in .site-provisioner/. Pass it to the avc package to enable these
commands (`packages.avc.override { siteProvisioner = ...; }`). What avc adds is the
part the provisioner leaves as "now commit, push and wait": every step that writes
apps/<slug>.json continues straight into the ship pipeline.
"""

from __future__ import annotations

import json
import shutil
from typing import TYPE_CHECKING

from avc import ui
from avc.actions import Arg, action
from avc.core import proc, ship
from avc.errors import AvcError

if TYPE_CHECKING:
    from avc.context import Ctx


def site_slugs(ctx: Ctx) -> list[str]:
    """Configured sites, plus any still being provisioned (state, no file yet)."""
    slugs = {p.stem for p in (ctx.root / "apps").glob("*.json")}
    state = ctx.root / ".site-provisioner"
    if state.exists():
        slugs |= {p.name.removesuffix(".state.json") for p in state.glob("*.state.json")}
    return sorted(s for s in slugs if _is_site(ctx, s))


def _is_site(ctx: Ctx, slug: str) -> bool:
    f = ctx.root / "apps" / f"{slug}.json"
    if not f.exists():
        return True  # only a provisioner state file: a site in progress
    try:
        return "wordpress" in json.loads(f.read_text())
    except json.JSONDecodeError:
        return False


def _provision(ctx: Ctx, *args: str) -> None:
    if shutil.which("site-provisioner") is None:
        raise AvcError(
            "site provisioning needs the optional site-provisioner tool, which this avc was built without "
            "(packages.avc.override { siteProvisioner = ...; })"
        )
    rc = proc.run(["site-provisioner", "site", *args], cwd=ctx.root, check=False, capture=False).returncode
    if rc != 0:
        raise AvcError(f"site-provisioner site {' '.join(args)} failed ({rc}) — its state is kept; re-running resumes")


def _site_paths(slug: str) -> list[str]:
    # The catalogue entry plus whatever vars the step created or changed.
    return [f"apps/{slug}.json", "vars/", "secrets/"]


def _slug(text: str) -> str | bool:
    import re

    return bool(re.fullmatch(r"[a-z0-9][a-z0-9-]*", text)) or "lowercase letters, digits and dashes"


def _ask_slug() -> str:
    return ui.text("Site slug (becomes apps/<slug>.json and the container name)", validate=_slug)


@action("site", "list", "List sites")
def list_sites(ctx: Ctx) -> None:
    _provision(ctx, "list")


@action("site", "status", "Provisioning progress", Arg("slug", "Site", choices=site_slugs))
def status(ctx: Ctx, slug: str) -> None:
    _provision(ctx, "status", slug)


def _provision(ctx: Ctx, mode: str, slug: str | None) -> None:
    slug = slug or _ask_slug()
    _provision(ctx, mode, slug)
    ui.info(f"apps/{slug}.json is written; the cluster creates both containers and the database once it is deployed")
    if ship.ship(ctx, f"feat(sites): add {slug}", paths=_site_paths(slug)):
        next_step = "restore" if mode == "migrate" else "verify"
        ui.ok(f"{slug} is deployed — next: `avc site {next_step} {slug}`")


@action("site", "new", "New empty site", Arg("slug", "Site slug", optional=True))
def new(ctx: Ctx, slug: str | None) -> None:
    _provision(ctx, "new", slug)


@action("site", "migrate", "Migrate an existing site", Arg("slug", "Site slug", optional=True))
def migrate(ctx: Ctx, slug: str | None) -> None:
    _provision(ctx, "migrate", slug)


@action("site", "restore", "Load the source database (after deploy)", Arg("slug", "Site", choices=site_slugs))
def restore(ctx: Ctx, slug: str) -> None:
    _provision(ctx, "restore", slug)


@action("site", "media", "Sync uploads to R2", Arg("slug", "Site", choices=site_slugs))
def media(ctx: Ctx, slug: str) -> None:
    _provision(ctx, "media", slug)


@action("site", "verify", "Verify row counts and both planes", Arg("slug", "Site", choices=site_slugs))
def verify(ctx: Ctx, slug: str) -> None:
    _provision(ctx, "verify", slug)


@action("site", "cutover", "Cut over the live domain", Arg("slug", "Site", choices=site_slugs))
def cutover(ctx: Ctx, slug: str) -> None:
    """The provisioner's cutover pauses for a deploy in the middle ("Deploy landed —
    move DNS now?"). avc runs it in two passes instead: the first rewrites the
    config, avc deploys it and proves it landed, the second moves DNS."""
    ui.header(f"Cutover {slug}")
    ui.say("Pass 1: the provisioner points the site config at the real domain.")
    ui.warn("When the provisioner asks \"Deploy landed — move DNS now?\", answer NO — avc deploys and verifies it next.")
    _provision(ctx, "cutover", slug)
    if not ship.ship(ctx, f"feat(sites): cut over {slug}", paths=_site_paths(slug)):
        ui.warn(f"not deployed yet; re-run `avc site cutover {slug}` once it is")
        return
    ui.say("Pass 2: the config is live; this time answer YES to move DNS.")
    if ui.confirm("Run cutover again to move DNS?", default=True):
        _provision(ctx, "cutover", slug)
        ui.info("purge the Cloudflare cache for the domain, and keep the source host until satisfied")


@action("site", "r2-rotate", "Rotate the site's R2 key", Arg("slug", "Site", choices=site_slugs))
def r2_rotate(ctx: Ctx, slug: str) -> None:
    _provision(ctx, "r2-rotate", slug)
    ship.ship(
        ctx,
        f"chore(secrets): rotate {slug} R2 key",
        paths=["vars/", "secrets/"],
        post=[ship.restart(f"app-{slug}", ctx.index.leader)]
        if slug in ctx.index.apps
        else [],
    )


@action("site", "sql", "Run SQL against the site's database", Arg("slug", "Site", choices=site_slugs), Arg("sql", "SQL"))
def sql(ctx: Ctx, slug: str, sql: str) -> None:
    _provision(ctx, "sql", slug, sql)


@action("site", "destroy", "Remove a site's config (never its data)", Arg("slug", "Site", choices=site_slugs))
def destroy(ctx: Ctx, slug: str) -> None:
    ui.type_to_confirm(f"Remove {slug} from the cluster config", slug)
    _provision(ctx, "destroy", slug)
    ship.ship(ctx, f"feat(sites): remove {slug}", paths=_site_paths(slug))
