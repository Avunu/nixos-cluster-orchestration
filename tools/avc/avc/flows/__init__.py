"""Importing this package registers every group and action."""

from avc.actions import group

group("status", "Status", 0)
group("site", "WordPress sites", 10)
group("app", "Apps", 20)
group("secrets", "Secrets", 30)
group("deploy", "Deploy", 40)
group("boot", "Boot", 50)
group("audit", "Audit trail", 60)

from avc.flows import apps, audit, boot, deploy, sites, status, secrets  # noqa: E402, F401
