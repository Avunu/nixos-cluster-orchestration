"""Importing this package registers every group and action."""

from avc.actions import group

group("status", "Status", 0)
group("site", "WordPress sites", 10)
group("app", "Apps", 20)
group("secrets", "Secrets", 30)
group("deploy", "Deploy", 40)
group("boot", "Boot", 50)
group("audit", "Audit trail", 60)
group("ci", "Pipeline", 70)

from avc.flows import apps, audit, boot, ci, deploy, sites, status, secrets  # noqa: E402, F401
