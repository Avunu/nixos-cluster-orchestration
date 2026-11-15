# lib/nomad.nix — Nomad client limits that app definitions are checked against,
# and the namespace and account the apps run as.
{
  # The client's max_kill_timeout (modules/cluster-common.nix). Nomad caps
  # every task's kill_timeout at it, silently -- its default is 30s -- so
  # lib/mk-app-container.nix asserts each app's nomad.killTimeoutSeconds fits.
  maxKillTimeoutSeconds = 600;

  # A node that cannot reach a server stops its stateful apps this long after its
  # last heartbeat (disconnect.stop_on_client_after, lib/mk-app-container.nix): by
  # then the servers have placed them elsewhere, on a copy of their state, and two
  # copies must not both be written to. The node taking an app over waits this long,
  # and the app's kill timeout, before it starts it (modules/app-state.nix). Shorter
  # fails over sooner, and stops every stateful app in the cluster when the servers
  # are away for that long, as for a blip on the control VLAN.
  stopOnClientAfterSeconds = 60;

  # Every app's job lives here (lib/mk-app-container.nix), and it is the only
  # namespace that may run raw_exec (modules/nomad-acl.nix). Every scoped token is
  # granted it by name, and the fence and every CLI on a node query it by name: a
  # fence asking any other namespace sees no allocations, and would stop every
  # container. So it is one constant, not a string repeated per module.
  appsNamespace = "apps";

  # The only account a raw_exec task may run as (modules/cluster-common.nix). Every
  # app's task names it (lib/mk-app-container.nix), and it may only start and stop
  # declared containers (the polkit rule in modules/app-container.nix). It has no
  # network at all: the ruleset's output chain rejects this uid by number
  # (modules/overlay-network.nix), so the uid is a constant too, not looked up.
  # modules/boot-security.nix refuses any other account at this uid.
  appsUser = "nomad-apps";
  appsUid = 4096;

  # raw_exec refuses every uid in these ranges, which leaves exactly appsUid and
  # everything above 65535. Nothing wider: Nomad materialises the ranges as a set,
  # and "0-4095,4097-4294967294" OOM-panicked the agent. The gap above 65535 is
  # closed in Nix instead: modules/boot-security.nix refuses any account there, and a
  # task can only run as an account that exists.
  rawExecDeniedUids = "0-4095,4097-65535";
}
