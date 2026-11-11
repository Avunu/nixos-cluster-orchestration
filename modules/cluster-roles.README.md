# cluster-roles

Assigns this cluster's **singleton** roles to machines by tag.

Every node in this cluster runs the same base modules — the Nomad agent (a client
on `worker` nodes, a server on `nomad-server` ones), the JuiceFS client, the node
exporter, the container fencer. A handful of services
must run on exactly one node, and this service is how that is expressed.

| Role | What it adds | Why exactly one |
|---|---|---|
| `juicefs-meta` | PostgreSQL metadata engine + volume format | Two engines over one S3 bucket is a split-brain filesystem — silent data loss |
| `nomad-leader` | Registers rendered jobspecs after raft leadership | Job submission is idempotent, so N registrars are just churn against the leader on every deploy |
| `metrics` | Prometheus, Loki, Alertmanager + Nomad autoscaler | Two autoscaler agents would both act on the same scaling policies; a second needs leader election first |

## Usage

Membership comes from `tags` in the topology, projected into the
inventory by `lib/mk-cluster.nix`:

```nix
inventory.instances.cluster-roles = {
  module = { name = "cluster-roles"; input = "self"; };
  roles.juicefs-meta.tags = [ "juicefs-meta" ];
  roles.nomad-leader.tags = [ "nomad-leader" ];
  roles.metrics.tags = [ "metrics" ];
};
```

## Why this exists

It replaces `nodeName == builtins.head (builtins.attrNames topology.nodes)`,
which appeared in three separate modules and silently elected whichever node
sorted first alphabetically. Renaming a node — or adding one that sorted
earlier — would have moved the metadata engine and the job registrar without
anyone editing those modules.

## Enforcement

Two independent layers, and they fail at different times:

- `manifest.constraints.roles.<r>.maxMachines = 1` surfaces through
  `clanInternals.cliChecks` (severity `error`). This is a **tooling** check —
  the clan CLI reads it. It is *not* forced by evaluating
  `nixosConfigurations`, so on its own it will not stop a `nixos-rebuild`.
- `clusterLib.net.soleTaggedNode` **throws during evaluation** while building
  the JuiceFS client config, which every node imports.

Keep both. The throw protects a pull-deployed node that never runs the CLI; the
constraint tells a human which role and which machines are at fault.
