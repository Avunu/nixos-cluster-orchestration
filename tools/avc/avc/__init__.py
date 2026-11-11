"""avc — one guided entrypoint for operating a nixos-cluster-orchestration cluster.

`avc` alone opens the status overview and a menu; `avc <group> <action> …`
runs the same action directly. Both are generated from one registry
(avc.actions), so every menu entry is scriptable and vice versa.
"""
