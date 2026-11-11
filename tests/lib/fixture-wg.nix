# WireGuard keys for the VM tests' control mesh. Throwaway values made once with
# `wg genkey` for this repository: no machine anywhere uses them, and they reach
# nothing. Committed, like the rest of the fixture, so that a test can name them at
# evaluation (the netdev's PublicKey); a key made at build time would be
# import-from-derivation, which `nix flake check --no-build` refuses.
#
# The public halves are also tests/fixtures/vars/per-machine/<node>/wg-ctrl/public/value,
# which is where modules/mesh-control.nix reads them, as on a real site. `rotated` is
# the key a rotation test changes to.
{
  node1 = {
    private = "YLQXy5WbX83xo32H5JxsvFoU1SbT9GIYfSMYKC1imn8=";
    public = "0t8Ul5Z5m+TbMSrfTUzE7zeIvhEctL1G/2kzlJH8s0o=";
  };
  node2 = {
    private = "gFZK0/nqdgKhWe87iuQDCI+c30cTv3az1lO3+ZNiclc=";
    public = "yl0pZWZ+3k6VrxrTyEej4XdblutBQLLlVCmPGcXrtnc=";
  };
  node3 = {
    private = "+AFmlB7Z9qHG/xsrLGq3/xYxgEP1R/VFpn4cVAiLflQ=";
    public = "ROEwXCOYpAM9SB2vxrqkAHlsvPkvvQU23O1M9NeqV2s=";
  };
  rotated = {
    private = "QJhRajazUy3l4xKC/OzChxNKx/MMRvXj/wRyySd4eW8=";
    public = "vMU/thZN6qxnew3atHjjbxMj7oKibWItCY0BaUggY2I=";
  };
}
