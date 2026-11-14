# One file per app; the file name is the app's name. This one is switched off, so
# it deploys nothing. Delete it when you add your first real app.
{ inputs, ... }:
{
  enable = false;
  odoo = {
    package = inputs.my-odoo-project.packages.x86_64-linux.default;
    hostname = "odoo.example.com";
  };
  tunnel.id = "00000000-0000-4000-8000-000000000000";
  # A container per pull request of the project, on a copy of this app's database
  # (needs `ci.url` in topology.nix). `input` is the name in flake.nix; `inputUrl`
  # only because that input is not a plain `github:` one.
  # preview = {
  #   slots = 2;
  #   input = "my-odoo-project";
  #   repo = "OWNER/my-odoo-project";
  #   inputUrl = "git+https://github.com/OWNER/my-odoo-project.git?ref={ref}&rev={rev}&submodules=1";
  # };
  resources = {
    cpu = 2000;
    memoryMB = 4096;
  };
}
