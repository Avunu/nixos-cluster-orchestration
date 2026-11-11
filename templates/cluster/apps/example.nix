# One file per app; the file name is the app's name. This one is switched off, so
# it deploys nothing. Delete it when you add your first real app.
{ inputs, ... }:
{
  enable = false;
  homeNode = "node1";
  odoo = {
    package = inputs.my-odoo-project.packages.x86_64-linux.default;
    hostname = "odoo.example.com";
  };
  tunnel.id = "00000000-0000-4000-8000-000000000000";
  resources = {
    cpu = 2000;
    memoryMB = 4096;
  };
}
