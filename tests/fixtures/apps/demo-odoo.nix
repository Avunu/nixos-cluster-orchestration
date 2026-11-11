# demo-odoo — the odoo kind, over a stub package.
{ pkgs, ... }:
{
  homeNode = "node1";
  odoo = {
    package = import ../stubs/odoo.nix { inherit pkgs; };
    hostname = "odoo.example.com";
    workers = 4;
    maxCronThreads = 2;
    serverWideModules = [
      "base"
      "web"
      "queue_job"
    ];
  };
  tunnel.id = "00000000-0000-4000-8000-000000000001";
  resources = {
    cpu = 2000;
    memoryMB = 4096;
  };
}
