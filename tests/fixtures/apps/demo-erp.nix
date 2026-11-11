# demo-erp — the frappe kind, over a stub package.
{ pkgs, ... }:
{
  homeNode = "node1";
  frappe = {
    package = import ../stubs/frappe.nix { inherit pkgs; };
    site = "erp.example.com";
    webThreads = 2;
    settings.allow_tests = false;
  };
  tunnel.id = "00000000-0000-4000-8000-000000000002";
  resources = {
    cpu = 2000;
    memoryMB = 6144;
  };
}
