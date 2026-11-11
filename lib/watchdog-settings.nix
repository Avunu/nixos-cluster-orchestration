# lib/watchdog-settings.nix — systemd's use of the hardware watchdog on every node.
# Here so that tests/deploy-safety.nix proves the values the nodes run.
#
# A node with a frozen PID 1 answers ping and holds its Nomad allocations, while nothing
# on it can restart anything. Nobody is near these machines, so it resets itself.
{
  RuntimeWatchdogSec = "10s";
  # A shutdown that hangs still ends in a reset.
  RebootWatchdogSec = "1min";
}
