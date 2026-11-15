# Fails to evaluate unless the consumer's input reached the app file.
{ inputs, ... }:
assert inputs.private-flake.marker != null;
{
  resources = {
    cpu = 100;
    memoryMB = 256;
  };
  module = { };
}
