# demo-wpdb — the wpdb kind: the one MariaDB every WordPress site shares.
{ ... }:
{
  wpdb = {
    # Below node1's DHCP pool, which starts at .10 (appDhcpPoolOffset).
    address = "10.20.1.2";
    bufferPoolSize = "2G";
  };
  resources = {
    cpu = 2000;
    memoryMB = 4096;
  };
}
