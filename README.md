# liquidping
Basic command line ping utility designed for efficient latency monitoring of thousands of hosts

This code may require setting net.ipv4.ping_group_range sysctl on linux systems (sysctl -w net.ipv4.ping_group_range = "0 2147483647") due to the way the sockets are constructed.
