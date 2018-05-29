
# arp-scanner

Simple tool to discover hosts on your network using ARP requests.

Works by firing ARP requests for each possible address and listening for ARP replies.

Built in rust using the `pnet` crate and works on Linux, Windows and probably OS X (untested).

## Usage (note requires root)

### Print help:

```bash
# arp-scanner -h
  ____  ____   ____        _____   __   ____  ____   ____     ___  ____
 /    ||    \ |    \      / ___/  /  ] /    ||    \ |    \   /  _]|    \
|  o  ||  D  )|  o  )    (   \_  /  / |  o  ||  _  ||  _  | /  [_ |  D  )
|     ||    / |   _/      \__  |/  /  |     ||  |  ||  |  ||    _]|    /
|  _  ||    \ |  |        /  \ /   \_ |  _  ||  |  ||  |  ||   [_ |    \
|  |  ||  .  \|  |        \    \     ||  |  ||  |  ||  |  ||     ||  .  \
|__|__||__|\_||__|         \___|\____||__|__||__|__||__|__||_____||__|\_|

Gavyn Riebau <gavyn.riebau@gmail.com>

Runs an ARP scan to discover all hosts in the network

USAGE:
    arp-scanner [FLAGS] [OPTIONS] --interface <INTERFACE> --index <INTERFACE_INDEX>

FLAGS:
    -h, --help       Prints help information
    -l, --list       List available interfaces including their index
    -V, --version    Prints version information

OPTIONS:
    -i, --interface <INTERFACE>      The interface on which the scan will be performed
    -x, --index <INTERFACE_INDEX>    The index of the interface rather than the interface name.
    -o, --out <FILE>                 Write results to a file in CSV format
```

### List interfaces:

This is useful to find the index of the interface on which your like to perform the scan.

```bash
# arp-scanner -l

Listing interfaces:
lo: flags=10049<UP,LOOPBACK>
      index: 1
      ether: 00:00:00:00:00:00
       inet: 127.0.0.1/8
      inet6: ::1/128
enp3s0: flags=1003<UP,BROADCAST,MULTICAST>
      index: 2
      ether: [REDACTED]
wlp6s0: flags=11043<UP,BROADCAST,MULTICAST>
      index: 3
      ether: [REDACTED]
       inet: 192.168.86.147/24
      inet6: [REDACTED]
virbr0: flags=1003<UP,BROADCAST,MULTICAST>
      index: 4
      ether: [REDACTED]
       inet: 192.168.122.1/24
virbr0-nic: flags=1002<BROADCAST,MULTICAST>
      index: 5
      ether: [REDACTED]

```

### Run an ARP scan on an interface using the interface index:

`# arp-scanner -x <index>`

e.g.

```bash
# arp-scanner -x 3
  ____  ____   ____        _____   __   ____  ____   ____     ___  ____
 /    ||    \ |    \      / ___/  /  ] /    ||    \ |    \   /  _]|    \
|  o  ||  D  )|  o  )    (   \_  /  / |  o  ||  _  ||  _  | /  [_ |  D  )
|     ||    / |   _/      \__  |/  /  |     ||  |  ||  |  ||    _]|    /
|  _  ||    \ |  |        /  \ /   \_ |  _  ||  |  ||  |  ||   [_ |    \
|  |  ||  .  \|  |        \    \     ||  |  ||  |  ||  |  ||     ||  .  \
|__|__||__|\_||__|         \___|\____||__|__||__|__||__|__||_____||__|\_|

Using interface: wlp6s0: flags=11043<UP,BROADCAST,MULTICAST>
      index: 3
      ether: [REDACTED]
       inet: 192.168.86.147/24
      inet6: [REDACTED]

[X] Sending ARP requests...
[X] Collecting results...

+----------------+-------------------+
| host           | mac               |
+----------------+-------------------+
| 192.168.86.1   | [REDACTED]        |
| 192.168.86.22  | [REDACTED]        |
| 192.168.86.21  | [REDACTED]        |
| 192.168.86.147 | [REDACTED]        |
| 192.168.86.218 | [REDACTED]        |
| 192.168.86.219 | [REDACTED]        |
| 192.168.86.222 | [REDACTED]        |
| 192.168.86.231 | [REDACTED]        |
| 192.168.86.233 | [REDACTED]        |
| 192.168.86.232 | [REDACTED]        |
+----------------+-------------------+

```

## Windows

To run on Windows you need to have the [WinPcap](https://www.winpcap.org/) library installed.

