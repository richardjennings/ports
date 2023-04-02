# Ports

## About

Ports is a Port Scanner (functional but incomplete).

## Requirements
Requires root for raw network access
and [libpcap](https://www.tcpdump.org).

## Usage

* [x] Host discovery using ARP scan:
```
$ sudo ports arp 192.168.10.0/24
192.168.0.1     3F:77:B0:33:35:BB Some Vendor
192.168.0.2     3E:77:B0:33:35:BB Some Other Vendor
```

* [x] Syn (Stealth) Port Scanning
```
$ sudo ports scan syn 192.168.0.100 0 60000
using timeout 1m15s
syn scan for ip: 192.168.0.111, mac: 00:00:00:00:00:00, port range: 0-60000
22(ssh) open
53(domain) open
80(http) open
8080(http-alt) open
in 75.001091 seconds
```

## References

* [https://github.com/google/gopacket](https://github.com/google/gopacket)
* [https://nmap.org/book/scan-methods.html](https://nmap.org/book/scan-methods.html)
* [github.com/libp2p/go-netroute](github.com/libp2p/go-netroute)