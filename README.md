# Ports

## About

Ports is a Port Scanner

## Requirements
Requires root for raw network access
and [libpcap](https://www.tcpdump.org).

## Usage

* [x] Host discovery using ARP scan:
```
$ sudo ports arp 192.168.10.0/24
192.168.0.1     3F:77:B0:33:35:BB Some Vendor
192.168.0.2     3E:77:B0:33:35:BB Some Vendor
```

* [ ] Syn (Stealth) Port Scanning
```
$ sudo ports scan --syn 192.168.0.100
...
```

