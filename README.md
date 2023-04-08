# Ports

## About

Ports is a Port Scanner (functional but incomplete).

## Requirements
Requires root for raw network access
and [libpcap](https://www.tcpdump.org).

## Usage
* [x] Syn (Stealth) Port Scanning
```
$ sudo ports syn 192.168.0.111 -p22
Starting Ports at 05 Apr 23 07:58 BST
Ports scan report for (192.168.0.111)
Host is up (34.35475ms latency)

PORT    STATE  SERVICE
22      open   ssh
Mac Address: dc:a6:32:43:83:cb (Raspberry Pi Trading Ltd)

Ports done: 1 IP address (1 host up) scanned in 0.011364 seconds
```
Ports may be expressed as ranges, e.g. -p0-10000
```
$ sudo ports syn scanme.nmap.org -p0-10000
Starting Ports at 08 Apr 23 10:54 BST
Ports scan report for (scanme.nmap.org)
Host is up (164.267875ms latency)

PORT    STATE  SERVICE
22      open   ssh
80      open   http
9929    open   

Ports done: 1 IP address (1 host up) scanned in 12.001028 seconds
```


* [x] Host discovery using ARP scan:
```
$ sudo ports arp 192.168.10.0/24
192.168.0.1     3F:77:B0:33:35:BB Some Vendor
192.168.0.2     3E:77:B0:33:35:BB Some Other Vendor
```

## Todo
lots.

## References

* [https://github.com/google/gopacket](https://github.com/google/gopacket)
* [https://nmap.org/book/scan-methods.html](https://nmap.org/book/scan-methods.html)
* [github.com/libp2p/go-netroute](github.com/libp2p/go-netroute)