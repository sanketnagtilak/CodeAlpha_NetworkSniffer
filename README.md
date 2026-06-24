# CodeAlpha Internship - Task 1: Basic Network Sniffer

This is my submission for Task 1 of the CodeAlpha Cybersecurity Internship.

## What it does

It's a simple network packet sniffer written in Python using the `scapy` library.
It captures live traffic on your network interface and prints basic details for
each packet - things like source/destination IP, protocol, ports, and TTL.

I kept it fairly simple since the task description just asked for basic packet
capturing and understanding how data flows through the network, but I added a
few extra bits like:
- showing common port names (80 = HTTP, 443 = HTTPS, etc.)
- a short preview of TCP payload if there is one
- pulling out the domain name from DNS queries
- a summary printed at the end showing how many packets of each type were seen

## Requirements

- Python 3
- scapy

```
pip install scapy
```

## How to run

Since it captures raw packets you need to run it with admin/root privileges.

```
sudo python3 network_sniffer.py
```

Some other ways to run it:

```
# only capture 20 packets then stop
sudo python3 network_sniffer.py -c 20

# capture on a specific interface
sudo python3 network_sniffer.py -i eth0

# only show HTTP traffic
sudo python3 network_sniffer.py -f "tcp port 80"

# only show DNS traffic
sudo python3 network_sniffer.py -f "udp port 53"
```

On Windows you'll need Npcap installed (https://npcap.com/) for scapy to be
able to sniff packets.

## Example output

```
Starting Network Sniffer...
Interface : default
Filter    : none (capturing everything)
Press Ctrl+C to stop capturing

[1] 14:02:11 | TCP | 192.168.1.5:51322 -> 142.250.182.4:443/HTTPS | TTL=64 | Flags=S
[2] 14:02:11 | UDP | 192.168.1.5:54711 -> 8.8.8.8:53/DNS | TTL=64
      DNS query for: www.google.com.
[3] 14:02:12 | ICMP | 192.168.1.1 -> 192.168.1.5 | Echo Reply (pong)
[4] 14:02:13 | ARP Request | 192.168.1.1 -> 192.168.1.254

--------------------------------------------------
CAPTURE SUMMARY
--------------------------------------------------
Total packets captured : 4
TCP packets             : 1
UDP packets             : 1
ICMP packets            : 1
ARP packets             : 1
Other                   : 0
--------------------------------------------------
```

## What I learned

This task helped me actually understand how packets are structured instead of
just reading about OSI layers in theory. Seeing the TCP three-way handshake
flags (SYN, SYN-ACK, ACK) show up in real time made a lot more sense than
just reading about it. Also got more comfortable with scapy's syntax for
digging into different protocol layers.

## Note

This is for learning purposes only. Only run this on a network you own or have
permission to monitor - sniffing traffic on networks you don't have permission
for is illegal in most places.

---
CodeAlpha Cybersecurity Internship - Task 1
