#!/usr/bin/env python3

# CodeAlpha Cybersecurity Internship
# Task 1 - Basic Network Sniffer
# Name: sanket nagtilak
#
# This script captures live network packets using scapy and prints
# basic info about each one (source/dest IP, protocol, ports etc).
# Made this as part of my internship task, learned a lot about how
# packets actually look on the wire while building it.

from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP, DNS, Raw
import argparse
import datetime

# just keeping some simple counters so I can print a summary at the end
packet_count = 0
tcp_count = 0
udp_count = 0
icmp_count = 0
arp_count = 0
other_count = 0


# common ports so the output is a bit more readable than just numbers
common_ports = {
    20: "FTP-DATA",
    21: "FTP",
    22: "SSH",
    23: "TELNET",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    3306: "MySQL",
    3389: "RDP",
}


def get_port_name(port):
    # returns "port/SERVICE" if we know it, else just the port number
    if port in common_ports:
        return str(port) + "/" + common_ports[port]
    return str(port)


def process_packet(packet):
    """
    This function runs for every single packet that scapy captures.
    It checks what kind of packet it is and prints the relevant info.
    """
    global packet_count, tcp_count, udp_count, icmp_count, arp_count, other_count

    packet_count += 1
    time_now = datetime.datetime.now().strftime("%H:%M:%S")

    # ARP packets dont have an IP layer so check this first
    if packet.haslayer(ARP):
        arp_count += 1
        arp_layer = packet[ARP]
        if arp_layer.op == 1:
            arp_type = "ARP Request"
        else:
            arp_type = "ARP Reply"
        print(f"[{packet_count}] {time_now} | {arp_type} | {arp_layer.psrc} -> {arp_layer.pdst}")
        return

    # for everything else we need an IP layer
    if not packet.haslayer(IP):
        other_count += 1
        return

    ip_layer = packet[IP]
    src_ip = ip_layer.src
    dst_ip = ip_layer.dst
    ttl = ip_layer.ttl

    # ---------- TCP ----------
    if packet.haslayer(TCP):
        tcp_count += 1
        tcp_layer = packet[TCP]
        src_port = tcp_layer.sport
        dst_port = tcp_layer.dport

        # quick flag check, not super detailed but covers the basics
        flags = tcp_layer.flags
        flag_str = str(flags)

        print(f"[{packet_count}] {time_now} | TCP | {src_ip}:{src_port} -> "
              f"{dst_ip}:{get_port_name(dst_port)} | TTL={ttl} | Flags={flag_str}")

        # if there's a payload, show a short preview of it
        if packet.haslayer(Raw):
            raw_data = packet[Raw].load
            preview = raw_data[:40]
            try:
                preview_text = preview.decode("utf-8", errors="ignore")
                # remove weird characters so it doesnt mess up the terminal
                preview_text = "".join(ch if ch.isprintable() else "." for ch in preview_text)
                if preview_text.strip():
                    print(f"      payload preview: {preview_text}")
            except Exception:
                pass

    # ---------- UDP ----------
    elif packet.haslayer(UDP):
        udp_count += 1
        udp_layer = packet[UDP]
        src_port = udp_layer.sport
        dst_port = udp_layer.dport

        print(f"[{packet_count}] {time_now} | UDP | {src_ip}:{src_port} -> "
              f"{dst_ip}:{get_port_name(dst_port)} | TTL={ttl}")

        # if it's a DNS packet, try to grab the domain name being looked up
        if packet.haslayer(DNS):
            dns_layer = packet[DNS]
            if dns_layer.qd is not None:
                try:
                    query_name = dns_layer.qd.qname.decode()
                    print(f"      DNS query for: {query_name}")
                except Exception:
                    pass

    # ---------- ICMP ----------
    elif packet.haslayer(ICMP):
        icmp_count += 1
        icmp_layer = packet[ICMP]
        # type 8 = echo request (ping), type 0 = echo reply
        if icmp_layer.type == 8:
            icmp_msg = "Echo Request (ping)"
        elif icmp_layer.type == 0:
            icmp_msg = "Echo Reply (pong)"
        else:
            icmp_msg = f"Type {icmp_layer.type}"

        print(f"[{packet_count}] {time_now} | ICMP | {src_ip} -> {dst_ip} | {icmp_msg}")

    else:
        other_count += 1
        print(f"[{packet_count}] {time_now} | OTHER | {src_ip} -> {dst_ip} | proto={ip_layer.proto}")


def print_summary():
    print("\n" + "-" * 50)
    print("CAPTURE SUMMARY")
    print("-" * 50)
    print(f"Total packets captured : {packet_count}")
    print(f"TCP packets             : {tcp_count}")
    print(f"UDP packets             : {udp_count}")
    print(f"ICMP packets            : {icmp_count}")
    print(f"ARP packets             : {arp_count}")
    print(f"Other                   : {other_count}")
    print("-" * 50)


def main():
    parser = argparse.ArgumentParser(description="Basic Network Sniffer - CodeAlpha Task 1")
    parser.add_argument("-i", "--interface", help="network interface to sniff on (e.g. eth0)")
    parser.add_argument("-c", "--count", type=int, default=0,
                         help="number of packets to capture (0 = capture until you stop it)")
    parser.add_argument("-f", "--filter", default="",
                         help="BPF filter string, e.g. 'tcp port 80' or 'icmp'")
    args = parser.parse_args()

    print("Starting Network Sniffer...")
    print("Interface :", args.interface if args.interface else "default")
    print("Filter    :", args.filter if args.filter else "none (capturing everything)")
    print("Press Ctrl+C to stop capturing\n")

    try:
        sniff(
            iface=args.interface if args.interface else None,
            filter=args.filter if args.filter else None,
            prn=process_packet,
            count=args.count,
            store=False,
        )
    except KeyboardInterrupt:
        print("\nStopped by user.")
    except PermissionError:
        print("Permission denied. Try running this with sudo.")
    finally:
        print_summary()


if __name__ == "__main__":
    main()
