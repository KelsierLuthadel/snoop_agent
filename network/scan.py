from enum import IntFlag
import random

from scapy.layers.inet import IP, TCP, ICMP, UDP
from scapy.sendrecv import sr1, sr, srp1
from scapy.volatile import RandShort


class TcpFlags(IntFlag):
    FIN = 0x01
    SYN = 0x02
    RST = 0x04
    PSH = 0x08
    ACK = 0x10
    URG = 0x20
    ECE = 0x40
    CWR = 0x80


# TCP 3-way handshake
#
# The client initializes a connection by sending a TCP packets with the SYN flag set. If the port is open and accepting
# connections, a TCP packet with the SYN and ACK flags are returned. The client will acknowledge this by sending a
# packet with the ACK and RST flags to complete the 3-way handshake.
#
# [client]    SYN+port -> [server]
# [client] <- SYN+ACK     [server]
# [client]    RST+ACK ->  [server]
def tcp_connect_scan(ip, port, timeout=1):
    return three_way_handshake(ip, port, "S", "AR", timeout)


# TCP stealth
#
# The client sends a TCP packet with the SYN flag set. If the port is open and accepting connections, a TCP packet with
# the SYN and ACK flags are returned. The client will send a packet with an RST flag to complete the operation.
#
# [client]    SYN+port -> [server]
# [client] <- SYN+ACK     [server]
# [client]    RST ->      [server]
def tcp_stealth_scan(ip, port, timeout=1):
    return three_way_handshake(ip, port, "S", "R", timeout)


# XMAS scan
#
# The client sends a TCP packet with the PSH, FIN and URG flags set. If the port is open, there will be no response
# from the server
#
# [client]    PSH+GIN+URG+port -> [server]
def tcp_xmas_scan(ip, port, timeout=1):
    return two_way_handshake(ip, port, "FPU", timeout)


# FIN scan
#
# The client sends a TCP packet with the FIN flag set. If the port is open, there will be no response
# from the server
#
# [client]    FIN+port -> [server]
def tcp_fin_scan(ip, port, timeout=1):
    return two_way_handshake(ip, port, "F", timeout)


# NULL scan
#
# The client sends a TCP packet with no flags set. If the port is open, there will be no response
# from the server
#
# [client]    port -> [server]
def tcp_null_scan(ip, port, timeout=1):
    return two_way_handshake(ip, port, "", timeout)


# ACK scan
#
# This scan does not determine if a port is open or closed, it determines if a stateful firewall is present.
#
# The client sends a TCP packet with the ACK flag set. If the server responds with a packet containing an RST flag, then
# the port is unfiltered and a stateful firewall is not present.
#
# [client]    ACK+port -> [server]
def tcp_ack_scan(ip, port, timeout=1):
    src_port = RandShort()
    response = tcp_connection(ip=ip, src_port=src_port, dst_port=port, flags="A", timeout=timeout)

    if response is None:
        return False  # Filtered
    elif response.haslayer(TCP):
        if response.getlayer(TCP).flags == TcpFlags.RST:
            return True  # Unfiltered
        elif response.haslayer(ICMP):
            if int(response.getlayer(ICMP).type == 3 and int(response.getlayer(ICMP).code) in [1, 2, 3, 9, 10, 13]):
                return False  # Filtered


# Window scan
#
# The client sends a TCP packet with the ACK flag set. If the server responds with a packet containing an RST flag, then
# the port is unfiltered and a stateful firewall is not present.
#
# [client]    UDP packet+port -> [server]
# [client] <- UDP packet         [server]
def tcp_window_scan(ip, port, timeout=1):
    src_port = RandShort()
    response = tcp_connection(ip=ip, src_port=src_port, dst_port=port, flags="A", timeout=timeout)

    if response is None:
        return False  # No response
    elif response.haslayer(TCP):
        if response.getlayer(TCP).windows == 0:
            return False  # Closed
        elif response.haslayer(TCP):
            if int(response.getlayer(TCP).window > 0):
                return True


# UDP scan
#
# The client sends a UDP packet. If the server responds with a packet then the port is open.
#
# [client]    UDP packet+port -> [server]
# [client] <- UDP packet         [server]
def udp_port_scan(ip, port, timeout=1):
    response = udp_connection(ip=ip, src_port=RandShort(), dst_port=port, timeout=timeout)
    if response is None:
        return True
    if response.haslayer(ICMP):
        return False
    if response.haslayer(UDP):
        return True

    return False


def three_way_handshake(ip, port, src_flags, dst_flags, timeout=1):
    # src_port = RandShort()
    src_port = random.randint(1025, 65534)
    response = tcp_connection(ip=ip, src_port=src_port, dst_port=port, flags=src_flags, timeout=timeout)

    if response is None:
        return False
    elif response.haslayer(TCP):
        if response.getlayer(TCP).flags == TcpFlags.SYN | TcpFlags.ACK:
            send_rst = sr(IP(dst=ip) / TCP(sport=src_port, dport=port, flags=dst_flags), timeout=timeout)
            return True
        elif response.getlayer(TCP).flags == TcpFlags.ACK | TcpFlags.RST:
            return False
        elif response.haslayer(ICMP):
            if int(response.getlayer(ICMP).type == 3 and int(response.getlayer(ICMP).code) in [1, 2, 3, 9, 10, 13]):
                return False  # Filtered


def two_way_handshake(ip, port, flags, timeout=1):
    src_port = RandShort()
    response = tcp_connection(ip=ip, src_port=src_port, dst_port=port, flags=flags, timeout=timeout)

    if response is None:
        return True
    elif response.haslayer(TCP):
        if response.getlayer(TCP).flags == TcpFlags.SYN | TcpFlags.ACK:
            return False
        elif response.haslayer(ICMP):
            if int(response.getlayer(ICMP).type == 3 and int(response.getlayer(ICMP).code) in [1, 2, 3, 9, 10, 13]):
                return False  # Filtered


def tcp_connection(ip, src_port, dst_port, flags, timeout=1):
    request = IP(dst=ip) / TCP(sport=src_port, dport=dst_port, flags=flags)
    response = srp1(request, timeout=timeout, verbose=0)
    return response


def udp_connection(ip, src_port, dst_port, timeout=1):
    request = IP(dst=ip) / UDP(sport=src_port, dport=dst_port)
    response = sr1(request, timeout=timeout)
    return response


class Scan:
    def __init__(self, dst_ip, dst_port):
        self.dst_ip = dst_ip
        self.dst_port = dst_port

    def run_scan(self, scan_type):
        match scan_type:
            case 'stealth':
                return tcp_stealth_scan(ip=self.dst_ip, port=self.dst_port)
            case 'xmas':
                return tcp_xmas_scan(ip=self.dst_ip, port=self.dst_port)
            case 'fin':
                return tcp_fin_scan(ip=self.dst_ip, port=self.dst_port)
            case 'null':
                return tcp_null_scan(ip=self.dst_ip, port=self.dst_port)
            case 'ack':
                return tcp_ack_scan(ip=self.dst_ip, port=self.dst_port)
            case 'window':
                return tcp_window_scan(ip=self.dst_ip, port=self.dst_port)
            case 'udp':
                return udp_port_scan(ip=self.dst_ip, port=self.dst_port)
            case 'tcp' | _:
                return tcp_connect_scan(ip=self.dst_ip, port=self.dst_port)
