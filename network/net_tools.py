import socket

from scapy.layers.inet import IP, ICMP
from scapy.sendrecv import sr1


def get_hostname(host_ip):
    host = ''
    try:
        host = socket.gethostbyaddr(host_ip)[0]
    finally:
        return host


def host_alive(host_ip, timeout=1):
    ping = IP(dst=host_ip) / ICMP()
    result = sr1(ping, timeout=timeout, verbose=0)
    return True if result is not None else False

