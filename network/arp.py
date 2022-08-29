from scapy.all import srp, conf
from scapy.layers.l2 import ARP, Ether

DST = "ff:ff:ff:ff:ff:ff"


class ArpScan:
    def __init__(self, interface, network, timeout=1, interval=0.2, retry=-3):
        self.interface = interface
        self.network = network
        self.timeout = timeout
        self.inter = interval
        self.retry = retry

    def scan(self):
        conf.verb = 0
        answers, unanswered = srp(Ether(dst=DST) / ARP(pdst=self.network),
                                  timeout=self.timeout,
                                  iface=self.interface, retry=self.retry)
        return answers

