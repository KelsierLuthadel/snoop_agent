import argparse
from argparse import ArgumentParser

MIN_SECONDS = 1
MAX_SECONDS = 10


def range_limit_timeout(arg):
    try:
        val = int(arg)
    except ValueError:
        raise argparse.ArgumentError(arg, "Must be an integer")
    if val < MIN_SECONDS or val > MAX_SECONDS:
        raise argparse.ArgumentTypeError(
            "Argument must be between " + str(MIN_SECONDS) + " and  " + str(MAX_SECONDS))
    return val


class SnoopArguments:
    def __init__(self):
        self.parser = ArgumentParser(description="ARP scan")
        self.menu()

    def menu(self):
        self.parser.add_argument("-i", "--interface", dest="interface", type=str,
                                 help="interface for ARP scan", metavar="INTERFACE")
        self.parser.add_argument("-n", "--network", dest="network", type=str,
                                 help="network to scan", metavar="NETWORK")
        self.parser.add_argument("-t", "--timeout", dest="timeout", type=range_limit_timeout,
                                 help="timeout value in seconds", metavar="TIMEOUT")
        self.parser.add_argument("-s", "--scan", dest="scan", type=str,
                                 help="Scan type", metavar="SCAN")

    def parse(self):
        args = self.parser.parse_args()
        return args
