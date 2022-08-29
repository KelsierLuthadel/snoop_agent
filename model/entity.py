import json


class Entity:
    def __init__(self, ip_v4, ip_v6=None, mac_address=None, hostname="", first_found_date=None, last_seen_date=None):
        self.ip_v4 = ip_v4
        self.ip_v6 = ip_v6
        self.hostname = hostname
        self.mac_address = mac_address
        self.first_found_date = first_found_date
        self.last_seen_date = last_seen_date

    def json(self):
        return json.dumps(self, default=lambda o: o.__dict__, sort_keys=True, indent=4)

    def minimal_json(self):
        return json.dumps({
            "ip_v4": self.ip_v4,
            "hostname": self.hostname,
            "mac_address": self.mac_address,
        }, default=lambda o: o.__dict__, sort_keys=True, indent=4)



