from datetime import datetime
import json

from model.entity import Entity
from config.args import SnoopArguments
from network.arp import ArpScan
from REST.api import RestInterface
from network.net_tools import get_hostname
from network.ports import CommonPorts
from network.scan import Scan
from tools.colors import BaseColors


def scan_entities(clients, scan_type):
    for client in clients:
        for port in CommonPorts.list():
            scan_host(client.ip_v4, port, scan_type)


def scan_host(ip, port, scan_type):
    scanner = Scan(ip, port)
    result = scanner.run_scan(scan_type)
    if result:
        print(f"{BaseColors.CYAN}" + ip + ":" + str(port) + f"{BaseColors.ENDC}")


def report_entities(clients):
    api = RestInterface()
    for client in clients:
        time = datetime.now().isoformat()

        ip4_addr = client.ip_v4
        mac_addr = client.mac_address

        entity = Entity(ip_v4=ip4_addr,
                        ip_v6=None,
                        hostname=get_hostname(ip4_addr),
                        mac_address=mac_addr,
                        first_found_date=time, last_seen_date=time)

        response = api.get_entities(params={"ip_v4": ip4_addr})
        if response.status_code == 200:
            entities = json.loads(response.text)
            if entities.get('count') == 0:
                api.create_entity(data=entity.__dict__)
            else:
                original = entities.get('results')[0]
                entity.first_found_date = original.get('first_found_date')
                api.update_entity(original.get('id'), data=entity.__dict__)


def extract_entities(arp_results):
    entity_list = []
    for sent, result in arp_results:
        entity_list.append(Entity(ip_v4=result.psrc, mac_address=result.hwsrc))
    return entity_list


def parse_args():
    return SnoopArguments().parse()


def get_clients():
    # ARP Scan
    arp = ArpScan(interface=arguments.interface, network=arguments.network, timeout=arguments.timeout)
    scan_results = arp.scan()
    # Get entities from scan
    return extract_entities(scan_results)


arguments = parse_args()
client_list = get_clients()
report_entities(client_list)

if arguments.scan:
    scan_entities(client_list, arguments.scan)
