#!/usr/bin/python3 -u

import argparse
import json
import os
import requests
import socket
from subprocess import run, PIPE
import sys
import time
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

import snmp_passpersist
from pySMART import DeviceList

from lib.dmidecode import DMIDecode


REFRESH = 60  # in seconds
BASE = '.1.3.6.1.4.1.45956.1.1.128'
SMART_KEYS = ('name',
              'model',
              'serial',
              'firmware',
              'is_ssd',
              '_capacity',
              'temperature')
SMART_ATTRIBUTE_KEYS = ('name',
                        'flags',
                        '_value',
                        '_worst',
                        '_thresh',
                        'type',
                        'updated',
                        'when_failed',
                        'raw')
BGP_SUMMARY_KEYS = ('neighbor_ip_address', 'version', 'as', 'messages_received',
                    'messages_sent', 'tbl_ver', 'in_q', 'out_q', 'up_down',
                    'state_prefixes_received', 'prefixes_sent', 'description')


class UnauthorizedException(Exception):
    pass


class RestGraphqlApi(object):
    """Representation of REST connection."""

    token = None
    authorized = False

    def __init__(self, host='localhost', verify=False, user='admin', password=None):
        self.host = host
        self.verify = verify
        self.user = user
        self.password = password

    def get(self, location, authorization_required=True):
        """Get data per REST API."""
        url = 'https://{}/api/v1/{}'.format(self.host, location.strip('/'))
        headers = {
            'Content-Type': 'application/json',
        }
        if authorization_required:
            if not self.authorized:
                self.login()
            if self.token:
                headers['Authorization'] = 'Bearer {}'.format(self.token)
        request = requests.get(
            url, headers=headers,
            verify=self.verify)
        return request

    def post(self, location, json, authorization_required=True):
        """Send data per REST API via post."""
        url = 'https://{}/api/v1/{}'.format(self.host, location.strip('/'))
        headers = {
            'Content-Type': 'application/json',
        }
        # Login if not yet done
        if authorization_required:
            if not self.authorized:
                self.login()
            if self.token:
                headers['Authorization'] = 'Bearer {}'.format(self.token)
        request = requests.post(
            url, headers=headers, json=json,
            verify=self.verify)
        return request

    def patch(self, location, json, authorization_required=True):
        """Send data per REST API via patch."""
        url = 'https://{}/api/v1/{}'.format(self.host, location.strip('/'))
        headers = {
            'Content-Type': 'application/json',
        }
        # Login if not yet done
        if authorization_required:
            if not self.authorized:
                self.login()
            if self.token:
                headers['Authorization'] = 'Bearer {}'.format(self.token)
        request = requests.patch(
            url, headers=headers, json=json,
            verify=self.verify)
        return request

    def login(self):
        json = {
            'username': self.user,
        }
        if self.password:
            json['password'] = self.password
        else:
            key_file = 'pdc_ssh_key'
            if not os.path.isfile(key_file):
                key_file = '/home/admin/.ssh/pdc_ssh_key'

            key_content = ''
            with open(key_file) as fd:
                key_content = fd.read()
            json['local'] = key_content
        request = self.post('/login', json, authorization_required=False)
        if request.status_code == 200:
            self.token = request.json()['token']
            self.authorized = True
        else:
            message = request.json()['message']
            raise UnauthorizedException(message)


def parse_arguments():
    """Get commandline arguments."""
    parser = argparse.ArgumentParser(
        description='Provide LTE stats through SNMP')
    parser.add_argument('--host', help='API host')
    parser.add_argument('--user', help='API username')
    parser.add_argument('--password', help='API password')
    parser.add_argument('--no-network', action='store_true', help='Do not expose network tables')
    parser.add_argument('--no-dmi', action='store_true', help='Do not call dmidecode')
    parser.add_argument('--no-smart', action='store_true', help='Do not collect SMART data')
    parser.add_argument('--no-bgp', action='store_true', help='Do not collect BGP stats')
    return parser.parse_args()


def error(*msg):
    print(*msg)
    sys.exit(1)


def read_socket(socket):
    CHUNK_SIZE = 8192
    buffer = bytearray()
    while True:
      chunk = socket.recv(CHUNK_SIZE)
      buffer.extend(chunk)
      if b'\0' in chunk or not chunk:
        break
    return buffer


def get_network_interfaces(api):
    json = {
        'query': '{ allNetworkInterfaces { nodes { globalId name description addresses { nodes { ipAddress prefixLength gateway } } state { addresses { ipAddress prefixLength gateway } } deviceInterface { name } } } }'
    }
    request = api.post('/graphql', json)
    interfaces = []
    if request.status_code == 200:
        for i in request.json()['data']['allNetworkInterfaces']['nodes']:
            # for static IP config address is in "addresses"
            if i['addresses']['nodes']:
                address = i['addresses']['nodes'][0]
            # for DHCP IP config address is in "state"
            elif i['state']['addresses']:
                address = i['state']['addresses'][0]
            # avoid 'None' as description
            description = ''
            if i['description']:
                description = i['description']
            interface = {
                'giid': i['globalId'],
                'name': i['name'],
                'device_name': i['deviceInterface']['name'],
                'description': description,
                'ip_address': address['ipAddress'],
                'prefix': address['prefixLength'],
                'gateway': address['gateway'],
            }
            interfaces.append(interface)
        return interfaces
    else:
        error('Retrieving network interfaces has failed: {} ({})'.format(
              request.text, request.status_code))


def get_peer_paths(api):
    json = {
        'query': '{ allPeers { nodes { name paths { status node networkInterface networkInterfaceDescription adjacentAddress mtu latency jitter loss mos uptime deviceInterface vlan isActive } } } }'
    }
    request = api.post('/graphql', json)
    peer_paths = []
    if request.status_code == 200:
        for peer in request.json()['data']['allPeers']['nodes']:
            for path in peer['paths']:
                path['name'] = peer['name']
                peer_paths.append(path)
        return peer_paths
    else:
        error('Retrieving peer path details has failed: {} ({})'.format(
              request.text, request.status_code))


def get_fib_table(api):
    json = {
        'query': '{ allRouters { nodes { name nodes { nodes { name fibEntries { nodes { serviceName route { ipPrefix tenant protocol l4Port l4PortUpper vrf } } } } } } } }'
    }
    request = api.post('/graphql', json)
    fib = {}
    if request.status_code == 200:
        for entry in request.json()['data']['allRouters']['nodes'][0]['nodes']['nodes'][0]['fibEntries']['nodes']:
            service = entry['serviceName']
            if service not in fib:
                fib[service] = []
            fib[service].append(entry['route'])
        return fib
    else:
        error('Retrieving FIB table has failed: {} ({})'.format(
              request.text, request.status_code))


def get_arp_table(api):
    json = {
        'query': '{ allRouters { nodes { name nodes { nodes { name arp { nodes { devicePort ipAddress destinationMac state networkInterface } } } } } } }'
    }
    request = api.post('/graphql', json)
    if request.status_code == 200:
        return request.json()['data']['allRouters']['nodes'][0]['nodes']['nodes'][0]['arp']['nodes']
    else:
        error('Retrieving ARP table has failed: {} ({})'.format(
              request.text, request.status_code))


def get_bgp_stats():
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        neighbors = []
        sock.connect('/var/run/128technology/routing/bgpd.vty')
        sock.sendall(b'show bgp summary\0')
        buffer = read_socket(sock).decode('ascii').strip()
        neighbors_start = False
        for line in buffer.split('\n'):
            if neighbors_start:
                if not line:
                    # end of peers
                    break
                neighbor = []
                for value in line.split():
                    try:
                        # convert to integer if possible
                        value = int(value)
                    except ValueError:
                        pass
                    neighbor.append(value)
                neighbors.append(neighbor)
                continue
            if line.startswith('Neighbor'):
                neighbors_start = True
        return neighbors
    except socket.error:
        pass


def update_sysinfo(api, pp, dmi):
    SYSINFO_OID = '1'
    pp.add_str('1.1', dmi.manufacturer())
    pp.add_str('1.2', dmi.model())
    pp.add_str('1.3', dmi.firmware())
    pp.add_str('1.4', dmi.serial_number())
    pp.add_str('1.5', dmi.cpu_type())
    pp.add_int('1.6', dmi.cpu_num())
    pp.add_int('1.7', dmi.total_enabled_cores())
    pp.add_int('1.8', dmi.total_ram())
    pp.add_str('2.1', 'Juniper Networks, Inc.')    # sw_vendor
    pp.add_str('2.2', 'Session Smart Router')      # sw_product
    pp.add_str('2.3', run('rpm -q --qf %{VERSION} 128T'.split(' '), stdout=PIPE, encoding='utf8').stdout)


def update_network_interfaces(api, pp):
    NI_OID = '10'
    interfaces = get_network_interfaces(api)
    for interface in interfaces:
        giid = interface['giid']
        # name
        oid = '{}.1.{}'.format(NI_OID, giid)
        pp.add_str(oid, interface['name'])
        # device_name
        oid = '{}.2.{}'.format(NI_OID, giid)
        pp.add_str(oid, interface['device_name'])
        # description
        oid = '{}.3.{}'.format(NI_OID, giid)
        pp.add_str(oid, interface['description'])
        # ip address + prefix
        oid = '{}.11.{}'.format(NI_OID, giid)
        pp.add_str(oid, '{i[ip_address]}/{i[prefix]}'.format(i=interface))
        # ip address
        oid = '{}.21.{}'.format(NI_OID, giid)
        pp.add_ip(oid, interface['ip_address'])
        # prefix
        oid = '{}.22.{}'.format(NI_OID, giid)
        pp.add_int(oid, interface['prefix'])
        # gateway
        gateway = interface['gateway']
        if gateway:
            oid = '{}.13.{}'.format(NI_OID, giid)
            pp.add_str(oid, gateway)
            oid = '{}.23.{}'.format(NI_OID, giid)
            pp.add_ip(oid, gateway)
    return interfaces


def update_peer_paths(api, pp):
    PP_OID = '11'
    p = 1
    for peer_path in get_peer_paths(api):
        oid = '{}.1.{}'.format(PP_OID, p)
        pp.add_str(oid, peer_path['name'])
        oid = '{}.2.{}'.format(PP_OID, p)
        pp.add_str(oid, peer_path['status'])
        oid = '{}.3.{}'.format(PP_OID, p)
        pp.add_str(oid, peer_path['node'])
        oid = '{}.4.{}'.format(PP_OID, p)
        pp.add_str(oid, peer_path['networkInterface'])
        oid = '{}.5.{}'.format(PP_OID, p)
        pp.add_str(oid, peer_path['networkInterfaceDescription'])
        oid = '{}.6.{}'.format(PP_OID, p)
        pp.add_str(oid, peer_path['adjacentAddress'])
        oid = '{}.7.{}'.format(PP_OID, p)
        pp.add_ip(oid, peer_path['adjacentAddress'])
        oid = '{}.8.{}'.format(PP_OID, p)
        pp.add_int(oid, peer_path['mtu'])
        oid = '{}.9.{}'.format(PP_OID, p)
        pp.add_int(oid, peer_path['latency'])
        oid = '{}.10.{}'.format(PP_OID, p)
        pp.add_int(oid, peer_path['jitter'])
        oid = '{}.11.{}'.format(PP_OID, p)
        pp.add_int(oid, peer_path['loss'])
        oid = '{}.12.{}'.format(PP_OID, p)
        pp.add_int(oid, peer_path['mos'])
        oid = '{}.13.{}'.format(PP_OID, p)
        uptime = peer_path['uptime']
        if not uptime:
            uptime = 0
        pp.add_int(oid, uptime)
        uptime = uptime // 1000
        days = uptime // 86400
        hours = uptime % 86400 // 3600
        minutes = uptime % 3600 // 60
        seconds = uptime % 60
        uptime_string = '{}d {:02d}:{:02d}:{:02d}'.format(days, hours, minutes, seconds)
        oid = '{}.14.{}'.format(PP_OID, p)
        pp.add_str(oid, uptime_string)
        oid = '{}.15.{}'.format(PP_OID, p)
        pp.add_str(oid, peer_path['deviceInterface'])
        oid = '{}.16.{}'.format(PP_OID, p)
        pp.add_int(oid, peer_path['vlan'])
        oid = '{}.17.{}'.format(PP_OID, p)
        pp.add_str(oid, peer_path['isActive'])
        p += 1


def update_fib(api, pp):
    FIB_OID = '20'
    fib_table = get_fib_table(api)

    s = 1
    for service, routes in fib_table.items():
        # populate service names (oid.x.1)
        oid = '{}.{}.1.1'.format(FIB_OID, s)
        pp.add_str(oid, service)
        r = 1
        for route in routes:
            # populate routes (oid.x.2)
            route_oid = '{}.{}.2.{}'.format(FIB_OID, s, r)
            oid = '{}.1'.format(route_oid)
            pp.add_str(oid, route['ipPrefix'])
            oid = '{}.2'.format(route_oid)
            pp.add_str(oid, route['tenant'])
            oid = '{}.3'.format(route_oid)
            pp.add_str(oid, route['protocol'])
            oid = '{}.4'.format(route_oid)
            pp.add_int(oid, route['l4Port'])
            oid = '{}.5'.format(route_oid)
            pp.add_int(oid, route['l4PortUpper'])
            oid = '{}.6'.format(route_oid)
            pp.add_str(oid, route['vrf'])
            r += 1
        s += 1


def update_arp(api, pp, interfaces):
    ARP_OID = '22'
    arp_table = get_arp_table(api)

    giids = {
        'controlKniIf': '254',
    }
    for interface in interfaces:
        giids[interface['name']] = interface['giid']

    # Add giid first
    for entry in arp_table:
        oid = '{}.1.{}.{}'.format(ARP_OID, giids[entry['networkInterface']], entry['ipAddress'])
        pp.add_int(oid, giids[entry['networkInterface']])

    # Add mac addresses
    for entry in arp_table:
        oid = '{}.2.{}.{}'.format(ARP_OID, giids[entry['networkInterface']], entry['ipAddress'])
        pp.add_oct(oid, entry['destinationMac'].replace(':', ' '))

    # Add ip addresses
    for entry in arp_table:
        oid = '{}.3.{}.{}'.format(ARP_OID, giids[entry['networkInterface']], entry['ipAddress'])
        pp.add_ip(oid, entry['ipAddress'])

    # Add entry type
    for entry in arp_table:
        oid = '{}.4.{}.{}'.format(ARP_OID, giids[entry['networkInterface']], entry['ipAddress'])
        state = 2   # default: "invalid"
        if entry['state'] == 'Valid':
            state = 3
        if entry['state'] == 'Static':
            state = 4
        pp.add_int(oid, state)

    # Add mac addresses as string
    for entry in arp_table:
        oid = '{}.5.{}.{}'.format(ARP_OID, giids[entry['networkInterface']], entry['ipAddress'])
        pp.add_str(oid, entry['destinationMac'])

    # Add network interface name as string
    for entry in arp_table:
        oid = '{}.6.{}.{}'.format(ARP_OID, giids[entry['networkInterface']], entry['ipAddress'])
        pp.add_str(oid, entry['networkInterface'])


def update_smart(api, pp):
    SMART_OID = '30'
    i = 1
    for device in DeviceList().devices:
        # add general details of the device (e.g. model, serial number, ...)
        j = 1
        for key in SMART_KEYS:
            oid = '{}.{}.1.{}.1'.format(SMART_OID, i, j)
            if key == '_capacity':
                pp.add_str(oid, 'capacity')
            else:
                pp.add_str(oid, key)
            oid = '{}.{}.1.{}.2'.format(SMART_OID, i, j)
            pp.add_auto(oid, device.__getattribute__(key))
            j += 1

        for attribute in device.attributes:
            if not attribute:
                # ignore attributes that have no data
                continue

            id = attribute.num
            j = 1
            for key in SMART_ATTRIBUTE_KEYS:
                oid = '{}.{}.2.{}.{}.1'.format(SMART_OID, i, id, j)
                if key == 'raw':
                    pp.add_str(oid, 'raw_value')
                elif key == '_thresh':
                    pp.add_str(oid, 'threshold')
                elif key == '_value':
                    pp.add_str(oid, 'value')
                elif key == '_worst':
                    pp.add_str(oid, 'worst')
                else:
                    pp.add_str(oid, key)

                oid = '{}.{}.2.{}.{}.2'.format(SMART_OID, i, id, j)
                pp.add_auto(oid, attribute.__getattribute__(key))
                j += 1
        i += 1


def update_bgp(api, pp):
    BGP_OID = '40'
    # BGP_OID.1 is reserved for general BGP stats
    # BGP_OID.2 is used for stats of BGP neighbors
    for neighbor in get_bgp_stats():
        base_oid = '{}.2.{}'.format(BGP_OID, neighbor[0])
        i = 1
        for value in neighbor:
            pp.add_auto('{}.{}.1'.format(base_oid, i), BGP_SUMMARY_KEYS[i-1])
            pp.add_auto('{}.{}.2'.format(base_oid, i), value)
            i += 1


def main():
    args = parse_arguments()
    # Prepare API
    keys = ('host', 'user', 'password')
    parameters = {k: v for k, v in args.__dict__.items() if k in keys and v}
    api = RestGraphqlApi(**parameters)
    if not args.no_dmi:
        dmi = DMIDecode()

    def update():
        if not args.no_dmi:
            update_sysinfo(api, pp, dmi)
        if not args.no_network:
            interfaces = update_network_interfaces(api, pp)
            update_peer_paths(api, pp)
            update_fib(api, pp)
            update_arp(api, pp, interfaces)
        if not args.no_smart:
            update_smart(api, pp)
        if not args.no_bgp:
            update_bgp(api, pp)

    class PassPersistAuto(snmp_passpersist.PassPersist):
        def add_auto(self, oid, value):
            if type(value) == str:
                self.add_str(oid, value)
            if type(value) == int:
                self.add_int(oid, value)

    # pp = snmp_passpersist.PassPersist(BASE)
    pp = PassPersistAuto(BASE)
    pp.start(update, REFRESH) # Every "REFRESH"s


if __name__ == '__main__':
    main()
