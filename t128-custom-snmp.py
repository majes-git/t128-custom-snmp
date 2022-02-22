#!/usr/bin/python3 -u

import argparse
import json
import os
import requests
from subprocess import run, PIPE
import sys
import time

from dmidecode import DMIDecode
import snmp_passpersist

from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

REFRESH = 60  # in seconds
BASE = '.1.3.6.1.4.1.45956.1.1.128'


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
    return parser.parse_args()


def error(*msg):
    print(*msg)
    sys.exit(1)


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
        'query': '{ allRouters { nodes { name nodes { nodes { name arp { nodes { devicePort ipAddress destinationMac state } } } } } } }'
    }
    request = api.post('/graphql', json)
    if request.status_code == 200:
        return request.json()['data']['allRouters']['nodes'][0]['nodes']['nodes'][0]['arp']['nodes']
    else:
        error('Retrieving ARP table has failed: {} ({})'.format(
              request.text, request.status_code))


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


def update_arp(api, pp):
    ARP_OID = '22'
    arp_table = get_arp_table(api)
    # Add deviceports first
    for entry in arp_table:
        oid = '{}.1.{}.{}'.format(ARP_OID, entry['devicePort'], entry['ipAddress'])
        pp.add_int(oid, entry['devicePort'])

    # Add mac addresses
    for entry in arp_table:
        oid = '{}.2.{}.{}'.format(ARP_OID, entry['devicePort'], entry['ipAddress'])
        pp.add_oct(oid, entry['destinationMac'].replace(':', ' '))

    # Add ip addresses
    for entry in arp_table:
        oid = '{}.3.{}.{}'.format(ARP_OID, entry['devicePort'], entry['ipAddress'])
        pp.add_ip(oid, entry['ipAddress'])

    # Add entry type
    for entry in arp_table:
        oid = '{}.4.{}.{}'.format(ARP_OID, entry['devicePort'], entry['ipAddress'])
        state = 2   # default: "invalid"
        if entry['state'] == 'Valid':
            state = 3
        if entry['state'] == 'Static':
            state = 4
        pp.add_int(oid, state)


def main():
    args = parse_arguments()
    # Prepare API
    keys = ('host', 'user', 'password')
    parameters = {k: v for k, v in args.__dict__.items() if k in keys and v}
    api = RestGraphqlApi(**parameters)
    dmi = DMIDecode()

    def update():
        update_sysinfo(api, pp, dmi)
        update_fib(api, pp)
        update_arp(api, pp)

    pp=snmp_passpersist.PassPersist(BASE)
    pp.start(update, REFRESH) # Every "REFRESH"s


if __name__ == '__main__':
    main()
