import os
import pathlib
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


class UnauthorizedException(Exception):
    pass


class RestGraphqlApi(object):
    """Representation of REST connection."""

    token = None
    authorized = False
    headers = {
        'Content-Type': 'application/json',
    }

    def __init__(self, host='localhost', verify=False, user='admin', password=None, app=__file__):
        self.host = host
        self.verify = verify
        self.user = user
        self.password = password
        basename = os.path.basename(app).split('.')[0]
        self.user_agent = basename
        self.token_file = os.path.join(
             pathlib.Path.home(), '.{}.token'.format(basename))
        self.read_token()
        self.headers.update({
             'User-Agent': self.user_agent,
             'Authorization': f'Bearer {self.token}',
        })

        self.session = requests.Session()
        self.session.headers.update(self.headers)
        self.session.hooks['response'].append(self.refresh_token)

    def read_token(self):
        try:
            with open(self.token_file) as fd:
                self.token = fd.read()
        except FileNotFoundError:
            pass

    def write_token(self):
        try:
            with open(self.token_file, 'w') as fd:
                fd.write(self.token)
        except:
            raise

    def refresh_token(self, r, *args, **kwargs):
        if r.status_code == 401:
            token = self.login()
            self.session.headers.update({'Authorization': f'Bearer {token}'})
            r.request.headers['Authorization'] = self.session.headers['Authorization']
            return self.session.send(r.request, verify=self.verify)

    def get(self, location, authorization_required=True):
        """Get data per REST API."""
        url = 'https://{}/api/v1/{}'.format(self.host, location.strip('/'))
        request = self.session.get(url, verify=self.verify)
        return request

    def post(self, location, json, authorization_required=True):
        """Send data per REST API via post."""
        url = 'https://{}/api/v1/{}'.format(self.host, location.strip('/'))
        request = self.session.post(url, json=json, verify=self.verify)
        return request

    def patch(self, location, json, authorization_required=True):
        """Send data per REST API via patch."""
        url = 'https://{}/api/v1/{}'.format(self.host, location.strip('/'))
        request = self.session.patch(url, json=json, verify=self.verify)
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
            self.write_token()
            return self.token
        else:
            message = request.json()['message']
            raise UnauthorizedException(message)

    def get_routers(self):
        return self.get('/router').json()

    def get_router_name(self):
        self.router_name = self.get_routers()[0]['name']
        return self.router_name

    def get_nodes(self, router):
        return self.get('/config/running/authority/router/{}/node'.format(
            router)).json()

    def get_node_names(self, router):
        nodes = self.get_nodes(router)
        node_names = [node['name'] for node in nodes]
        return node_names

    def get_device_interfaces(self, router, node):
        return self.get(('/config/running/authority/router/{}/node/{}'
                         '/device-interface').format(router, node)).json()
