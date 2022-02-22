# t128-custom-snmp.py

t128-custom-snmp.py is a script to extend the snmpd capabilities to provide additional data via SNMP:

* SSR hardware and software details
* SSR FIB table
* SSR ARP table

## Clone Repo

```
$ sudo dnf install -y git
$ cd /usr/local/src
$ sudo git clone https://github.com/majes-git/t128-custom-snmp.git
$ cd /srv/salt
$ sudo ln -s /usr/local/src/t128-custom-snmp/t128-custom-snmp.sls
$ sudo ln -s /usr/local/src/t128-custom-snmp/t128-custom-snmp.pyz
```

## Apply salt state

The salt state `t128-custom-snmp.sls` needs to be referenced in the `top.sls` file, e.g.

```
$ cat /srv/salt/top.sls
base:
  'test-router':
    - t128-custom-snmp
```

On the conductor run state.apply to install the extension on "test-router":

```
$ sudo t128-salt test-router state.apply saltenv=base
```
