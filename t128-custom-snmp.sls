{% set config_file = "/etc/snmp/128T-snmpd-custom.conf" %}
{% set custom_script = "/usr/sbin/t128-custom-snmp.pyz" %}
{% set override_file = "/etc/systemd/system/128T-snmpd.service.d/override.conf" %}

128T snmpd config:
  file.managed:
    - name: {{ config_file }}
    - contents:
      - pass_persist .1.3.6.1.4.1.45956.1.1.128 /usr/sbin/t128-custom-snmp.pyz
    - mode: 400

custom script:
  file.managed:
    - name: {{ custom_script }}
    - mode: 755
    - source: salt://t128-custom-snmp.pyz

/etc/systemd/system/128T-snmpd.service.d:
  file.directory:
    - mode: 755

128T-snmpd.service:
  file.managed:
    - name: {{ override_file }}
    - contents: |
        [Service]
        ExecStart=
        ExecStart=/usr/sbin/snmpd \
          $OPTIONS -f \
          $IF_MIB_OVERRIDES \
          -C -c /etc/snmp/128T-snmpd.conf,{{ config_file }} \
          -p /run/128T-snmpd.pid
  module.run:
    - name: service.systemctl_reload
    - onchanges:
      - file: {{ override_file }}
  service.running:
    - watch:
      - file: {{ config_file }}
      - file: {{ custom_script }}
      - file: {{ override_file }}
