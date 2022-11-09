{% set base_directory = "/etc/snmp" %}
{% set config_directory = "conf.d" %}
{% set custom_config = "128T-snmpd-custom.conf" %}
{% set global_config = "128T-snmpd.conf" %}
{% set include_config = "128T-include.conf" %}
{% set custom_script = "/usr/sbin/t128-custom-snmp.pyz" %}
{% set override_file = "/etc/systemd/system/128T-snmpd.service.d/override.conf" %}

t128-custom-snmp 128T snmpd config directory:
  file.directory:
    - name: {{ base_directory }}/{{ config_directory }}
    - mode: 755

t128-custom-snmp 128T snmpd include config:
  file.managed:
    - name: {{ base_directory }}/{{ include_config }}
    - contents:
      - includeDir	{{ base_directory }}/{{ config_directory }}
    - mode: 400

t128-custom-snmp 128T snmpd custom config:
  file.managed:
    - name: {{ base_directory }}/{{ custom_config }}
    - contents:
      - pass_persist .1.3.6.1.4.1.45956.1.1.128 {{ custom_script }}
    - mode: 400

t128-custom-snmp 128T snmpd custom config symlink:
  file.symlink:
    - name: {{ base_directory }}/{{ config_directory }}/{{ custom_config }}
    - target: {{ base_directory }}/{{ custom_config }}

t128-custom-snmp 128T snmpd global config symlink:
  file.symlink:
    - name: {{ base_directory }}/{{ config_directory }}/{{ global_config }}
    - target: {{ base_directory }}/{{ global_config }}

t128-custom-snmp custom script:
  file.managed:
    - name: {{ custom_script }}
    - mode: 755
    - source: salt://t128-custom-snmp.pyz

t128-custom-snmp systemd override directory:
  file.directory:
    - name: /etc/systemd/system/128T-snmpd.service.d
    - mode: 755

t128-custom-snmp snmpd systemd:
  file.managed:
    - name: {{ override_file }}
    - contents: |
        [Service]
        ExecStart=
        ExecStart=/usr/sbin/snmpd \
          $OPTIONS -f \
          $IF_MIB_OVERRIDES \
          -C -c {{ base_directory }}/{{ include_config }} \
          -p /run/128T-snmpd.pid
  module.run:
    - name: service.systemctl_reload
    - onchanges:
      - file: {{ override_file }}
  service.running:
    - name: 128T-snmpd.service
    - watch:
      - file: {{ base_directory }}/{{ custom_config }}
      - file: {{ custom_script }}
      - file: {{ override_file }}
