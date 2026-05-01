# ZABBIX EATON IPP

This tool is designed to get value from Eaton IPP interface and push to zabbix. It can also be used without zabbix (for instance nagios?)

### Prerequisites

- Windows or Linux compatible OS
- Eaton IPP > 1.68
- libcurl, OpenSSL, libcjson (build dependencies)

## Build

On Linux:
```bash
apt install libcurl4-openssl-dev libssl-dev libcjson-dev
make
```

On Windows (requires Docker):
```bat
docker_build.bat
```

## Setup

### Windows

_Steps:_
* Setup Zabbix Windows Agent
* Clone the repository
* Build the binary (see above)
* Copy `eatonipp-windows.conf` to `C:\Program Files\Zabbix Agent 2\zabbix_agent.conf.d`
* Copy `check_eaton_ipp` to `C:\Program Files\Zabbix Agent 2\scripts`
* Copy `check_eaton_ipp.conf` to `C:\Program Files\Zabbix Agent 2\scripts` and fill in url/username/passwd
* Upload the template named `zabbix-eatonipp.yaml` on Zabbix and apply to host

### Linux

_Steps:_
* Setup Zabbix Linux Agent
* Clone the repository
* Build the binary (see above)
* Copy `eatonipp-linux.conf` to `/etc/zabbix/zabbix_agent.conf.d`
* Copy `check_eaton_ipp` to `/etc/zabbix/scripts`
* Copy `check_eaton_ipp.conf` to `/etc/zabbix` and fill in url/username/passwd
* Upload the template named `zabbix-eatonipp.yaml` on Zabbix and apply to host