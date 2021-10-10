# ZABBIX EATON IPM

This tool is designed to get value from Eaton IPM interface and push to zabbix
The script can also be used without zabbix (for instance nagios?)

### Prerequisites

- Windows or Linux compatible OS
- NodeJS
- Axios NodeJS librairy
- Eaton IPM > 1.68

## Setup

### Windows

_Steps:_
* Setup Zabbix Windows Agent
* Install NodeJS (add it to the Windows path)
* Clone the repository
* copy eatonipm-windows.conf to C:\Program Files\Zabbix Agent\zabbix_agent.conf.d
* copy eaton.js to C:\Program Files\Zabbix Agent\scripts
* In C:\Program Files\Zabbix Agent\scripts, type "npm install axios" in the cmd shell
* Upload the template named zabbix-eatonipp.yaml on Zabbix and apply to host.

### Linux

_Steps:_
* Setup Zabbix Linux Agent
* Clone the repository
* copy eatonipm-linux.conf to /etc/zabbix/zabbix_agent.conf.d
* copy eaton.js to /etc/zabbix/scripts
* In /etc/zabbix/scripts, type "npm install axios"
* Upload the template named zabbix-eatonipp.yaml on Zabbix and apply to host.