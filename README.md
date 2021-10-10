# ZABBIX EATON IPP

This tool is designed to get value from Eaton IPP interface and push to zabbix. The script can also be used without zabbix (for instance nagios?)

### Prerequisites

- Windows or Linux compatible OS
- NodeJS
- Axios NodeJS librairy
- Eaton IPP > 1.68

## Setup

### Windows

_Steps:_
* Setup Zabbix Windows Agent
* Install NodeJS (add it to the Windows path)
* Clone the repository
* copy eatonipm-windows.conf to C:\Program Files\Zabbix Agent\zabbix_agent.conf.d
* copy eaton.js to C:\Program Files\Zabbix Agent\scripts
* In C:\Program Files\Zabbix Agent\scripts, type "npm install axios" in the cmd shell
* Create an monitor "User" account in Eaton IPP and put the username/password in the eaton.js file
* Upload the template named zabbix-eatonipp.yaml on Zabbix and apply to host

### Linux

_Steps:_
* Setup Zabbix Linux Agent
* Install NodeJS (add it to the Windows path)
* Clone the repository
* copy eatonipm-linux.conf to /etc/zabbix/zabbix_agent.conf.d
* copy eaton.js to /etc/zabbix/scripts
* In /etc/zabbix/scripts, type "npm install axios"
* Create an monitor "User" account in Eaton IPP and put the username/password in the eaton.js file
* Upload the template named zabbix-eatonipp.yaml on Zabbix and apply to host.