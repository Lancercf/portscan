#!/usr/bin/env python
# encoding: utf-8

DEBUG = False

# White ip list for server control
ALLOW_IPLIST = set(['127.0.0.1',
                    '',
                    ''])

# Skip ip for scanner
SCAN_IP_WHITELIST = set(['', ''])
# Skip service for nmap
SCAN_SERVICE_WHITELIST = set(['tcpwrapped', 'abyss'])

# Scanner bin
MASSCAN_BIN = '/usr/bin/masscan'
NMAP_BIN = '/usr/bin/nmap'

# For Auth
AUTH_USERNAME = ''
AUTH_PASSWORD = ''

# For sending email
EMAIL_HOST = ''
EMAIL_PORT = 143
EMAIL_USERNAME = ''
EMAIL_PASSWORD = ''
EMAIL_SENDER = ''
# Add admin list here
EMAIL_RECIPIENTS = ['']

# For store nmap result
STORE_URL = ''
STORE_ENTRY = 'port_scan'
STORE_KEY = ''

if DEBUG:
    SERVER_URL = 'http://127.0.0.1:8000'
    DB_HOST = '127.0.0.1'
    DB_PORT = 3306
    DB_USER = 'root'
    DB_PASSWD = ''
    DB_NAME = 'portscan'
else:
    SERVER_URL = ''
    DB_HOST = ''
    DB_PORT = 3701
    DB_USER = 'w'
    DB_PASSWD = '1'
    DB_NAME = ''
