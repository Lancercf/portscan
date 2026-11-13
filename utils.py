#!/usr/bin/env python
# encoding: utf-8


import re
import sys
import fcntl
import socket
import struct
import logging
import smtplib
from email.header import Header
from email.utils import formataddr
from email.mime.text import MIMEText

import ipaddr

import config as cfg


def valid_ip(ip):
    ip_pat = r'(\d{1,3}\.){3}\d{1,3}'
    r1 = re.compile(r'^%s(/\d{1,2})?$' % ip_pat)
    r2 = re.compile(r'^%s(-%s)?$' % (ip_pat, ip_pat))
    return bool(r1.match(ip) or r2.match(ip))


def valid_port(ports):
    r = re.compile(r'^\d{1,5}((-\d{1,5})?|(,\d{1,5})*)$')
    return bool(r.match(ports))


def unpack_ip(ip):
    result = []
    for addr in iter(ipaddr.IPNetwork(ip)):
        result.append(str(addr))

    return result


def get_logger(name, level=logging.INFO):
    logging.basicConfig(
        level=level,
        datefmt='%Y-%m-%d %H:%M:%S',
        format='[%(asctime)s <%(filename)s:%(lineno)d> %(levelname)s] %(message)s',  # noqa
        stream=sys.stdout
    )

    return logging.getLogger(name)


def send_email(subject, content, content_type='plain'):
    try:
        sender = cfg.EMAIL_SENDER
        recipients = cfg.EMAIL_RECIPIENTS
        hostname = cfg.EMAIL_HOST
        username = cfg.EMAIL_USERNAME
        password = cfg.EMAIL_PASSWORD
    except KeyError as e:
        raise e

    msg = MIMEText(content, _subtype=content_type, _charset='UTF-8')

    msg['To'] = formataddr(('Admin(PortScan)', ';'.join(recipients)))
    msg['From'] = formataddr(('notice', sender))
    msg['Subject'] = Header(subject, charset='UTF-8')

    server = smtplib.SMTP(hostname)
    try:
        # server.set_debuglevel(True)
        server.ehlo()
        if server.has_extn('STARTTLS'):
            server.starttls()
            server.ehlo()

        server.login(username, password)
        server.sendmail(sender, recipients, msg.as_string())
    except Exception as e:
        raise e
    finally:
        server.quit()


def get_ip_address(ifname):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    return socket.inet_ntoa(fcntl.ioctl(
        s.fileno(),
        0x8915,  # SIOCGIFADDR
        struct.pack('256s', ifname[:15])
    )[20:24])

if __name__ == '__main__':
    assert valid_ip('100.200.10.60') is True
    assert valid_ip('100.200.10.60/23') is True
    assert valid_ip('100.200.10.60/233') is False
    assert valid_ip('100.200.10.') is False
    assert valid_port('22') is True
    assert valid_port('22-3306') is True
    assert valid_port('22,80,3306') is True
    assert valid_port('22-,') is False
    print unpack_ip('100.200.10.60/24')
