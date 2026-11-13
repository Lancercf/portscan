#!/usr/bin/env python
# encoding: utf-8

from api import WebAPI
from utils import valid_ip, unpack_ip, get_logger


logger = get_logger(__name__)


def publish_task(unpack=False):
    iplist = []

    with open('wan_ip.txt', 'r') as f:
        for line in f.readlines():
            ip = line.strip()
            if valid_ip(ip):
                if unpack:
                    iplist.extend(unpack_ip(ip))
                else:
                    iplist.append(ip)

    r = WebAPI.publish_task(len(iplist), iplist)

    if r['status'] != 0:
        logger.info('Fail: {0} - {1}'.format(r['status'], r['msg']))
    else:
        logger.info('Success: {0} - {1}'.format(r['status'], r['msg']))


def send_report():
    pass


def clean_db(before=30):
    pass


if __name__ == '__main__':
    publish_task()
