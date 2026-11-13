#!/usr/bin/env python
# encoding: utf-8

import sys
import time
import atexit
import logging
import argparse

import psutil
from api import WebAPI
from utils import get_logger
from scanner import ScannerManager, NmapScanner, MasScanner


logger = get_logger(__name__)
logging.getLogger('requests').setLevel(logging.WARN)


class Scheduler(object):

    # what:
    # masscan -> for masscan only
    # nmap -> for nmap only
    def __init__(self, interval=5, masscan=1, nmap=1):
        self.interval = interval
        self.masscan = masscan
        self.nmap = nmap

        if masscan > 0:
            self.masscan_sm = ScannerManager(MasScanner, masscan)
        if nmap > 0:
            self.nmap_sm = ScannerManager(NmapScanner, nmap)

    def kill_zombie_nmap(self):
        '''
        Get unfinished nmap task process list, terminate,
        PS: These are zombie process, may generate cuz timeout
        '''
        plist = psutil.get_process_list()
        for p in plist:
            try:
                if p.name() == 'nmap' and p.parent().pid == 1:
                    psutil.Process(p.pid).kill()
            except:  # NoSuchProcess
                continue

    def run(self):
        while True:
            self.kill_zombie_nmap()

            if self.masscan:
                WebAPI.client_ping(self.masscan_sm.name,
                                   self.masscan_sm.pool_size,
                                   self.masscan_sm.idle)
                while self.masscan_sm.has_idle():
                    r = WebAPI.get_masscan_task()
                    if r['status'] == 0:
                        self.masscan_sm.apply(host=r['data'], ports='1-65535')
                    else:
                        # logger.info(r['msg'])
                        break

            if self.nmap:
                WebAPI.client_ping(self.nmap_sm.name,
                                   self.nmap_sm.pool_size,
                                   self.nmap_sm.idle)
                while self.nmap_sm.has_idle():
                    r = WebAPI.get_nmap_task()
                    if r['status'] == 0:
                        host, ports = r['data'].split('|')
                        r = self.nmap_sm.apply(host=host, ports=ports)
                    else:
                        # logger.info(r['msg'])
                        break

            time.sleep(self.interval)

    def exit(self, signum=0, frame=None):
        if self.masscan > 0:
            self.masscan_sm.unregister()
        if self.nmap > 0:
            self.nmap_sm.unregister()
        sys.exit(signum)


def parse_args(args):
    parser = argparse.ArgumentParser(description='help of portscan scheduler')
    parser.add_argument('--masscan',
                        '-m',
                        action='store',
                        dest='masscan',
                        type=int,
                        default=1)
    parser.add_argument('--nmap',
                        '-n',
                        action='store',
                        dest='nmap',
                        type=int,
                        default=1)
    return parser.parse_args(args)

if __name__ == '__main__':
    args = parse_args(sys.argv[1:])
    logger.info('Scheduler start running (schedule every 5s)...')
    scheduler = Scheduler(interval=5,
                          masscan=args.masscan,
                          nmap=args.nmap)
    atexit.register(scheduler.exit)
    scheduler.run()
