#!/usr/bin/env python
# encoding: utf-8

import re
import os
import shlex
import subprocess
from threading import Thread, Timer

import config as cfg
from api import WebAPI
from utils import valid_ip, valid_port, get_logger

import nmap


logger = get_logger(__name__)


class NmapScanner(object):

    name = 'nmap'

    def __init__(self, timeout=3600):
        self.timeout = timeout
        self.args = '-sV -Pn -T4 --open'
        self.protocols = ['tcp', 'udp']
        self.nm = nmap.PortScannerAsync()

    def command_line(self):
        return self.cmd_line

    def scan_and_submit(self, host, ports, manager):
        host, ports = str(host), str(ports)
        try:
            assert (valid_ip(host) and valid_port(ports))
            logger.info('<{}> start to process {}'.format(NmapScanner.name, host))  # noqa
            self.nm.scan(hosts=host,
                         ports=ports,
                         arguments=self.args,
                         callback=self.submit_callback)
            self.nm.wait(self.timeout)
            if self.nm.still_scanning():
                self.nm.stop()
        except Exception as e:
            logger.error('Failed to scan %s with nmap: %s', host, e)
        finally:
            manager.idle += 1

    def submit_callback(self, host, data):
        self.cmd_line = data['nmap']['command_line']
        result = {'host': host, 'ports': []}
        # print to see the result structure
        for proto in self.protocols:
            for k, v in data['scan'].get(host, {}).get(proto, {}).iteritems():
                if (v['name'] not in cfg.SCAN_SERVICE_WHITELIST
                        or (v['name'] == 'tcpwrapped' and int(k) == 9000)):
                    result['ports'].append({
                        'port': k,
                        'name': v['name'] or u'unknown',
                        'product': v['product'],
                        'version': v['version']
                    })
        try:
            if result['ports']:
                WebAPI.submit_nmap_result(result)
        except Exception as e:
            logger.error('Failed to submit nmap result<%s> : %s', host,  e)


class MasScanner(object):

    name = 'masscan'

    def __init__(self, cmd=cfg.MASSCAN_BIN, rate=100000, timeout=2 * 3600):
        self.cmd = cmd
        self.rate = rate
        self.timeout = timeout
        self.pat = re.compile(r'^Discovered open port (\d+)/(.+) on ([\d.]+)\s*$')  # noqa

    def command_line(self):
        return self.cmd_line

    def ontimeout(self, process):
        process.terminate()
        logger.error('Error: MasScanner scan timeout')

    def scan(self, host, ports):
        host, ports = str(host), str(ports)
        if not (valid_ip(host) and valid_port(ports)):
            raise Exception('Wrong format of ip or ports')

        logger.info('<{}> start to process {}'.format(MasScanner.name, host))
        self.cmd_line = ' '.join([self.cmd,
                                  '-sS', host,
                                  '-p', ports,
                                  '--open',
                                  '--wait=0',
                                  '--rate={}'.format(self.rate)])

        p = subprocess.Popen(shlex.split(self.cmd_line),
                             stdin=subprocess.PIPE,
                             stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE)

        timer = Timer(self.timeout, self.ontimeout, args=(p,))

        timer.start()
        stdmsg, errmsg = p.communicate()
        timer.cancel()

        result = {}
        for msg in stdmsg.splitlines():
            m = self.pat.match(msg)
            if m:
                open_port, ip = m.group(1), m.group(3)
                v = result.setdefault(ip, set([]))
                v.add(open_port)

        return result

    def scan_and_submit(self, host, ports, manager):
        data = []
        try:
            r = self.scan(host, ports)
            for k, v in r.iteritems():
                data.append('|'.join([k, ','.join(v)]))
            if data:
                WebAPI.submit_masscan_result(data)
        except Exception as e:
            logger.error('Failed to scan %s with masscan: %s', host,  e)
        finally:
            manager.idle += 1


class ScannerManager(object):

    def __init__(self, scanner, pool_size=1):
        self.scanner = scanner
        self.name = '{0}-{1}'.format(os.getpid(), self.scanner.name)

        self.pool_size = pool_size
        self.idle = pool_size

        self.register()

    def register(self):
        r = WebAPI.register_client(self.name, self.pool_size)
        logger.info('{0}:{1}-{2}'.format(self.name, r['status'], r['msg']))

    def unregister(self):
        r = WebAPI.unregister_client(self.name)
        logger.info('{0}:{1}-{2}'.format(self.name, r['status'], r['msg']))

    def get_status(self):
        return {'total': self.pool_size, 'idle': self.idle}

    def has_idle(self):
        return self.idle > 0

    def apply(self, host, ports):
        self.idle -= 1
        try:
            assert self.idle >= 0
            Thread(target=self.scanner().scan_and_submit,
                   args=(host, ports, self)).start()
        except Exception as e:
            logger.error('Failed to scan host<{0}>: {1}'.format(host, e))

if __name__ == '__main__':
    sm = ScannerManager(NmapScanner, 3)
