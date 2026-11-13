#!/usr/bin/env python
# encoding: utf-8

import operator

import pymysql
from datetime import datetime

import config as cfg
from utils import get_logger

logger = get_logger(__name__)


class DataBase(object):

    def __init__(self, connect=True):
        if connect:
            self.connect()

    def __del__(self):
        self.close()

    def connect(self):
        self.conn = pymysql.connect(host=cfg.DB_HOST,
                                    port=cfg.DB_PORT,
                                    user=cfg.DB_USER,
                                    passwd=cfg.DB_PASSWD,
                                    db=cfg.DB_NAME)

    def close(self):
        if self.conn.open:
            self.conn.close()

    @property
    def tables(self):
        try:
            cur = self.conn.cursor()
            sql = 'SHOW TABLES'
            cur.execute(sql)
            r = cur.fetchall()
        except Exception as e:
            logger.error('Fail to show tables: {}'.format(e))
            return []
        finally:
            cur.close()

        return map(lambda x: operator.getitem(x, 0), r)

    def insert_nmap_result(self, host, ports):
        now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        data = []
        for port in ports:
            data.append((host,
                         port['port'],
                         port['name'],
                         port['product'],
                         port['version'],
                         now))
        try:
            cur = self.conn.cursor()
            sql = 'INSERT INTO portscan_main (ip, port, service, product, version, createtime) VALUES (%s,%s,%s,%s,%s,%s)'  # noqa
            cur.executemany(sql, data)
            self.conn.commit()
        except Exception as e:
            logger.error('Fail to insert nmap result: {}'.format(e))
        finally:
            cur.close()


if __name__ == '__main__':
    db = DataBase()

    print db.tables
    '''
    host = '121.8.156.76'
    ports = [{u'product': u'Busybox telnetd', u'version': u'', u'port': 2323, u'name': u'telnet'},
             {u'product': u'', u'version': u'', u'port': 8080, u'name': u'tcpwrapped'}]
    db.insert_nmap_result(host, ports)
    '''
