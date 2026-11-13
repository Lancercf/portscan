#!/usr/bin/env python
# encoding: utf-8


import time
import json
import logging
import hashlib
import functools

import redis
import bottle
import requests
from bottle import (get,
                    post,
                    error,
                    abort,
                    request,
                    template,
                    auth_basic)

import config as cfg
from utils import get_logger
from database import DataBase


class TaskManager(object):

    rds = redis.StrictRedis(host='127.0.0.1',
                            port=6379,
                            password='',
                            db=0)

    @staticmethod
    def add_masscan_tasks(total, iplist):
        p = TaskManager.rds.pipeline()
        p.set('TASK:START', int(time.time()))
        p.set('TASK:DONE', 0)
        p.set('TASK:TOTAL', total)
        for ip in iplist:
            p.rpush('TASK:MASSCAN', str(ip))
        p.execute()
        return TaskManager.rds.llen('TASK:MASSCAN')

    @staticmethod
    def pop_masscan_task():
        return TaskManager.rds.lpop('TASK:MASSCAN')

    @staticmethod
    def get_masscan_progress():
        return int(TaskManager.rds.get('TASK:TOTAL')) - TaskManager.rds.llen('TASK:MASSCAN')  # noqa

    @staticmethod
    def add_nmap_task(task):
        p = TaskManager.rds.pipeline()
        for t in task:
            p.rpush('TASK:NMAP', str(t))
        p.execute()
        return TaskManager.rds.llen('TASK:NMAP')

    @staticmethod
    def pop_nmap_task():
        task = TaskManager.rds.lpop('TASK:NMAP')
        if task:
            TaskManager.rds.incr('TASK:DONE')
        return task

    @staticmethod
    def get_nmap_progress():
        return int(TaskManager.rds.get('TASK:DONE'))

    @staticmethod
    def get_task_status():
        p = TaskManager.rds.pipeline()
        p.get('TASK:START')
        p.get('TASK:TOTAL')
        p.llen('TASK:MASSCAN')
        p.get('TASK:DONE')
        r = p.execute()
        return map(lambda x: 0 if x is None else int(x), r)

    @staticmethod
    def is_task_finished():
        return not (TaskManager.rds.llen('TASK:MASSCAN') or
                    TaskManager.rds.llen('TASK:NMAP'))


class ClientManager(object):
    rds = redis.StrictRedis(host='127.0.0.1',
                            port=6379,
                            password='',
                            db=0)

    @staticmethod
    def ping(client_name, pool_size, idle):
        ClientManager.rds.setex('CLIENT:{}'.format(client_name),
                                30,
                                '{0}/{1}'.format(idle, pool_size))

    @staticmethod
    def register(client_name, pool_size):
        ClientManager.rds.setex('CLIENT:{}'.format(client_name),
                                30,
                                '{0}/{1}'.format(pool_size, pool_size))

    @staticmethod
    def unregister(client_name):
        ClientManager.rds.delete('CLIENT:{}'.format(client_name))

    @staticmethod
    def list_clients():
        clients = ClientManager.rds.keys('CLIENT:*')
        if clients:
            clients_status = ClientManager.rds.mget(*clients)
        else:
            return {}
        return dict(zip(clients, clients_status))


##############################################################################
# DEFINE ROUTE
##############################################################################
logger = get_logger(__name__)
logging.getLogger('requests').setLevel(logging.WARNING)


def validate_ip(func):
    @functools.wraps(func)
    def wrapper(*args, **kargs):
        remote_ip = request.remote_addr
        if remote_ip not in cfg.ALLOW_IPLIST:
            abort(403)
        else:
            return func(*args, **kargs)
    return wrapper


def validate_auth(username, password):
    if username == cfg.AUTH_USERNAME and password == cfg.AUTH_PASSWORD:
        return True
    return False


@get('/')
@auth_basic(validate_auth)
def index():
    return template('<b>Hello {{name}}</b>', name='PortScanner')


@post('/client/registration')
@validate_ip
def register_client():
    client_name = request.forms.client_name
    pool_size = request.forms.pool_size
    try:
        client_name = '-'.join([request.remote_addr, client_name])
        ClientManager.register(client_name, pool_size)
    except Exception as e:
        logger.error('Fail to register client<{0}>:{1}'.format(client_name, e))
        return {'status': 1, 'msg': 'Fail to register client'}

    logger.info('Succeed registering client<{0}> ({1} scanners)'.format(client_name, pool_size))  # noqa

    return {'status': 0, 'msg': 'Ok->register client'}


@post('/client/unregistration')
@validate_ip
def unregister_client():
    client_name = request.forms.client_name
    try:
        client_name = '-'.join([request.remote_addr, client_name])
        ClientManager.unregister(client_name)
    except Exception as e:
        logger.error('Fail to unregister client<{0}>:{1}'.format(client_name, e))  # noqa
        return {'status': 1, 'msg': 'Fail to unregister client'}

    logger.info('Succeed unregistering client <{}>'.format(client_name))
    return {'status': 0, 'msg': 'OK->unregister client'}


@post('/client/ping')
@validate_ip
def client_ping():
    client_name = request.forms.client_name
    pool_size = request.forms.pool_size
    idle = request.forms.idle
    try:
        client_name = '-'.join([request.remote_addr, client_name])
        ClientManager.ping(client_name, pool_size, idle)
    except Exception as e:
        logger.error('Fail to ping client<{0}>:{1}'.format(client_name, e))
        return {'status': 1, 'msg': 'Fail to ping client'}

    # logger.info('Succeed ping client<{0}>'.format(client_name))
    return {'status': 0, 'msg':  'OK->ping client'}


@get('/client/list')
def list_clients():
    try:
        clients = ClientManager.list_clients()
    except Exception as e:
        logger.error('Fail to get clients: {}'.format(e))
        return {
            'status': 1,
            'msg': 'Fail to list all online clients',
        }

    return {
        'status': 0,
        'msg': 'OK->list all online clients',
        'data': clients
    }


@post('/tasks')
@validate_ip
def add_tasks():
    if not TaskManager.is_task_finished():
        return {'status': 1, 'msg': 'Busy on processing previous tasks'}

    try:
        total = request.forms.total
        iplist = json.loads(request.forms.data)
    except Exception as e:
        logger.error('Fail to add masscan tasks: {}'.format(e))
        return {'status': 2, 'msg': 'Invalid params'}

    try:
        total = TaskManager.add_masscan_tasks(total, iplist)
    except Exception as e:
        logger.error('Fail to add masscan tasks: {}'.format(e))
        total = None

    if not total:
        return {'status': 3, 'msg': 'No any task is added'}

    return {'status': 0, 'msg': 'OK->adding {} task'.format(total)}


@get('/task/<task_type>')
@validate_ip
def fetch_task(task_type):
    task_type = task_type.lower()
    if task_type == 'masscan':
        try:
            data = TaskManager.pop_masscan_task()
        except Exception as e:
            logger.error('Fail to get masscan task: {}'.format(e))
            data = None

        if data:
            return {
                'status': 0,
                'msg': 'OK->get {} task'.format(task_type),
                'data': data
            }
        else:
            return {'status': 1, 'msg': 'No more masscan tasks'}

    elif task_type == 'nmap':
        try:
            data = TaskManager.pop_nmap_task()
        except Exception as e:
            logger.error('Fail to get nmap task: {}'.format(e))
            data = None

        if data:
            return {
                'status': 0,
                'msg': 'OK->get {} task'.format(task_type),
                'data': data
            }
        else:
            return {'status': 1, 'msg': 'No more nmap tasks'}
    else:
        return {'status': 2, 'msg': 'Wrong task type'}


@post('/task/<task_type>/result')
@validate_ip
def submit_task_result(task_type):
    task_type = task_type.lower()
    if task_type == 'masscan':
        task = json.loads(request.forms.ip_ports)
        try:
            total = TaskManager.add_nmap_task(task)
        except Exception as e:
            logger.error('Fail to add masscan task: {}'.format(e))
            return {'status': 1, 'msg': 'Fail to add masscan task'}

        logger.info('Succeed Adding {} nmap tasks'.format(total))
    elif task_type == 'nmap':
        host = request.forms.host
        try:
            ports = json.loads(request.forms.ports)
        except:
            return {'status': 2, 'msg': 'Invalid params'}
        # Directly stored by database.py
        '''
        try:
            db = DataBase()
            db.insert_nmap_result(host, ports)
            db.close()
        except Exception as e:
            logger.error('Fail to store nmap result: {}'.format(e))
            return {'status': 3, 'msg': 'Fail to store nmap result'}
        '''
        # Post to remote server to store
        for port in ports:
            port.update({'ip': host})

        e = cfg.STORE_ENTRY
        t = str(int(time.time()))
        s = hashlib.md5(''.join([e, t, cfg.STORE_KEY])).hexdigest()

        payload = {'e': e,
                   't': t,
                   's': s,
                   'data': json.dumps(ports)}
        try:
            r = requests.post(cfg.STORE_URL, data=payload, timeout=10).json()
            assert r['status'] == 1, r['info']
        except Exception as e:
            logger.error('Fail to store nmap result: {}'.format(e))
            return {'status': 3, 'msg': 'Fail to store nmap result'}
    else:
        return {'status': 4, 'msg': 'Wrong task type'}

    return {'status': 0, 'msg': 'OK->add {} task'.format(task_type)}


@get('/task/status')
def get_task_status():
    r = TaskManager.get_task_status()
    return {
        'status': 0,
        'start': time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(r[0])),
        'msg': 'OK->get task status',
        'data': {'total': r[1],
                 'masscan_progress': r[1] - r[2],
                 'nmap_progress': r[3]}
    }


@error(404)
def error404(error):
    return '<b>Not Found</b>'


@error(403)
def error403(error):
    return '<b>Forbidden</b>'


##############################################################################
def make_app():
    app = bottle.default_app()
    app.config['SECRET_KEY'] = 'AnDtHisF**KINGSpecTacular'
    return app

app = make_app()

if __name__ == '__main__':
    bottle.run(host='0.0.0.0',
               port=8000,
               debug=cfg.DEBUG,
               reloader=cfg.DEBUG)
