#!/usr/bin/env python
# encoding: utf-8

import json
import requests

import config


class WebAPI(object):

    @staticmethod
    def post(url, payload):
        try:
            r = requests.post(url, data=payload).json()
        except Exception as e:
            return {'status': -1, 'msg': 'Fail to post: {}'.format(e)}

        return r

    @staticmethod
    def get(url):
        try:
            r = requests.get(url).json()
        except Exception as e:
            return {'status': -1, 'msg': 'Fail to get: {}'.format(e)}

        return r

    @staticmethod
    def register_client(client, pool_size):
        api_url = config.SERVER_URL + '/client/registration'
        payload = {'client_name': client, 'pool_size': pool_size}
        return WebAPI.post(api_url, payload)

    @staticmethod
    def unregister_client(client):
        api_url = config.SERVER_URL + '/client/unregistration'
        payload = {'client_name': client}
        return WebAPI.post(api_url, payload)

    @staticmethod
    def client_ping(client, pool_size, idle):
        api_url = config.SERVER_URL + '/client/ping'
        payload = {'client_name': client,
                   'pool_size': pool_size,
                   'idle': idle}
        return WebAPI.post(api_url, payload)

    @staticmethod
    def publish_task(total, iplist):
        api_url = config.SERVER_URL + '/tasks'
        try:
            iplist = json.dumps(iplist)
        except Exception as e:
            return {'status': -1, 'msg': 'Fail to publish task: {}'.format(e)}
        else:
            payload = {'total': total, 'data': iplist}
            return WebAPI.post(api_url, payload)

    @staticmethod
    def get_masscan_task():
        api_url = config.SERVER_URL + '/task/masscan'
        return WebAPI.get(api_url)

    @staticmethod
    def submit_masscan_result(r):
        api_url = config.SERVER_URL + '/task/masscan/result'
        try:
            payload = {'ip_ports': json.dumps(r)}
        except Exception as e:
            return {'status': -1,
                    'msg': 'Fail to submit masscan result: {}'.format(e)}
        return WebAPI.post(api_url, payload)

    @staticmethod
    def get_nmap_task():
        api_url = config.SERVER_URL + '/task/nmap'
        return WebAPI.get(api_url)

    @staticmethod
    def submit_nmap_result(r):
        api_url = config.SERVER_URL + '/task/nmap/result'
        try:
            payload = {'host': r['host'], 'ports': json.dumps(r['ports'])}
        except Exception as e:
            return {'status': -1,
                    'msg': 'Fail to submit nmap result: {}'.format(e)}
        return WebAPI.post(api_url, payload)
