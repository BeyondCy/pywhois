#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import socket
import configparser
import re
import chardet

config = configparser.ConfigParser()
config.read('whois_servers.ini')
DOMAIN_WHOIS_SERVERS = config['domain']
IP_WHOIS_SERVERS = config['ip']


def send(keyword,server='whois.iana.org',port=43):

   with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((server, port))
        s.send(b'%s\r\n' % bytes(keyword, encoding='utf-8'))

        buffer = []
        while True:
            d = s.recv(1024)
            if d:
                buffer.append(d)
            else:
                break        
        data = b''.join(buffer)
        return data

def query(keyword,type):

    if type == 'domain':
        TLD = keyword.split('.')[-1]
        whois_server = DOMAIN_WHOIS_SERVERS.get(TLD,None)
    elif type == 'ip':
        Prefix = keyword.split('.')[0]
        whois_server = IP_WHOIS_SERVERS.get(Prefix,None)
    else:
        return None

    if whois_server:
        info  = send(keyword=keyword,server=whois_server)
    else:
        info  = send(keyword=keyword)
    return info
