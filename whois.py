#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import socket
import configparser
import re
import chardet
import argparse
import os
from update import update

CONFIG_PATH = 'whois_servers.ini'
DOMAIN_WHOIS_SERVERS = None
IPV4_WHOIS_SERVERS = None

def send(query,server='whois.iana.org',port=43):

   with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((server, port))

        s.send(b'%s\r\n' % bytes(query, encoding='utf-8'))

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
    elif type == 'ipv4':
        Prefix = keyword.split('.')[0]
        whois_server = IPV4_WHOIS_SERVERS.get(Prefix,None)
    else:
        return None

    if whois_server:
        #https://www.arin.net/resources/services/whois_guide.html
        if whois_server in ['whois.arin.net']:
            info  = send(query=('+ n %s' % (keyword)),server=whois_server)
        else:
            info  = send(query=keyword,server=whois_server)
    else:
        info  = send(query=keyword)
    return info


def main(args):

    if args.update:
        update()
    
    if os.path.exists(CONFIG_PATH):
        config = configparser.ConfigParser()
        config.read(CONFIG_PATH)
        global DOMAIN_WHOIS_SERVERS,IPV4_WHOIS_SERVERS
        DOMAIN_WHOIS_SERVERS = config['domain']
        IPV4_WHOIS_SERVERS = config['ipv4']
    else:
        print("Lose whois server config file.You need update.")
        return False

    if args.ipv4:
        info = query(args.ipv4,'ipv4')
        print(str(info,encoding=chardet.detect(info)['encoding']))
    elif args.domain:
        info = query(args.domain,'domain')
        print(str(info,encoding=chardet.detect(info)['encoding']))
    else:
        return False


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Search whois information of IPv4/domain')

    parser.add_argument('-p', '--ipv4', metavar='ipv4', dest='ipv4', action='store',
                    help='search ipv4 whois information')

    parser.add_argument('-d', '--domain', metavar='domain', dest='domain', action='store',
                    help='search domain whois information')

    parser.add_argument('-v', '--version', action='version', version='%(prog)s 1.0 BY felicitychou',
                    help='print version')

    parser.add_argument('--update', dest='update', action='store_true',help='update whois servers')

    main(parser.parse_args())