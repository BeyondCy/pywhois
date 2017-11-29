#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import socket
import re 
import chardet
 
def send(keyword,server='whois.iana.org',port=43):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
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
    print(chardet.detect(data)['encoding'])
    return str(data,encoding=chardet.detect(data)['encoding'])

def query(keyword):
    info  = send(keyword=keyword)
    whois_server = re.search(r'whois:\s*([A-Za-z0-9\_\-\.]+)',info).group(1)
    info  = send(keyword=keyword,server=whois_server)
    return info
