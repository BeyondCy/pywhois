# pywhois


### Usage

```


```



### Sample

```
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import chardet
import whois

if __name__ == '__main__':

    domains = ['baidu.cn','google.com','fff.aab']
    for domain in domains:
        info = whois.query(domain,'domain')
        print(str(info,encoding=chardet.detect(info)['encoding']))

    ips = ['1.1.1.1','2.2.2.2','9.9.9.9']
    for ip in ips:
        info = whois.query(ip,'ip')
        print(str(info,encoding=chardet.detect(info)['encoding']))
```
