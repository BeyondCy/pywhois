import requests,re,os
from urllib.parse import urljoin
import csv
import configparser
from io import StringIO

CONFIG = configparser.ConfigParser()
CONFIG['domain'] = {}
CONFIG['ip'] = {}
CACHE_PATH = 'cache'
if not os.path.exists(CACHE_PATH):
    os.mkdir(CACHE_PATH)

def download(filename,url):
    data = None
    if CACHE_PATH and os.path.exists(CACHE_PATH) and os.path.isdir(CACHE_PATH):
        filepath = os.path.join(CACHE_PATH,filename)
        if os.path.exists(filepath):
            with open(filepath,'rb') as fr:
                data = fr.read()
        else:
            r = requests.get(url)
            data = r.content
            with open(filepath,'wb') as fw:
                fw.write(r.content)
    else:
        r = requests.get(url)
        data = r.content

    return data


def update():
    # domain
    data = download(filename='root_db.html',url='https://www.iana.org/domains/root/db')
    result = re.findall('(\/domains\/root\/db\/.+?\.html)\">(.+?)<',str(data, encoding='utf-8'))
    for item in result:
        # 
        if 'xn--' in item[0]:
            continue

        TLD_URL = urljoin('https://www.iana.org/',item[0])
        data = download(filename=os.path.basename(TLD_URL),url=TLD_URL)

        whois = re.search('WHOIS Server:</b> (\S+)',str(data, encoding='utf-8'))
        CONFIG['domain'][item[1][1:]] = whois[1] if whois else ''

        print('Update %s whois server' % (item[1][1:],))

    # ip
    # https://www.iana.org/assignments/ipv4-address-space/ipv4-address-space.csv
    IPv4_URL = 'https://www.iana.org/assignments/ipv4-address-space/ipv4-address-space.csv'
    data = download(filename=os.path.basename(IPv4_URL),url=IPv4_URL)
    reader = csv.DictReader(StringIO(str(data, encoding='utf-8')))
    for row in reader:
        CONFIG['ip'][str(int(row['Prefix'].split('/')[0]))] = row['WHOIS']
        print('Update %s whois server' % (row['Prefix'],))

    with open('whois_servers.ini', 'w') as configfile:
        CONFIG.write(configfile)  

if __name__ == '__main__':
    update()