import requests,re,os
from urllib.parse import urljoin
import csv
import configparser

CONFIG = configparser.ConfigParser()
CONFIG['domain'] = {}
CONFIG['ip'] = {}
CACHE_PATH = 'cache'
if not os.path.exists(CACHE_PATH):
    os.mkdir(CACHE_PATH)

def cache(filename,url):
    data = None
    if CACHE_PATH and os.path.exists(CACHE_PATH) and os.path.isdir(CACHE_PATH):
        filepath = os.path.join(CACHE_PATH,filename)
        if not os.path.exists(filepath):
            r = requests.get(url)
            data = r.content
            with open(filepath,'wb') as fw:
                fw.write(r.content)
        else:
            with open(filepath,'wb') as fr:
                data = fr.read()
    return data


def update():
    # domain
    base_url = 'https://www.iana.org/'


    data = cache()
    
    if CACHE_PATH and os.path.exists(CACHE_PATH) and os.path.isdir(CACHE_PATH):
        ROOT_DB = os.path.join(CACHE_PATH,'root_db.html')
        if not os.path.exists(ROOT_DB):
            r = requests.get('https://www.iana.org/domains/root/db')
            with open(ROOT_DB,'wb') as fw:
                fw.write(r.content)
                data = r.content
        else:
            with open(ROOT_DB,'wb') as fr:
                data = fr.read()

    result = re.findall('(\/domains\/root\/db\/.+?\.html)\">(.+?)<',str(data, encoding='utf-8'))
    for item in result:
        # 
        if 'xn--' in item[0]:
            continue

        TLD_URL = urljoin(base_url,item[0])
        TLD_FILE = os.path.join(CACHE_PATH,os.path.basename(TLD_URL))
        if not os.path.exists(TLD_FILE):
            r = requests.get(TLD_URL)

        if CACHE_PATH:
            with open(TLD_FILE,'wb') as fw:
                fw.write(r.content)

        whois = re.search('WHOIS Server:</b> (\S+)',str(r.content, encoding='utf-8'))
        if whois:
            CONFIG['domain'][item[1][1:]] = whois[1]
        else:
            CONFIG['domain'][item[1][1:]] = ''
        print('Update %s whois server' % (item[1][1:],))

    # ip
    # https://www.iana.org/assignments/ipv4-address-space/ipv4-address-space.csv
    r = requests.get('https://www.iana.org/assignments/ipv4-address-space/ipv4-address-space.csv')
    reader = csv.DictReader(StringIO(str(r.content, encoding='utf-8')))
    for row in reader:
        CONFIG['ip'][str(int(row['Prefix'].split('/')[0]))] = row['WHOIS']
        print('Update %s whois server' % (row['Prefix'],))

    with open('whois_servers.ini', 'w') as configfile:
        CONFIG.write(configfile)  

if __name__ == '__main__':
    update()
