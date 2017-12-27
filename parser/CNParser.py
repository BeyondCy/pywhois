from BasicParser import BasicParser

class CNParser(BasicParser):
    
    def __init__(self):
        super().__init__()

    def parse(self, data, whois_server):
        self.data = data
        if 'whois.cnnic.cn' == whois_server:
            return self.parse1()

        
    # whois.cnnic.cn
    def parse1(self):

        confs = [
            {'name': 'DOMAIN', 'restr': r'Domain Name: (\S+)', 'func': self.lower},
            {'name': 'REGISTRY_DOMAIN_ID', 'restr': r'ROID: (\S+)'},
            {'name': 'DOMAIN_STATUS', 'restr': r'Domain Status: ([\S ]+)'},
            {'name': 'REGISTRANT_ID', 'restr': r'Registrant ID: (\S+)'},
            {'name': 'REGISTRANT_NAME', 'restr': r'Registrant: (.+)'},
            {'name': 'REGISTRANT_EMAIL',
                'restr': r'Registrant Contact Email: (\S+)'},
            {'name': 'REGISTAR_NAME',
                'restr': r'Sponsoring Registrar: ([\S ]+)'},
            {'name': 'NAME_SERVER', 'restr': r'Name Server: ([\S ]+)'},
            {'name': 'CREATION_DATE',
                'restr': r'Registration Time: ([\S ]+)', 'func': self.str2datetime},
            {'name': 'EXPIRY_DATE',
                'restr': r'Expiration Time: ([\S ]+)', 'func': self.str2datetime},
            {'name': 'DNSSEC', 'restr': r'DNSSEC: (\S+)'},
        ]

        registered = 'Domain Name'
        unregistered = 'No matching record.'

        try:
            if registered in self.data:
                self._parse(confs=confs)
                return {'registered': True, 'whois': self.whois}             
            elif unregistered in self.data:
                return {'registered': False}
            else:
                return {'error': self.data}
        except Exception as e:
            print(e)


def main():
    registered = r'''
Domain Name: zzz.cn
ROID: 20040402s10001s01177921-cn
Domain Status: clientDeleteProhibited
Domain Status: clientTransferProhibited
Registrant ID: ename_hdu2emr64c
Registrant: 西部數碼國際有限公司
Registrant Contact Email: domain@dai.top
Sponsoring Registrar: 厦门易名科技股份有限公司
Name Server: ns1.4.cn
Name Server: ns2.4.cn
Registration Time: 2004-04-02 04:45:13
Expiration Time: 2018-04-02 04:45:13
DNSSEC: unsigned
    '''

    unregistered = r'No matching record.'
    error = r'Invalid parameter: zs.game2.cn'

    Parser = CNParser()
    print(Parser.parse(data=registered, whois_server='whois.cnnic.cn'))
    print(Parser.parse(data=unregistered, whois_server='whois.cnnic.cn'))
    print(Parser.parse(data=error, whois_server='whois.cnnic.cn'))


if __name__ == '__main__':
    main()
