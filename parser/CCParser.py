from BasicParser import BasicParser

class CCParser(BasicParser):
    
    def __init__(self):
        super().__init__()

    def parse(self, data, whois_server):
        self.data = data
        if 'ccwhois.verisign-grs.com' == whois_server:
            return self.parse1()

    # ccwhois.verisign-grs.com
    def parse1(self):

        registered = 'Domain Name'
        unregistered = 'No match'

        registered_confs = [
            {'name': 'DOMAIN', 'restr': r'Domain Name: (\S+)', 'func': self.lower},
            {'name': 'REGISTRY_DOMAIN_ID',
                'restr': r'Registry Domain ID: (\S+)'},
            {'name': 'REGISTRAR_WHOIS_SERVER',
                'restr': r'Registrar WHOIS Server: (\S+)'},
            {'name': 'REGISTRAR_URL',
             'restr': r'Registrar URL: (\S+)'},
            {'name': 'UPDATE_DATE',
             'restr': r'Updated Date: ([\S ]+)', 'func': self.str2datetime},
            {'name': 'CREATION_DATE',
                'restr': r'Creation Date: ([\S ]+)', 'func': self.str2datetime},
            {'name': 'EXPIRY_DATE',
                'restr': r'Registry Expiry Date: ([\S ]+)', 'func': self.str2datetime},
            {'name': 'REGISTAR_NAME','restr': r'Registrar: ([\S ]+)'},
            {'name': 'REGISTAR_IANA_ID',
                'restr': r'Registrar IANA ID: ([\S ]+)'},
            {'name': 'REGISTAR_ABUSE_CONTACT_EMAIL',
             'restr': r'Registrar Abuse Contact Email: (\S+)'},
            {'name': 'REGISTAR_ABUSE_CONTACT_PHONE',
             'restr': r'Registrar Abuse Contact Phone: (\S+)'},
            {'name': 'DOMAIN_STATUS', 'restr': r'Domain Status: ([\S ]+)'},
            {'name': 'NAME_SERVER', 'restr': r'Name Server: ([\S ]+)'},
            {'name': 'DNSSEC', 'restr': r'DNSSEC: (\S+)'},
            {'name': 'WHOIS_DATABASE_LAST_UPDATE_DATE',
                'restr': r'Last update of WHOIS database: (\S+)','func': self.str2datetime},
        ]

        unregistered_confs = [
            {'name': 'DOMAIN',
                'restr': r'No match for \"(\S+)\"', 'func': self.lower},
            {'name': 'WHOIS_DATABASE_LAST_UPDATE_DATE',
                               'restr': r'Last update of WHOIS database: (\S+)', 'func': self.str2datetime},

        ]



        try:
            if registered in self.data:
                self._parse(confs=registered_confs)
                return {'registered': True, 'whois': self.whois}             
            elif unregistered in self.data:
                self._parse(confs=unregistered_confs)
                return {'registered': False, 'whois': self.whois}
            else:
                return {'error': self.data}
        except Exception as e:
            print(e)


def main():
    registered = r'''
   Domain Name: JWGCYKHWMVRNUV.CC
   Registry Domain ID: 127448568_DOMAIN_CC-VRSN
   Registrar WHOIS Server:
   Registrar URL:
   Updated Date: 2017-12-01T08:00:46Z
   Creation Date: 2016-11-30T14:13:11Z
   Registry Expiry Date: 2018-11-30T14:13:11Z
   Registrar: VERISIGN SECURITY AND STABILITY
   Registrar IANA ID: 8888888
   Registrar Abuse Contact Email:
   Registrar Abuse Contact Phone:
   Domain Status: serverDeleteProhibited https://icann.org/epp#serverDeleteProhibited
   Domain Status: serverTransferProhibited https://icann.org/epp#serverTransferProhibited
   Domain Status: serverUpdateProhibited https://icann.org/epp#serverUpdateProhibited
   Name Server: SC-A.SINKHOLE.SHADOWSERVER.ORG
   Name Server: SC-B.SINKHOLE.SHADOWSERVER.ORG
   Name Server: SC-C.SINKHOLE.SHADOWSERVER.ORG
   Name Server: SC-D.SINKHOLE.SHADOWSERVER.ORG
   DNSSEC: unsigned
   URL of the ICANN Whois Inaccuracy Complaint Form: https://www.icann.org/wicf/
>>> Last update of WHOIS database: 2017-12-22T04:57:37Z <<<

For more information on Whois status codes, please visit https://icann.org/epp

NOTICE: The expiration date displayed in this record is the date the
registrar's sponsorship of the domain name registration in the registry is
currently set to expire. This date does not necessarily reflect the
expiration date of the domain name registrant's agreement with the
sponsoring registrar.  Users may consult the sponsoring registrar's
Whois database to view the registrar's reported date of expiration
for this registration.

TERMS OF USE: You are not authorized to access or query our Whois
database through the use of electronic processes that are high-volume and
automated except as reasonably necessary to register domain names or
modify existing registrations; the Data in VeriSign's ("VeriSign") Whois
database is provided by VeriSign for information purposes only, and to
assist persons in obtaining information about or related to a domain name
registration record. VeriSign does not guarantee its accuracy.
By submitting a Whois query, you agree to abide by the following terms of
use: You agree that you may use this Data only for lawful purposes and that
under no circumstances will you use this Data to: (1) allow, enable, or
otherwise support the transmission of mass unsolicited, commercial
advertising or solicitations via e-mail, telephone, or facsimile; or
(2) enable high volume, automated, electronic processes that apply to
VeriSign (or its computer systems). The compilation, repackaging,
dissemination or other use of this Data is expressly prohibited without
the prior written consent of VeriSign. You agree not to use electronic
processes that are automated and high-volume to access or query the
Whois database except as reasonably necessary to register domain names
or modify existing registrations. VeriSign reserves the right to restrict
your access to the Whois database in its sole discretion to ensure
operational stability.  VeriSign may restrict or terminate your access to the
Whois database for failure to abide by these terms of use. VeriSign
reserves the right to modify these terms at any time.
    '''

    unregistered = r'''
    No match for "I1B38867D3178801970C8E92961E610EFA.CC".
>>> Last update of WHOIS database: 2017-12-22T05:29:54Z <<<

NOTICE: The expiration date displayed in this record is the date the
registrar's sponsorship of the domain name registration in the registry is
currently set to expire. This date does not necessarily reflect the
expiration date of the domain name registrant's agreement with the
sponsoring registrar.  Users may consult the sponsoring registrar's
Whois database to view the registrar's reported date of expiration
for this registration.

TERMS OF USE: You are not authorized to access or query our Whois
database through the use of electronic processes that are high-volume and
automated except as reasonably necessary to register domain names or
modify existing registrations; the Data in VeriSign's ("VeriSign") Whois
database is provided by VeriSign for information purposes only, and to
assist persons in obtaining information about or related to a domain name
registration record. VeriSign does not guarantee its accuracy.
By submitting a Whois query, you agree to abide by the following terms of
use: You agree that you may use this Data only for lawful purposes and that
under no circumstances will you use this Data to: (1) allow, enable, or
otherwise support the transmission of mass unsolicited, commercial
advertising or solicitations via e-mail, telephone, or facsimile; or
(2) enable high volume, automated, electronic processes that apply to
VeriSign (or its computer systems). The compilation, repackaging,
dissemination or other use of this Data is expressly prohibited without
the prior written consent of VeriSign. You agree not to use electronic
processes that are automated and high-volume to access or query the
Whois database except as reasonably necessary to register domain names
or modify existing registrations. VeriSign reserves the right to restrict
your access to the Whois database in its sole discretion to ensure
operational stability.  VeriSign may restrict or terminate your access to the
Whois database for failure to abide by these terms of use. VeriSign
reserves the right to modify these terms at any time.

    '''

    error = r'Invalid parameter: zs.game2.cn'

    Parser = CCParser()
    print(Parser.parse(data=registered, whois_server='ccwhois.verisign-grs.com'))
    print(Parser.parse(data=unregistered, whois_server='ccwhois.verisign-grs.com'))
    #print(Parser.parse(data=error, whois_server='whois.cnnic.cn'))


if __name__ == '__main__':
    main()
