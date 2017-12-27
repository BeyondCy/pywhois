
import re
from datetime import datetime

class BasicParser(object):
    
    def __init__(self):
        self.data = None
        self.whois = None
        self.datetime_formats = [
            r'%Y-%m-%dT%XZ',  # ORG/CC 2017-08-04T02:50:15Z 
                    r'%Y-%m-%d %X',  # CN 2005-05-31 13:05:48
                ]
        self.init_field_names()

    def init_field_names(self):
        self.field_names = {
            'DOMAIN': '',
            'REGISTRY_DOMAIN_ID': '',
            'REGISTRAR_WHOIS_SERVER': '',
            'REGISTRAR_URL': '',
            'UPDATE_DATE': '',
            'CREATION_DATE': '',
            'EXPIRY_DATE': '',
            'REGISTRAR_EXPIRY_DATE': '',
            'REGISTAR_NAME': '',
            'REGISTAR_IANA_ID': '',
            'REGISTAR_ABUSE_CONTACT_EMAIL': '',
            'REGISTAR_ABUSE_CONTACT_PHONE': '',
            'RESELLER': '',
            'REGISTRANT_ID': '',
            'REGISTRANT_NAME': '',
            'REGISTRANT_ORGANIZATION': '',
            'REGISTRANT_STREET': '',
            'REGISTRANT_CITY': '',
            'REGISTRANT_STATE': '',
            'REGISTRANT_POSTAL_CODE': '',
            'REGISTRANT_COUNTRY': '',
            'REGISTRANT_PHONE': '',
            'REGISTRANT_PHONE_EXT': '',
            'REGISTRANT_FAX': '',
            'REGISTRANT_FAX_EXT': '',
            'REGISTRANT_EMAIL': '',
            'ADMAIN_ID': '',
            'ADMIN_NAME': '',
            'ADMIN_ORGANIZATION': '',
            'ADMIN_STREET': '',
            'ADMIN_CITY': '',
            'ADMIN_STATE': '',
            'ADMIN_POSTAL_CODE': '',
            'ADMIN_COUNTRY': '',
            'ADMIN_PHONE': '',
            'ADMIN_PHONE_EXT': '',
            'ADMIN_FAX': '',
            'ADMIN_FAX_EXT': '',
            'ADMIN_EMAIL': '',
            'TECH_ID': '',
            'TECH_NAME': '',
            'TECH_ORGANIZATION': '',
            'TECH_STREET': '',
            'TECH_CITY': '',
            'TECH_STATE': '',
            'TECH_POSTAL_CODE': '',
            'TECH_COUNTRY': '',
            'TECH_PHONE': '',
            'TECH_PHONE_EXT': '',
            'TECH_FAX': '',
            'TECH_FAX_EXT': '',
            'TECH_EMAIL': '',
            'NAME_SERVER': '',
            'DOMAIN_STATUS': '',
            'DNSSEC': '',
            'WHOIS_DATABASE_LAST_UPDATE_DATE': '',

        }

        for field in self.field_names:
            if not self.field_names.get(field):
                self.field_names[field] = field.lower()


    def parse(self,data):
        pass

    def _parse(self,confs):
        self.whois = {}
        for conf in confs:
            field_name = self.field_names.get(conf['name'],None)
            func = conf.get('func', None)
            # if name wrong
            if not field_name:
                raise ValueError(
                    'field name %s of conf Not found.' % conf['name'])
                #continue

            result = re.findall(pattern=conf['restr'], string=self.data)
            if not result:
                self.whois[field_name] = None
            elif len(result) == 1:
                if func:
                    self.whois[field_name] = func(result[0])
                else:
                    self.whois[field_name] = result[0]
            else:
                if func:
                    self.whois[field_name] = [func(item) for item in result]
                else:
                    self.whois[field_name] = [item for item in result]
        return True

    def lower(self,data):
        return data.lower()

    def str2datetime(self,data):
        for datetime_format in self.datetime_formats:
            try:
                return datetime.strptime(data, datetime_format)
            except Exception as e:
                continue
        return data

    def str2timestamp(self,data):
        for datetime_format in self.datetime_formats:
            try:
                return int(round(datetime.strptime(data, datetime_format).timestamp()) * 1000)
            except Exception as e:
                continue
        return data










