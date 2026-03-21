import malwoverview.modules.configvars as cv
from malwoverview.utils.colors import mycolors, printr
from malwoverview.utils.session import create_session
from malwoverview.utils.output import collector, is_text_output
import json


class WhoisExtractor():
    def __init__(self):
        pass

    def domain_whois(self, domain):
        try:
            import whois
        except ImportError:
            print(mycolors.foreground.error(cv.bkg) + "\nThe 'python-whois' package is required for WHOIS lookups. Please install it:" + mycolors.reset)
            print(mycolors.foreground.error(cv.bkg) + "\n    pip install python-whois\n" + mycolors.reset)
            exit(1)

        try:
            print("\n")
            print((mycolors.reset + "WHOIS DOMAIN REPORT".center(100)), end='')
            print((mycolors.reset + "".center(28)), end='')
            print("\n" + (100 * '-').center(50))

            w = whois.whois(domain)

            COLSIZE = 22
            infocolor = mycolors.foreground.info(cv.bkg)
            errorcolor = mycolors.foreground.error(cv.bkg)

            fields = {
                'Domain Name': w.domain_name,
                'Registrar': w.registrar,
                'Creation Date': w.creation_date,
                'Expiration Date': w.expiration_date,
                'Updated Date': w.updated_date,
                'Name Servers': w.name_servers,
                'Status': w.status,
                'Emails': w.emails,
                'Organization': w.org,
                'Country': w.country
            }

            for field_name, field_value in fields.items():
                if isinstance(field_value, list):
                    display_value = ', '.join([str(v) for v in field_value])
                else:
                    display_value = str(field_value) if field_value is not None else 'N/A'

                if is_text_output():
                    if field_name in ('Expiration Date', 'Status'):
                        print(errorcolor + f"{field_name}:".ljust(COLSIZE) + "\t" + mycolors.reset + display_value)
                    else:
                        print(infocolor + f"{field_name}:".ljust(COLSIZE) + "\t" + mycolors.reset + display_value)

                collector.start_record()
                collector.field('field', field_name)
                collector.field('value', display_value)
                collector.end_record()

        except Exception as e:
            print(mycolors.foreground.error(cv.bkg) + "\nError: " + str(e) + "\n")

        print(mycolors.reset)

    def ip_whois(self, ip):
        try:
            from ipwhois import IPWhois
        except ImportError:
            print(mycolors.foreground.error(cv.bkg) + "\nThe 'ipwhois' package is required for IP WHOIS lookups. Please install it:" + mycolors.reset)
            print(mycolors.foreground.error(cv.bkg) + "\n    pip install ipwhois\n" + mycolors.reset)
            exit(1)

        try:
            print("\n")
            print((mycolors.reset + "WHOIS IP REPORT".center(100)), end='')
            print((mycolors.reset + "".center(28)), end='')
            print("\n" + (100 * '-').center(50))

            obj = IPWhois(ip)
            result = obj.lookup_rdap()

            COLSIZE = 22
            infocolor = mycolors.foreground.info(cv.bkg)
            errorcolor = mycolors.foreground.error(cv.bkg)

            network = result.get('network', {}) or {}
            entities = result.get('entities', []) or []

            fields = {
                'ASN': result.get('asn', 'N/A'),
                'ASN Description': result.get('asn_description', 'N/A'),
                'ASN Country Code': result.get('asn_country_code', 'N/A'),
                'Network Name': network.get('name', 'N/A'),
                'Network CIDR': network.get('cidr', 'N/A'),
                'Entities': ', '.join(entities) if entities else 'N/A'
            }

            for field_name, field_value in fields.items():
                display_value = str(field_value) if field_value is not None else 'N/A'

                if is_text_output():
                    if field_name == 'ASN':
                        print(errorcolor + f"{field_name}:".ljust(COLSIZE) + "\t" + mycolors.reset + display_value)
                    else:
                        print(infocolor + f"{field_name}:".ljust(COLSIZE) + "\t" + mycolors.reset + display_value)

                collector.start_record()
                collector.field('field', field_name)
                collector.field('value', display_value)
                collector.end_record()

        except Exception as e:
            print(mycolors.foreground.error(cv.bkg) + "\nError: " + str(e) + "\n")

        print(mycolors.reset)
