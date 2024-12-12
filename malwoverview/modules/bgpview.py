import requests
import malwoverview.modules.configvars as cv
from malwoverview.utils.colors import mycolors

class BGPViewExtractor:
    urlbgpview = "https://api.bgpview.io/ip/"

    def _raw_ip_info(self, ip_address):
        url = f"{BGPViewExtractor.urlbgpview}{ip_address}"
        
        try:
            response = requests.get(url)
            data = response.json()
            return data.get('data', {}) if data.get('status') == 'ok' else {}
        except:
            return {}

    def get_ip_details(self, ip_address):
        data = self._raw_ip_info(ip_address)

        try:
            print()
            print((mycolors.reset + "BGPVIEW.IO REPORT".center(100)), end='')
            print((mycolors.reset + "".center(28)), end='')
            print("\n" + (100 * '-').center(50))
            
            if not data:
                print(mycolors.foreground.error(cv.bkg) + "\nNo information available\n" + mycolors.reset)
                return

            prefixes = data.get('prefixes', [{}])
            if len(prefixes) == 0:
                prefixes = [{}]

            fields = {
                'IP Address': data.get('ip'),
                'PTR Record': data.get('ptr_record'),
                'Prefix': prefixes[0].get('prefix'),
                'ASN': prefixes[0].get('asn', {}).get('asn'),
                'AS Name': prefixes[0].get('asn', {}).get('name'),
                'AS Description': prefixes[0].get('asn', {}).get('description'),
                'Country Code': prefixes[0].get('asn', {}).get('country_code')
            }

            COLSIZE = max(len(field) for field in fields.keys()) + 3
            
            for field, value in fields.items():
                print(mycolors.foreground.info(cv.bkg) + f"{field}: ".ljust(COLSIZE) + mycolors.reset + str(value))

        except Exception as e:
            print(mycolors.foreground.error(cv.bkg) + f"\nError: {str(e)}" + mycolors.reset)
