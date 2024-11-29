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
            print("\n")
            print((mycolors.reset + "BGPVIEW.IO REPORT".center(100)), end='')
            print((mycolors.reset + "".center(28)), end='')
            print("\n" + (100 * '-').center(50))
            
            if not data:
                if (cv.bkg == 1):
                    print(mycolors.foreground.lightred + "\nNo information available\n" + mycolors.reset)
                else:
                    print(mycolors.foreground.red + "\nNo information available\n" + mycolors.reset)
                return

            fields = {
                'IP Address': data.get('ip'),
                'PTR Record': data.get('ptr_record'),
                'Prefix': data.get('prefixes', [{}])[0].get('prefix'),
                'ASN': data.get('prefixes', [{}])[0].get('asn', {}).get('asn'),
                'AS Name': data.get('prefixes', [{}])[0].get('asn', {}).get('name'),
                'AS Description': data.get('prefixes', [{}])[0].get('asn', {}).get('description'),
                'Country Code': data.get('prefixes', [{}])[0].get('asn', {}).get('country_code')
            }

            COLSIZE = max(len(field) for field in fields.keys()) + 3
            
            for field, value in fields.items():
                if value:
                    if (cv.bkg == 1):
                        print(mycolors.foreground.lightcyan + f"{field}: ".ljust(COLSIZE) + mycolors.reset + str(value))
                    else:
                        print(mycolors.foreground.cyan + f"{field}: ".ljust(COLSIZE) + mycolors.reset + str(value))

        except Exception as e:
            if (cv.bkg == 1):
                print(mycolors.foreground.lightred + f"\nError: {str(e)}\n" + mycolors.reset)
            else:
                print(mycolors.foreground.red + f"\nError: {str(e)}\n" + mycolors.reset)
