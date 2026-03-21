import malwoverview.modules.configvars as cv
from malwoverview.utils.colors import mycolors, printc
from malwoverview.utils.session import create_session
import ipaddress

class IPInfoExtractor:
    def __init__(self, IPINFOAPI):
        self.IPINFOAPI = IPINFOAPI

    def _raw_ip_info(self, ip_address):
        try:
            ipaddress.ip_address(ip_address)
        except ValueError:
            return {'error': {'message': 'Invalid IP address format'}}
        
        url = f"https://ipinfo.io/{ip_address}"
        headers = {}
        if self.IPINFOAPI:
            headers['Authorization'] = f'Bearer {self.IPINFOAPI}'

        try:
            requestsession = create_session(headers)
            response = requestsession.get(url, timeout=30)
            return response.json()
        except Exception as e:
            return {'error': {'message': str(e)}}

    def get_ip_details(self, ip_address):
#        self.requestIPINFOAPI()
        
        data = self._raw_ip_info(ip_address)

        try:
            print()
            print((mycolors.reset + "IPINFO.IO REPORT".center(100)), end='')
            print((mycolors.reset + "".center(28)), end='')
            print("\n" + (100 * '-').center(50))
            
            if 'error' in data:
                printc(f"\n{data['error']['message']}\n", mycolors.foreground.error(cv.bkg))
                return
                
            fields = ['ip', 'hostname', 'org', 'country', 'region', 'city', 'loc', 'postal', 'timezone']

            COLSIZE = max(len(field) for field in fields) + 3
            
            for field in fields:
                if field in data:
                    print(mycolors.foreground.info(cv.bkg) + f"{field.title()}: ".ljust(COLSIZE) + mycolors.reset + str(data[field]))

        except Exception as e:
            printc(f"\nError: {str(e)}\n", mycolors.foreground.error(cv.bkg))
