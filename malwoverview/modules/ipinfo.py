import malwoverview.modules.configvars as cv
from malwoverview.utils.colors import mycolors
import requests

class IPInfoExtractor:
    def __init__(self, IPINFOAPI):
        self.IPINFOAPI = IPINFOAPI
        
    def requestIPINFOAPI(self):
        if self.IPINFOAPI == '':
            print(mycolors.foreground.red + "\nTo use IPInfo.io services, you must create the .malwapi.conf file under your user home directory (on Linux is $HOME\\.malwapi.conf and on Windows is in C:\\Users\\[username]\\.malwapi.conf) and insert the IPInfo API key according to the format shown on the Github website." + mycolors.reset + "\n")
            exit(1)
            
    def _raw_ip_info(self, ip_address):
        url = f"https://ipinfo.io/{ip_address}?token={self.IPINFOAPI}"
        
        try:
            response = requests.get(url)
            data = response.json()
        except:
            return {}

    def get_ip_details(self, ip_address):
        self.requestIPINFOAPI()
        
        data = self._get_info(ip_address)

        try:
            print("\n")
            print((mycolors.reset + "IPINFO.IO REPORT".center(100)), end='')
            print((mycolors.reset + "".center(28)), end='')
            print("\n" + (100 * '-').center(50))
            
            if 'error' in data:
                if (cv.bkg == 1):
                    print(mycolors.foreground.lightred + f"\n{data['error']['message']}\n" + mycolors.reset)
                else:
                    print(mycolors.foreground.red + f"\n{data['error']['message']}\n" + mycolors.reset)
                return
                
            fields = ['ip', 'hostname', 'city', 'region', 'country', 'loc', 'org', 'postal', 'timezone']

            COLSIZE = max(len(field) for field in fields) + 3
            
            for field in fields:
                if field in data:
                    if (cv.bkg == 1):
                        print(mycolors.foreground.lightcyan + f"{field.title()}: ".ljust(COLSIZE) + mycolors.reset + str(data[field]))
                    else:
                        print(mycolors.foreground.cyan + f"{field.title()}: ".ljust(COLSIZE) + mycolors.reset + str(data[field]))
                        
        except Exception as e:
            if (cv.bkg == 1):
                print(mycolors.foreground.lightred + f"\nError: {str(e)}\n" + mycolors.reset)
            else:
                print(mycolors.foreground.red + f"\nError: {str(e)}\n" + mycolors.reset)
