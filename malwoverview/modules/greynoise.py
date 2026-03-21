import malwoverview.modules.configvars as cv
from malwoverview.utils.colors import mycolors, printr
from malwoverview.utils.session import create_session
from malwoverview.utils.cache import cached
from malwoverview.utils.output import collector, is_text_output
from urllib.parse import quote
import json


class GreyNoiseExtractor():
    urlcommunity = 'https://api.greynoise.io/v3/community'

    def __init__(self, GREYNOISEAPI):
        self.GREYNOISEAPI = GREYNOISEAPI

    def requestGREYNOISEAPI(self):
        if self.GREYNOISEAPI == '':
            print(mycolors.foreground.error(cv.bkg) + "\nTo be able to get information from GreyNoise, you must create the .malwapi.conf file under your user home directory (on Linux is $HOME\\.malwapi.conf and on Windows is in C:\\Users\\[username]\\.malwapi.conf) and insert the GreyNoise API key according to the format shown on the Github website." + mycolors.reset + "\n")
            exit(1)

    @cached("greynoise_ip")
    def _raw_ip_info(self, ip):
        self.requestGREYNOISEAPI()

        url = f"{GreyNoiseExtractor.urlcommunity}/{quote(ip, safe='')}"
        headers = {
            'key': self.GREYNOISEAPI,
            'Accept': 'application/json'
        }

        try:
            session = create_session(headers)
            response = session.get(url, timeout=30)

            if response.status_code == 401:
                return {'error': 'Unauthorized. Check your GreyNoise API key.'}
            if response.status_code == 403:
                return {'error': 'Access forbidden. Check your GreyNoise API permissions.'}
            if response.status_code == 404:
                return {'error': 'IP not found in GreyNoise dataset.'}
            if response.status_code == 429:
                return {'error': 'Rate limit exceeded. Please wait and try again.'}

            data = response.json()
            return data

        except ValueError:
            return {'error': 'Error parsing JSON response from GreyNoise.'}
        except Exception as e:
            return {'error': str(e)}

    def quick_check(self, ip):
        self.requestGREYNOISEAPI()

        data = self._raw_ip_info(ip)

        try:
            if is_text_output():
                print()
                print((mycolors.reset + "GREYNOISE COMMUNITY IP REPORT".center(100)), end='')
                print((mycolors.reset + "".center(28)), end='')
                print("\n" + (100 * '-').center(50))

            if 'error' in data:
                if is_text_output():
                    print(mycolors.foreground.error(cv.bkg) + f"\n{data['error']}\n" + mycolors.reset)
                return

            ip_addr = str(data.get('ip', 'N/A'))
            noise = str(data.get('noise', 'N/A'))
            riot = str(data.get('riot', 'N/A'))
            classification = str(data.get('classification', 'unknown'))
            name = str(data.get('name', 'N/A'))
            last_seen = str(data.get('last_seen', 'N/A'))
            message = str(data.get('message', 'N/A'))

            record = {
                'ip': ip_addr,
                'noise': noise,
                'riot': riot,
                'classification': classification,
                'name': name,
                'last_seen': last_seen,
                'message': message
            }
            collector.add(record)

            if is_text_output():
                fields = {
                    'IP': ip_addr,
                    'Noise': noise,
                    'RIOT': riot,
                    'Classification': classification,
                    'Name': name,
                    'Last Seen': last_seen,
                    'Message': message
                }

                COLSIZE = max(len(field) for field in fields.keys()) + 3

                for field, value in fields.items():
                    if field == 'Classification' and classification == 'malicious':
                        print(mycolors.foreground.error(cv.bkg) + f"{field}:".ljust(COLSIZE) + "\t" + mycolors.reset + value)
                    else:
                        print(mycolors.foreground.info(cv.bkg) + f"{field}:".ljust(COLSIZE) + "\t" + mycolors.reset + value)

        except Exception as e:
            if is_text_output():
                print(mycolors.foreground.error(cv.bkg) + f"\nError: {str(e)}\n" + mycolors.reset)

