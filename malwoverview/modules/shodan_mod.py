import malwoverview.modules.configvars as cv
from malwoverview.utils.colors import mycolors, printr
from malwoverview.utils.session import create_session
from malwoverview.utils.cache import cached
from malwoverview.utils.output import collector, is_text_output
from urllib.parse import quote
import json


class ShodanExtractor():
    urlshodan = 'https://api.shodan.io'

    def __init__(self, SHODANAPI):
        self.SHODANAPI = SHODANAPI

    def requestSHODANAPI(self):
        if self.SHODANAPI == '':
            print(mycolors.foreground.error(cv.bkg) + "\nTo be able to get information from Shodan, you must create the .malwapi.conf file under your user home directory (on Linux is $HOME\\.malwapi.conf and on Windows is in C:\\Users\\[username]\\.malwapi.conf) and insert the Shodan API key according to the format shown on the Github website." + mycolors.reset + "\n")
            exit(1)

    @cached("shodan_ip")
    def _raw_ip_info(self, ip):
        self.requestSHODANAPI()

        url = f"{ShodanExtractor.urlshodan}/shodan/host/{quote(ip, safe='')}"
        headers = {'Accept': 'application/json'}
        params = {'key': self.SHODANAPI}

        try:
            session = create_session(headers)
            response = session.get(url, params=params, timeout=30)

            if response.status_code == 401:
                return {'error': 'Unauthorized. Check your Shodan API key.'}
            if response.status_code == 403:
                return {'error': 'Access forbidden. Your API plan may not support this query.'}
            if response.status_code == 404:
                return {'error': 'No information available for this IP.'}
            if response.status_code == 429:
                return {'error': 'Rate limit exceeded. Please wait and try again.'}

            data = response.json()
            return data

        except ValueError:
            return {'error': 'Error parsing JSON response from Shodan.'}
        except Exception as e:
            return {'error': str(e)}

    def shodan_ip(self, ip):
        self.requestSHODANAPI()

        data = self._raw_ip_info(ip)

        try:
            if is_text_output():
                print()
                print((mycolors.reset + "SHODAN IP REPORT".center(100)), end='')
                print((mycolors.reset + "".center(28)), end='')
                print("\n" + (100 * '-').center(50))

            if 'error' in data:
                if is_text_output():
                    print(mycolors.foreground.error(cv.bkg) + f"\n{data['error']}\n" + mycolors.reset)
                return

            ip_addr = str(data.get('ip_str', 'N/A'))
            org = str(data.get('org', 'N/A'))
            isp = str(data.get('isp', 'N/A'))
            os_info = str(data.get('os', 'N/A'))
            ports = ', '.join(str(p) for p in data.get('ports', []))
            vulns = ', '.join(data.get('vulns', []))
            hostnames = ', '.join(data.get('hostnames', []))
            city = str(data.get('city', 'N/A'))
            country = str(data.get('country_name', 'N/A'))
            last_update = str(data.get('last_update', 'N/A'))

            record = {
                'ip': ip_addr,
                'org': org,
                'isp': isp,
                'os': os_info,
                'ports': ports,
                'vulns': vulns,
                'hostnames': hostnames,
                'city': city,
                'country': country,
                'last_update': last_update
            }
            collector.add(record)

            if is_text_output():
                fields = {
                    'IP': ip_addr,
                    'Organization': org,
                    'ISP': isp,
                    'OS': os_info,
                    'Ports': ports if ports else 'N/A',
                    'Vulns': vulns if vulns else 'None',
                    'Hostnames': hostnames if hostnames else 'N/A',
                    'City': city,
                    'Country': country,
                    'Last Update': last_update
                }

                COLSIZE = max(len(field) for field in fields.keys()) + 3

                for field, value in fields.items():
                    if field == 'Vulns' and value != 'None':
                        print(mycolors.foreground.error(cv.bkg) + f"{field}:".ljust(COLSIZE) + "\t" + mycolors.reset + value)
                    else:
                        print(mycolors.foreground.info(cv.bkg) + f"{field}:".ljust(COLSIZE) + "\t" + mycolors.reset + value)

        except Exception as e:
            if is_text_output():
                print(mycolors.foreground.error(cv.bkg) + f"\nError: {str(e)}\n" + mycolors.reset)

    def shodan_search(self, query):
        self.requestSHODANAPI()

        url = f"{ShodanExtractor.urlshodan}/shodan/host/search"
        headers = {'Accept': 'application/json'}
        params = {'key': self.SHODANAPI, 'query': query}

        try:
            session = create_session(headers)
            response = session.get(url, params=params, timeout=30)

            if is_text_output():
                print()
                print((mycolors.reset + "SHODAN SEARCH REPORT".center(100)), end='')
                print((mycolors.reset + "".center(28)), end='')
                print("\n" + (100 * '-').center(50))

            if response.status_code == 401:
                if is_text_output():
                    print(mycolors.foreground.error(cv.bkg) + "\nUnauthorized. Check your Shodan API key.\n" + mycolors.reset)
                return
            if response.status_code == 403:
                if is_text_output():
                    print(mycolors.foreground.error(cv.bkg) + "\nAccess forbidden. Your API plan may not support this query.\n" + mycolors.reset)
                return
            if response.status_code == 404:
                if is_text_output():
                    print(mycolors.foreground.error(cv.bkg) + "\nNo results found.\n" + mycolors.reset)
                return
            if response.status_code == 429:
                if is_text_output():
                    print(mycolors.foreground.error(cv.bkg) + "\nRate limit exceeded. Please wait and try again.\n" + mycolors.reset)
                return

            data = response.json()

            if 'matches' not in data or len(data['matches']) == 0:
                if is_text_output():
                    print(mycolors.foreground.error(cv.bkg) + "\nNo results found for this query.\n" + mycolors.reset)
                return

            COLSIZE = 15

            for match in data['matches']:
                ip_addr = str(match.get('ip_str', 'N/A'))
                port = str(match.get('port', 'N/A'))
                org = str(match.get('org', 'N/A'))
                snippet = str(match.get('data', ''))[:80].replace('\n', ' ').replace('\r', '')

                record = {
                    'ip': ip_addr,
                    'port': port,
                    'org': org,
                    'data_snippet': snippet
                }
                collector.add(record)

                if is_text_output():
                    print()
                    print(mycolors.foreground.info(cv.bkg) + f"IP:".ljust(COLSIZE) + "\t" + mycolors.reset + ip_addr)
                    print(mycolors.foreground.info(cv.bkg) + f"Port:".ljust(COLSIZE) + "\t" + mycolors.reset + port)
                    print(mycolors.foreground.info(cv.bkg) + f"Organization:".ljust(COLSIZE) + "\t" + mycolors.reset + org)
                    print(mycolors.foreground.info(cv.bkg) + f"Data Snippet:".ljust(COLSIZE) + "\t" + mycolors.reset + snippet)
                    print((50 * '-'))

        except ValueError:
            if is_text_output():
                print(mycolors.foreground.error(cv.bkg) + "\nError parsing JSON response from Shodan.\n" + mycolors.reset)
        except Exception as e:
            if is_text_output():
                print(mycolors.foreground.error(cv.bkg) + f"\nError: {str(e)}\n" + mycolors.reset)
