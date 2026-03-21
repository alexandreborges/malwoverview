import malwoverview.modules.configvars as cv
from malwoverview.utils.colors import mycolors, printr
from malwoverview.utils.session import create_session
from malwoverview.utils.cache import cached
from malwoverview.utils.output import collector, is_text_output
import json


class AbuseIPDBExtractor():
    urlbase = 'https://api.abuseipdb.com/api/v2'

    def __init__(self, ABUSEIPDBAPI):
        self.ABUSEIPDBAPI = ABUSEIPDBAPI

    def requestABUSEIPDBAPI(self):
        if self.ABUSEIPDBAPI == '':
            print(mycolors.foreground.error(cv.bkg) + "\nTo be able to get information from AbuseIPDB, you must create the .malwapi.conf file under your user home directory (on Linux is $HOME\\.malwapi.conf and on Windows is in C:\\Users\\[username]\\.malwapi.conf) and insert the AbuseIPDB API key according to the format shown on the Github website." + mycolors.reset + "\n")
            exit(1)

    @cached("abuseipdb_ip")
    def _raw_ip_info(self, ip):
        self.requestABUSEIPDBAPI()

        url = f"{AbuseIPDBExtractor.urlbase}/check"
        headers = {
            'Key': self.ABUSEIPDBAPI,
            'Accept': 'application/json'
        }
        params = {
            'ipAddress': ip,
            'maxAgeInDays': '90',
            'verbose': ''
        }

        try:
            session = create_session(headers)
            response = session.get(url, params=params, timeout=30)

            if response.status_code == 401:
                return {'error': 'Unauthorized. Check your AbuseIPDB API key.'}
            if response.status_code == 403:
                return {'error': 'Access forbidden. Check your AbuseIPDB API permissions.'}
            if response.status_code == 404:
                return {'error': 'Resource not found.'}
            if response.status_code == 429:
                return {'error': 'Rate limit exceeded. Please wait and try again.'}

            data = response.json()
            return data

        except ValueError:
            return {'error': 'Error parsing JSON response from AbuseIPDB.'}
        except Exception as e:
            return {'error': str(e)}

    def check_ip(self, ip):
        self.requestABUSEIPDBAPI()

        data = self._raw_ip_info(ip)

        try:
            if is_text_output():
                print()
                print((mycolors.reset + "ABUSEIPDB IP REPORT".center(100)), end='')
                print((mycolors.reset + "".center(28)), end='')
                print("\n" + (100 * '-').center(50))

            if 'error' in data:
                if is_text_output():
                    print(mycolors.foreground.error(cv.bkg) + f"\n{data['error']}\n" + mycolors.reset)
                return

            report = data.get('data', {})

            ip_addr = str(report.get('ipAddress', 'N/A'))
            abuse_score = str(report.get('abuseConfidenceScore', 'N/A'))
            isp = str(report.get('isp', 'N/A'))
            usage_type = str(report.get('usageType', 'N/A'))
            country = str(report.get('countryCode', 'N/A'))
            domain = str(report.get('domain', 'N/A'))
            total_reports = str(report.get('totalReports', 'N/A'))
            num_distinct_users = str(report.get('numDistinctUsers', 'N/A'))
            last_reported = str(report.get('lastReportedAt', 'N/A'))

            record = {
                'ip': ip_addr,
                'abuse_confidence_score': abuse_score,
                'isp': isp,
                'usage_type': usage_type,
                'country': country,
                'domain': domain,
                'total_reports': total_reports,
                'num_distinct_users': num_distinct_users,
                'last_reported_at': last_reported
            }
            collector.add(record)

            if is_text_output():
                fields = {
                    'IP': ip_addr,
                    'Abuse Score': abuse_score,
                    'ISP': isp,
                    'Usage Type': usage_type,
                    'Country': country,
                    'Domain': domain,
                    'Total Reports': total_reports,
                    'Distinct Users': num_distinct_users,
                    'Last Reported': last_reported
                }

                COLSIZE = max(len(field) for field in fields.keys()) + 3

                for field, value in fields.items():
                    if field == 'Abuse Score':
                        try:
                            score = int(abuse_score)
                        except (ValueError, TypeError):
                            score = 0
                        if score >= 50:
                            print(mycolors.foreground.error(cv.bkg) + f"{field}:".ljust(COLSIZE) + "\t" + mycolors.reset + value)
                        else:
                            print(mycolors.foreground.info(cv.bkg) + f"{field}:".ljust(COLSIZE) + "\t" + mycolors.reset + value)
                    elif field == 'Total Reports':
                        try:
                            rcount = int(total_reports)
                        except (ValueError, TypeError):
                            rcount = 0
                        if rcount > 0:
                            print(mycolors.foreground.error(cv.bkg) + f"{field}:".ljust(COLSIZE) + "\t" + mycolors.reset + value)
                        else:
                            print(mycolors.foreground.info(cv.bkg) + f"{field}:".ljust(COLSIZE) + "\t" + mycolors.reset + value)
                    else:
                        print(mycolors.foreground.info(cv.bkg) + f"{field}:".ljust(COLSIZE) + "\t" + mycolors.reset + value)

        except Exception as e:
            if is_text_output():
                print(mycolors.foreground.error(cv.bkg) + f"\nError: {str(e)}\n" + mycolors.reset)
