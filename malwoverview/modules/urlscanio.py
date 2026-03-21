import malwoverview.modules.configvars as cv
from malwoverview.utils.colors import mycolors, printr
from malwoverview.utils.session import create_session
from malwoverview.utils.cache import cached
from malwoverview.utils.output import collector, is_text_output
from urllib.parse import quote
import json
import time


# Centralized table column widths
COL_DOMAIN = 45
COL_IP = 18
COL_COUNTRY = 9
COL_STATUS = 8
COL_ASN = 10
COL_SCORE = 7
COL_DATE = 22
COL_UUID = 36
TABLE_WIDTH = COL_DOMAIN + COL_IP + COL_COUNTRY + COL_STATUS + COL_ASN + COL_SCORE + COL_DATE + COL_UUID

MAX_SEARCH_RESULTS = 30


class URLScanIOExtractor():
    urlbase = 'https://urlscan.io/api/v1'

    def __init__(self, URLSCANIOAPI):
        self.URLSCANIOAPI = URLSCANIOAPI

    def requestURLSCANIOAPI(self):
        if self.URLSCANIOAPI == '':
            print(mycolors.foreground.error(cv.bkg) + "\nTo be able to get information from URLScan.io, you must create the .malwapi.conf file under your user home directory (on Linux is $HOME\\.malwapi.conf and on Windows is in C:\\Users\\[username]\\.malwapi.conf) and insert the URLScan.io API key according to the format shown on the Github website." + mycolors.reset + "\n")
            exit(1)

    def _handle_status(self, response):
        if response.status_code == 401:
            return {'error': 'Unauthorized. Check your URLScan.io API key.'}
        if response.status_code == 403:
            return {'error': 'Access forbidden. Check your URLScan.io API permissions.'}
        if response.status_code == 404:
            return {'error': 'Resource not found.'}
        if response.status_code == 429:
            return {'error': 'Rate limit exceeded. Please wait and try again.'}
        return None

    def _print_search_header(self):
        header = (
            mycolors.foreground.info(cv.bkg)
            + "Domain".ljust(COL_DOMAIN)
            + "IP".ljust(COL_IP)
            + "Country".ljust(COL_COUNTRY)
            + "Status".ljust(COL_STATUS)
            + "ASN".ljust(COL_ASN)
            + "Score".ljust(COL_SCORE)
            + "Date".ljust(COL_DATE)
            + "UUID"
            + mycolors.reset
        )
        print()
        print(header)
        print((TABLE_WIDTH * '-'))

    def _print_search_row(self, page_domain, page_ip, page_country, page_status, page_asn, verdict_score, task_time, task_uuid):
        row = (
            page_domain[:COL_DOMAIN - 2].ljust(COL_DOMAIN)
            + page_ip[:COL_IP - 2].ljust(COL_IP)
            + page_country[:COL_COUNTRY - 2].ljust(COL_COUNTRY)
            + page_status[:COL_STATUS - 2].ljust(COL_STATUS)
            + page_asn[:COL_ASN - 2].ljust(COL_ASN)
            + verdict_score[:COL_SCORE - 2].ljust(COL_SCORE)
            + task_time.ljust(COL_DATE)
            + task_uuid
        )
        print(row)

    def urlscanio_submit(self, url_to_scan):
        self.requestURLSCANIOAPI()

        url = f"{URLScanIOExtractor.urlbase}/scan/"
        headers = {
            'API-Key': self.URLSCANIOAPI,
            'Content-Type': 'application/json'
        }
        payload = {
            'url': url_to_scan,
            'visibility': 'public'
        }

        try:
            session = create_session(headers)
            response = session.post(url, json=payload, timeout=30)

            if is_text_output():
                print()
                print((mycolors.reset + "URLSCAN.IO SUBMISSION REPORT".center(100)), end='')
                print((mycolors.reset + "".center(28)), end='')
                print("\n" + (100 * '-').center(50))

            err = self._handle_status(response)
            if err:
                if is_text_output():
                    print(mycolors.foreground.error(cv.bkg) + f"\n{err['error']}\n" + mycolors.reset)
                return

            data = response.json()

            if 'message' in data and 'uuid' not in data:
                if is_text_output():
                    print(mycolors.foreground.error(cv.bkg) + f"\n{data.get('message', 'Submission failed.')}\n" + mycolors.reset)
                return

            scan_uuid = str(data.get('uuid', 'N/A'))
            scan_url = str(data.get('result', 'N/A'))
            api_url = str(data.get('api', 'N/A'))
            visibility = str(data.get('visibility', 'N/A'))
            submitted_url = str(data.get('url', 'N/A'))

            record = {
                'uuid': scan_uuid,
                'url': submitted_url,
                'result_url': scan_url,
                'api_url': api_url,
                'visibility': visibility
            }
            collector.add(record)

            if is_text_output():
                fields = {
                    'UUID': scan_uuid,
                    'Submitted URL': submitted_url,
                    'Result Page': scan_url,
                    'API Result': api_url,
                    'Visibility': visibility,
                }

                COLSIZE = max(len(f) for f in fields.keys()) + 3

                for field, value in fields.items():
                    print(mycolors.foreground.info(cv.bkg) + f"{field}:".ljust(COLSIZE) + "\t" + mycolors.reset + value)

                print()
                print(mycolors.foreground.info(cv.bkg) + f"{'Note:'.ljust(COLSIZE)}" + "\t" + mycolors.reset + "Results take ~15 seconds. Use -u 2 -U <uuid> to retrieve.")

        except ValueError:
            if is_text_output():
                print(mycolors.foreground.error(cv.bkg) + "\nError parsing JSON response from URLScan.io.\n" + mycolors.reset)
        except Exception as e:
            if is_text_output():
                print(mycolors.foreground.error(cv.bkg) + f"\nError: {str(e)}\n" + mycolors.reset)

    @cached("urlscanio_result")
    def _raw_result(self, uuid):
        self.requestURLSCANIOAPI()

        url = f"{URLScanIOExtractor.urlbase}/result/{quote(uuid, safe='')}/"
        headers = {
            'API-Key': self.URLSCANIOAPI,
            'Accept': 'application/json'
        }

        try:
            session = create_session(headers)
            response = session.get(url, timeout=30)

            err = self._handle_status(response)
            if err:
                return err

            data = response.json()
            return data

        except ValueError:
            return {'error': 'Error parsing JSON response from URLScan.io.'}
        except Exception as e:
            return {'error': str(e)}

    def urlscanio_result(self, uuid):
        self.requestURLSCANIOAPI()

        data = self._raw_result(uuid)

        try:
            if is_text_output():
                print()
                print((mycolors.reset + "URLSCAN.IO SCAN RESULT".center(100)), end='')
                print((mycolors.reset + "".center(28)), end='')
                print("\n" + (100 * '-').center(50))

            if 'error' in data:
                if is_text_output():
                    print(mycolors.foreground.error(cv.bkg) + f"\n{data['error']}\n" + mycolors.reset)
                return

            task = data.get('task', {})
            page = data.get('page', {})
            stats = data.get('stats', {})
            lists = data.get('lists', {})
            verdicts = data.get('verdicts', {})

            task_url = str(task.get('url', 'N/A'))
            task_domain = str(task.get('domain', 'N/A'))
            task_time = str(task.get('time', 'N/A'))
            task_visibility = str(task.get('visibility', 'N/A'))

            page_ip = str(page.get('ip', 'N/A'))
            page_country = str(page.get('country', 'N/A'))
            page_server = str(page.get('server', 'N/A'))
            page_title = str(page.get('title', 'N/A'))[:80]
            page_status = str(page.get('status', 'N/A'))
            page_mime = str(page.get('mimeType', 'N/A'))
            page_asn = str(page.get('asn', 'N/A'))
            page_asnname = str(page.get('asnname', 'N/A'))

            total_requests = str(stats.get('uniqIPs', 'N/A'))
            resource_count = str(stats.get('totalLinks', 'N/A'))

            overall_verdict = verdicts.get('overall', {})
            malicious = str(overall_verdict.get('malicious', False))
            score = str(overall_verdict.get('score', 0))
            verdict_categories = ', '.join(overall_verdict.get('categories', [])) or 'None'
            verdict_tags = ', '.join(overall_verdict.get('tags', [])) or 'None'

            ips_list = lists.get('ips', [])
            domains_list = lists.get('domains', [])
            countries_list = lists.get('countries', [])

            ips_str = ', '.join(ips_list[:10])
            if len(ips_list) > 10:
                ips_str += f' (+{len(ips_list) - 10} more)'
            domains_str = ', '.join(domains_list[:10])
            if len(domains_list) > 10:
                domains_str += f' (+{len(domains_list) - 10} more)'
            countries_str = ', '.join(countries_list) if countries_list else 'N/A'

            record = {
                'url': task_url,
                'domain': task_domain,
                'ip': page_ip,
                'country': page_country,
                'server': page_server,
                'title': page_title,
                'status_code': page_status,
                'mime_type': page_mime,
                'asn': page_asn,
                'asn_name': page_asnname,
                'scan_time': task_time,
                'visibility': task_visibility,
                'unique_ips': total_requests,
                'total_links': resource_count,
                'malicious': malicious,
                'verdict_score': score,
                'verdict_categories': verdict_categories,
                'verdict_tags': verdict_tags,
                'contacted_ips': ips_str,
                'contacted_domains': domains_str,
                'countries': countries_str
            }
            collector.add(record)

            if is_text_output():
                fields = {
                    'URL': task_url,
                    'Domain': task_domain,
                    'IP': page_ip,
                    'Country': page_country,
                    'ASN': page_asn,
                    'ASN Name': page_asnname,
                    'Server': page_server,
                    'Status Code': page_status,
                    'MIME Type': page_mime,
                    'Page Title': page_title,
                    'Scan Time': task_time,
                    'Visibility': task_visibility,
                    'Unique IPs': total_requests,
                    'Total Links': resource_count,
                    'Malicious': malicious,
                    'Verdict Score': score,
                    'Categories': verdict_categories,
                    'Tags': verdict_tags,
                    'Contacted IPs': ips_str if ips_str else 'None',
                    'Contacted Domains': domains_str if domains_str else 'None',
                    'Countries': countries_str,
                }

                COLSIZE = max(len(f) for f in fields.keys()) + 3

                for field, value in fields.items():
                    print(mycolors.foreground.info(cv.bkg) + f"{field}:".ljust(COLSIZE) + "\t" + mycolors.reset + value)

                certs = data.get('lists', {}).get('certificates', [])
                if certs:
                    print()
                    print(mycolors.foreground.info(cv.bkg) + "SSL Certificates:" + mycolors.reset)
                    CERT_COLSIZE = 16
                    for cert in certs[:5]:
                        subject = str(cert.get('subjectName', 'N/A'))
                        issuer = str(cert.get('issuer', 'N/A'))
                        valid_from = str(cert.get('validFrom', 'N/A'))
                        valid_to = str(cert.get('validTo', 'N/A'))
                        print()
                        print(mycolors.foreground.info(cv.bkg) + "  Subject:".ljust(CERT_COLSIZE) + "\t" + mycolors.reset + subject)
                        print(mycolors.foreground.info(cv.bkg) + "  Issuer:".ljust(CERT_COLSIZE) + "\t" + mycolors.reset + issuer)
                        print(mycolors.foreground.info(cv.bkg) + "  Valid From:".ljust(CERT_COLSIZE) + "\t" + mycolors.reset + valid_from)
                        print(mycolors.foreground.info(cv.bkg) + "  Valid To:".ljust(CERT_COLSIZE) + "\t" + mycolors.reset + valid_to)

        except Exception as e:
            if is_text_output():
                print(mycolors.foreground.error(cv.bkg) + f"\nError: {str(e)}\n" + mycolors.reset)

    def urlscanio_search(self, query):
        self.requestURLSCANIOAPI()

        url = f"{URLScanIOExtractor.urlbase}/search/"
        headers = {
            'API-Key': self.URLSCANIOAPI,
            'Accept': 'application/json'
        }
        params = {'q': query}

        try:
            session = create_session(headers)
            response = session.get(url, params=params, timeout=30)

            if is_text_output():
                print()
                print((mycolors.reset + "URLSCAN.IO SEARCH REPORT".center(100)), end='')
                print((mycolors.reset + "".center(28)), end='')
                print("\n" + (100 * '-').center(50))

            err = self._handle_status(response)
            if err:
                if is_text_output():
                    print(mycolors.foreground.error(cv.bkg) + f"\n{err['error']}\n" + mycolors.reset)
                return

            data = response.json()

            results = data.get('results', [])
            if not results:
                if is_text_output():
                    print(mycolors.foreground.error(cv.bkg) + "\nNo results found for this query.\n" + mycolors.reset)
                return

            if is_text_output():
                self._print_search_header()

            for result in results[:MAX_SEARCH_RESULTS]:
                task = result.get('task', {})
                page = result.get('page', {})

                task_uuid = str(result.get('_id', 'N/A'))
                task_time = str(task.get('time', 'N/A'))[:19]
                page_ip = str(page.get('ip', 'N/A'))
                page_domain = str(page.get('domain', 'N/A'))
                page_country = str(page.get('country', 'N/A'))
                page_status = str(page.get('status', 'N/A'))
                page_asn = str(page.get('asn', 'N/A'))

                verdict_score = str(result.get('verdicts', {}).get('overall', {}).get('score', 0))
                malicious = result.get('verdicts', {}).get('overall', {}).get('malicious', False)

                record = {
                    'uuid': task_uuid,
                    'domain': page_domain,
                    'ip': page_ip,
                    'country': page_country,
                    'status_code': page_status,
                    'asn': page_asn,
                    'verdict_score': verdict_score,
                    'malicious': str(malicious),
                    'scan_time': task_time,
                }
                collector.add(record)

                if is_text_output():
                    self._print_search_row(page_domain, page_ip, page_country, page_status, page_asn, verdict_score, task_time, task_uuid)

            total = data.get('total', len(results))
            if is_text_output():
                print()
                if total > MAX_SEARCH_RESULTS:
                    print(f"Showing {MAX_SEARCH_RESULTS} of {total} total results.")
                else:
                    print(f"{len(results)} result(s) found.")

        except ValueError:
            if is_text_output():
                print(mycolors.foreground.error(cv.bkg) + "\nError parsing JSON response from URLScan.io.\n" + mycolors.reset)
        except Exception as e:
            if is_text_output():
                print(mycolors.foreground.error(cv.bkg) + f"\nError: {str(e)}\n" + mycolors.reset)

    def urlscanio_domain(self, domain):
        self.urlscanio_search(f"domain:{domain}")

    def urlscanio_ip(self, ip):
        self.urlscanio_search(f"page.ip:{ip}")
