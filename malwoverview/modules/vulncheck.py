import malwoverview.modules.configvars as cv
import requests
import json
import textwrap
from malwoverview.utils.colors import mycolors, printr


class VulnCheckExtractor():
    base_url = 'https://api.vulncheck.com/v3'

    def __init__(self, VULNCHECKAPI):
        self.VULNCHECKAPI = VULNCHECKAPI

    @staticmethod
    def sanitize_text(text):
        """Sanitize text for Windows console output by replacing problematic Unicode characters."""
        if not text:
            return text
        replacements = {
            '\u2011': '-',
            '\u2012': '-',
            '\u2013': '-',
            '\u2014': '--',
            '\u2015': '--',
            '\u2018': "'",
            '\u2019': "'",
            '\u201a': "'",
            '\u201b': "'",
            '\u201c': '"',
            '\u201d': '"',
            '\u201e': '"',
            '\u2026': '...',
            '\u2022': '*',
            '\u00a0': ' ',
        }
        for unicode_char, ascii_char in replacements.items():
            text = text.replace(unicode_char, ascii_char)
        
        try:
            text = text.encode('ascii', errors='replace').decode('ascii')
        except:
            pass
        
        return text

    def requestVULNCHECKAPI(self):
        if (self.VULNCHECKAPI == ''):
            print(mycolors.foreground.red + "\nTo be able to get information from VULNCHECK, you must create the .malwapi.conf file under your user home directory (on Linux is $HOME\\.malwapi.conf and on Windows is in C:\\Users\\[username]\\.malwapi.conf) and insert the VULNCHECK API (Token) according to the format shown on the Github website." + mycolors.reset + "\n")
            exit(1)

    def vulncheck_list_indexes(self):
        
        self.requestVULNCHECKAPI()
        
        try:
            print("\n")
            print((mycolors.reset + "VULNCHECK - AVAILABLE INDEXES".center(100)), end='')
            print((mycolors.reset + "".center(28)), end='')
            print("\n" + (100 * '-').center(50))

            requestsession = requests.Session()
            requestsession.headers.update({'Accept': 'application/json'})
            requestsession.headers.update({'Authorization': f'Bearer {self.VULNCHECKAPI}'})

            response = requestsession.get(
                url=f'{self.base_url}/index',
                timeout=30
            )

            if response.status_code == 401:
                print(mycolors.foreground.red + "\nError: Invalid API token (401 Unauthorized).\n")
                return
            elif response.status_code == 402:
                print(mycolors.foreground.red + "\nError: Subscription required to view this data (402 Payment Required).\n")
                return
            elif response.status_code == 429:
                print(mycolors.foreground.red + "\nError: Rate limit exceeded (429 Too Many Requests).\n")
                return
            
            response.raise_for_status()
            data = response.json()

            if data and '_benchmarks' in data:
                benchmarks = data['_benchmarks']
                if cv.bkg == 1:
                    print(mycolors.foreground.lightcyan + f"{('API Response Time:'):<25}" + mycolors.reset + f"{benchmarks.get('response_time', 'N/A')}")
                else:
                    print(mycolors.foreground.cyan + f"{('API Response Time:'):<25}" + mycolors.reset + f"{benchmarks.get('response_time', 'N/A')}")

            if data and 'data' in data:
                indexes = data['data']
                
                if cv.bkg == 1:
                    for idx in indexes:
                        print(mycolors.foreground.yellow + f"\n{'Index Name:':<20}" + mycolors.reset + idx.get('name', 'N/A'))
                        print(mycolors.foreground.lightcyan + f"{'Href:':<20}" + mycolors.reset + idx.get('href', 'N/A'))
                else:
                    for idx in indexes:
                        print(mycolors.foreground.red + f"\n{'Index Name:':<20}" + mycolors.reset + idx.get('name', 'N/A'))
                        print(mycolors.foreground.cyan + f"{'Href:':<20}" + mycolors.reset + idx.get('href', 'N/A'))
            else:
                msg_color = mycolors.foreground.blue if cv.bkg == 0 else mycolors.foreground.yellow
                print(msg_color + "\nNo indexes found.\n")

        except requests.exceptions.Timeout:
            print(mycolors.foreground.red + "\nError: Request timed out.\n")
        except requests.exceptions.ConnectionError as e:
            print(mycolors.foreground.red + f"\nError: Connection error: {str(e)}\n")
        except requests.exceptions.HTTPError as e:
            print(mycolors.foreground.red + f"\nError: HTTP error: {str(e)}\n")
        except json.JSONDecodeError:
            print(mycolors.foreground.red + "\nError: Invalid JSON response.\n")
        except Exception as e:
            print(mycolors.foreground.red + f"\nError: {str(e)}\n")

    def vulncheck_kev(self, max_results=100):
        
        self.requestVULNCHECKAPI()
        
        try:
            print("\n")
            print((mycolors.reset + "VULNCHECK KEV - KNOWN EXPLOITED VULNERABILITIES".center(100)), end='')
            print((mycolors.reset + "".center(28)), end='')
            print("\n" + (100 * '-').center(50))

            requestsession = requests.Session()
            requestsession.headers.update({'Accept': 'application/json'})
            requestsession.headers.update({'Authorization': f'Bearer {self.VULNCHECKAPI}'})

            response = requestsession.get(
                url=f'{self.base_url}/index/vulncheck-kev',
                params={'size': max_results, 'limit': max_results},
                timeout=30
            )

            if response.status_code == 401:
                print(mycolors.foreground.red + "\nError: Invalid API token (401 Unauthorized).\n")
                return
            elif response.status_code == 402:
                print(mycolors.foreground.red + "\nError: Subscription required to view this data (402 Payment Required).\n")
                return
            elif response.status_code == 429:
                print(mycolors.foreground.red + "\nError: Rate limit exceeded (429 Too Many Requests).\n")
                return
            
            response.raise_for_status()
            data = response.json()

            if data and '_benchmarks' in data:
                benchmarks = data['_benchmarks']
                total = data.get('_meta', {}).get('total_documents', 0)
                fetched = data.get('_meta', {}).get('fetched', 0)
                
                if cv.bkg == 1:
                    print(mycolors.foreground.lightcyan + f"\n{'Total KEV Entries:':<25}" + mycolors.reset + str(total))
                    print(mycolors.foreground.lightcyan + f"{'Fetched:':<25}" + mycolors.reset + str(fetched))
                    print(mycolors.foreground.lightcyan + f"{'Response Time:':<25}" + mycolors.reset + f"{benchmarks.get('response_time', 'N/A')}")
                else:
                    print(mycolors.foreground.cyan + f"\n{'Total KEV Entries:':<25}" + mycolors.reset + str(total))
                    print(mycolors.foreground.cyan + f"{'Fetched:':<25}" + mycolors.reset + str(fetched))
                    print(mycolors.foreground.cyan + f"{'Response Time:':<25}" + mycolors.reset + f"{benchmarks.get('response_time', 'N/A')}")

            if data and 'data' in data:
                vulns = data['data']
                
                for idx, vuln in enumerate(vulns, 1):
                    print("\n" + (90 * '-').center(45))
                    
                    if cv.bkg == 1:
                        if 'cve' in vuln:
                            cve_id = vuln['cve'][0] if isinstance(vuln['cve'], list) else str(vuln['cve'])
                            label = f"[{idx}] CVE ID:"
                            print(mycolors.foreground.yellow + f"\n{label:<25}" + mycolors.reset + cve_id)
                        
                        if 'vendorProject' in vuln and vuln['vendorProject']:
                            vendor = str(vuln['vendorProject']) if not isinstance(vuln['vendorProject'], list) else ', '.join(vuln['vendorProject'])
                            wrapped_vendor = textwrap.fill(self.sanitize_text(vendor).strip(), width=90, initial_indent=' ' * 25, subsequent_indent=' ' * 25)
                            print(mycolors.foreground.lightcyan + f"{'Vendor/Project:':<25}" + mycolors.reset + wrapped_vendor[25:])
                        
                        if 'product' in vuln and vuln['product']:
                            product = str(vuln['product']) if not isinstance(vuln['product'], list) else ', '.join(vuln['product'])
                            wrapped_product = textwrap.fill(self.sanitize_text(product).strip(), width=90, initial_indent=' ' * 25, subsequent_indent=' ' * 25)
                            print(mycolors.foreground.lightcyan + f"{'Product:':<25}" + mycolors.reset + wrapped_product[25:])
                        
                        if 'shortDescription' in vuln and vuln['shortDescription']:
                            wrapped_desc = textwrap.fill(self.sanitize_text(vuln['shortDescription']).strip(), width=90, initial_indent=' ' * 25, subsequent_indent=' ' * 25)
                            print(mycolors.foreground.lightcyan + f"{'Description:':<25}" + mycolors.reset + wrapped_desc[25:])
                        
                        if 'vulnerabilityName' in vuln and vuln['vulnerabilityName']:
                            wrapped_vuln = textwrap.fill(self.sanitize_text(str(vuln['vulnerabilityName'])).strip(), width=90, initial_indent=' ' * 25, subsequent_indent=' ' * 25)
                            print(mycolors.foreground.lightcyan + f"{'Vulnerability:':<25}" + mycolors.reset + wrapped_vuln[25:])
                        
                        if 'requiredAction' in vuln and vuln['requiredAction']:
                            wrapped_action = textwrap.fill(self.sanitize_text(str(vuln['requiredAction'])).strip(), width=90, initial_indent=' ' * 25, subsequent_indent=' ' * 25)
                            print(mycolors.foreground.lightcyan + f"{'Required Action:':<25}" + mycolors.reset + wrapped_action[25:])
                        
                        if 'dateAdded' in vuln and vuln['dateAdded']:
                            print(mycolors.foreground.lightcyan + f"{'Date Added:':<25}" + mycolors.reset + str(vuln['dateAdded']))
                        
                        if 'dueDate' in vuln and vuln['dueDate']:
                            print(mycolors.foreground.lightcyan + f"{'Due Date:':<25}" + mycolors.reset + str(vuln['dueDate']))
                        
                        if 'knownRansomware' in vuln:
                            ransomware_status = "Yes" if vuln['knownRansomware'] else "No"
                            color = mycolors.foreground.red if vuln['knownRansomware'] else mycolors.foreground.green
                            print(mycolors.foreground.lightcyan + f"{'Known Ransomware:':<25}" + color + ransomware_status + mycolors.reset)
                        
                        if 'notes' in vuln and vuln['notes']:
                            notes_text = ' '.join(vuln['notes']) if isinstance(vuln['notes'], list) else str(vuln['notes'])
                            wrapped_notes = textwrap.fill(self.sanitize_text(notes_text).strip(), width=90, initial_indent=' ' * 25, subsequent_indent=' ' * 25)
                            print(mycolors.foreground.lightcyan + f"{'Notes:':<25}" + mycolors.reset + wrapped_notes[25:])
                    
                    else:
                        if 'cve' in vuln:
                            cve_id = vuln['cve'][0] if isinstance(vuln['cve'], list) else str(vuln['cve'])
                            label = f"[{idx}] CVE ID:"
                            print(mycolors.foreground.red + f"\n{label:<25}" + mycolors.reset + cve_id)
                        
                        if 'vendorProject' in vuln and vuln['vendorProject']:
                            vendor = str(vuln['vendorProject']) if not isinstance(vuln['vendorProject'], list) else ', '.join(vuln['vendorProject'])
                            wrapped_vendor = textwrap.fill(self.sanitize_text(vendor).strip(), width=90, initial_indent=' ' * 25, subsequent_indent=' ' * 25)
                            print(mycolors.foreground.cyan + f"{'Vendor/Project:':<25}" + mycolors.reset + wrapped_vendor[25:])
                        
                        if 'product' in vuln and vuln['product']:
                            product = str(vuln['product']) if not isinstance(vuln['product'], list) else ', '.join(vuln['product'])
                            wrapped_product = textwrap.fill(self.sanitize_text(product).strip(), width=90, initial_indent=' ' * 25, subsequent_indent=' ' * 25)
                            print(mycolors.foreground.cyan + f"{'Product:':<25}" + mycolors.reset + wrapped_product[25:])
                        
                        if 'shortDescription' in vuln and vuln['shortDescription']:
                            wrapped_desc = textwrap.fill(self.sanitize_text(vuln['shortDescription']).strip(), width=90, initial_indent=' ' * 25, subsequent_indent=' ' * 25)
                            print(mycolors.foreground.cyan + f"{'Description:':<25}" + mycolors.reset + wrapped_desc[25:])
                        
                        if 'vulnerabilityName' in vuln and vuln['vulnerabilityName']:
                            wrapped_vuln = textwrap.fill(self.sanitize_text(str(vuln['vulnerabilityName'])).strip(), width=90, initial_indent=' ' * 25, subsequent_indent=' ' * 25)
                            print(mycolors.foreground.cyan + f"{'Vulnerability:':<25}" + mycolors.reset + wrapped_vuln[25:])
                        
                        if 'requiredAction' in vuln and vuln['requiredAction']:
                            wrapped_action = textwrap.fill(self.sanitize_text(str(vuln['requiredAction'])).strip(), width=90, initial_indent=' ' * 25, subsequent_indent=' ' * 25)
                            print(mycolors.foreground.cyan + f"{'Required Action:':<25}" + mycolors.reset + wrapped_action[25:])
                        
                        if 'dateAdded' in vuln and vuln['dateAdded']:
                            print(mycolors.foreground.cyan + f"{'Date Added:':<25}" + mycolors.reset + str(vuln['dateAdded']))
                        
                        if 'dueDate' in vuln and vuln['dueDate']:
                            print(mycolors.foreground.cyan + f"{'Due Date:':<25}" + mycolors.reset + str(vuln['dueDate']))
                        
                        if 'knownRansomware' in vuln:
                            ransomware_status = "Yes" if vuln['knownRansomware'] else "No"
                            color = mycolors.foreground.red if vuln['knownRansomware'] else mycolors.foreground.green
                            print(mycolors.foreground.cyan + f"{'Known Ransomware:':<25}" + color + ransomware_status + mycolors.reset)
                        
                        if 'notes' in vuln and vuln['notes']:
                            notes_text = ' '.join(vuln['notes']) if isinstance(vuln['notes'], list) else str(vuln['notes'])
                            wrapped_notes = textwrap.fill(self.sanitize_text(notes_text).strip(), width=90, initial_indent=' ' * 25, subsequent_indent=' ' * 25)
                            print(mycolors.foreground.cyan + f"{'Notes:':<25}" + mycolors.reset + wrapped_notes[25:])
            else:
                msg_color = mycolors.foreground.blue if cv.bkg == 0 else mycolors.foreground.yellow
                print(msg_color + "\nNo vulnerabilities found.\n")

        except requests.exceptions.Timeout:
            print(mycolors.foreground.red + "\nError: Request timed out.\n")
        except requests.exceptions.ConnectionError as e:
            print(mycolors.foreground.red + f"\nError: Connection error: {str(e)}\n")
        except requests.exceptions.HTTPError as e:
            print(mycolors.foreground.red + f"\nError: HTTP error: {str(e)}\n")
        except json.JSONDecodeError:
            print(mycolors.foreground.red + "\nError: Invalid JSON response.\n")
        except Exception as e:
            print(mycolors.foreground.red + f"\nError: {str(e)}\n")

    def vulncheck_cve_search(self, cve_id):
        
        self.requestVULNCHECKAPI()
        
        if not cve_id:
            print(mycolors.foreground.red + "\nError: CVE ID is required for this search. Use -VC or --VULNCHECK to specify a CVE ID." + mycolors.reset)
            ex_color = mycolors.foreground.blue if cv.bkg == 0 else mycolors.foreground.yellow
            print(ex_color + "Example: python malwoverview.py -vc 3 -VC CVE-2025-6543 -o 0\n" + mycolors.reset)
            return
        
        try:
            print("\n")
            print((mycolors.reset + f"VULNCHECK - CVE SEARCH: {cve_id}".center(100)), end='')
            print((mycolors.reset + "".center(28)), end='')
            print("\n" + (100 * '-').center(50))

            requestsession = requests.Session()
            requestsession.headers.update({'Accept': 'application/json'})
            requestsession.headers.update({'Authorization': f'Bearer {self.VULNCHECKAPI}'})

            response = requestsession.get(
                url=f'{self.base_url}/index/vulncheck-kev',
                params={'cve': cve_id},
                timeout=30
            )

            if response.status_code == 401:
                print(mycolors.foreground.red + "\nError: Invalid API token (401 Unauthorized).\n")
                return
            elif response.status_code == 402:
                print(mycolors.foreground.red + "\nError: Subscription required to view this data (402 Payment Required).\n")
                return
            elif response.status_code == 429:
                print(mycolors.foreground.red + "\nError: Rate limit exceeded (429 Too Many Requests).\n")
                return
            
            response.raise_for_status()
            data = response.json()

            if data and 'data' in data and len(data['data']) > 0:
                vuln = data['data'][0]
                
                if cv.bkg == 1:
                    if 'cve' in vuln:
                        cve_result = vuln['cve'][0] if isinstance(vuln['cve'], list) else str(vuln['cve'])
                        print(mycolors.foreground.yellow + f"\n{'CVE ID:':<25}" + mycolors.reset + cve_result)
                    
                    if 'vendorProject' in vuln and vuln['vendorProject']:
                        vendor = str(vuln['vendorProject']) if not isinstance(vuln['vendorProject'], list) else ', '.join(vuln['vendorProject'])
                        wrapped_vendor = textwrap.fill(self.sanitize_text(vendor).strip(), width=90, initial_indent=' ' * 25, subsequent_indent=' ' * 25)
                        print(mycolors.foreground.lightcyan + f"{'Vendor/Project:':<25}" + mycolors.reset + wrapped_vendor[25:])
                    
                    if 'product' in vuln and vuln['product']:
                        product = str(vuln['product']) if not isinstance(vuln['product'], list) else ', '.join(vuln['product'])
                        wrapped_product = textwrap.fill(self.sanitize_text(product).strip(), width=90, initial_indent=' ' * 25, subsequent_indent=' ' * 25)
                        print(mycolors.foreground.lightcyan + f"{'Product:':<25}" + mycolors.reset + wrapped_product[25:])
                    
                    if 'shortDescription' in vuln and vuln['shortDescription']:
                        wrapped_desc = textwrap.fill(self.sanitize_text(vuln['shortDescription']).strip(), width=90, initial_indent=' ' * 25, subsequent_indent=' ' * 25)
                        print(mycolors.foreground.lightcyan + f"{'Description:':<25}" + mycolors.reset + wrapped_desc[25:])
                    
                    if 'vulnerabilityName' in vuln and vuln['vulnerabilityName']:
                        wrapped_vuln = textwrap.fill(self.sanitize_text(str(vuln['vulnerabilityName'])).strip(), width=90, initial_indent=' ' * 25, subsequent_indent=' ' * 25)
                        print(mycolors.foreground.lightcyan + f"{'Vulnerability:':<25}" + mycolors.reset + wrapped_vuln[25:])
                    
                    if 'requiredAction' in vuln and vuln['requiredAction']:
                        wrapped_action = textwrap.fill(self.sanitize_text(str(vuln['requiredAction'])).strip(), width=90, initial_indent=' ' * 25, subsequent_indent=' ' * 25)
                        print(mycolors.foreground.lightcyan + f"{'Required Action:':<25}" + mycolors.reset + wrapped_action[25:])
                    
                    if 'dateAdded' in vuln and vuln['dateAdded']:
                        print(mycolors.foreground.lightcyan + f"{'Date Added:':<25}" + mycolors.reset + str(vuln['dateAdded']))
                    
                    if 'dueDate' in vuln and vuln['dueDate']:
                        print(mycolors.foreground.lightcyan + f"{'Due Date:':<25}" + mycolors.reset + str(vuln['dueDate']))
                    
                    if 'knownRansomware' in vuln:
                        ransomware_status = "Yes" if vuln['knownRansomware'] else "No"
                        color = mycolors.foreground.red if vuln['knownRansomware'] else mycolors.foreground.green
                        print(mycolors.foreground.lightcyan + f"{'Known Ransomware:':<25}" + color + ransomware_status + mycolors.reset)
                    
                    if 'notes' in vuln and vuln['notes']:
                        notes_text = ' '.join(vuln['notes']) if isinstance(vuln['notes'], list) else str(vuln['notes'])
                        wrapped_notes = textwrap.fill(self.sanitize_text(notes_text).strip(), width=90, initial_indent=' ' * 25, subsequent_indent=' ' * 25)
                        print(mycolors.foreground.lightcyan + f"{'Notes:':<25}" + mycolors.reset + wrapped_notes[25:])
                
                else:
                    if 'cve' in vuln:
                        cve_result = vuln['cve'][0] if isinstance(vuln['cve'], list) else str(vuln['cve'])
                        print(mycolors.foreground.red + f"\n{'CVE ID:':<25}" + mycolors.reset + cve_result)
                    
                    if 'vendorProject' in vuln and vuln['vendorProject']:
                        vendor = str(vuln['vendorProject']) if not isinstance(vuln['vendorProject'], list) else ', '.join(vuln['vendorProject'])
                        wrapped_vendor = textwrap.fill(self.sanitize_text(vendor).strip(), width=90, initial_indent=' ' * 25, subsequent_indent=' ' * 25)
                        print(mycolors.foreground.cyan + f"{'Vendor/Project:':<25}" + mycolors.reset + wrapped_vendor[25:])
                    
                    if 'product' in vuln and vuln['product']:
                        product = str(vuln['product']) if not isinstance(vuln['product'], list) else ', '.join(vuln['product'])
                        wrapped_product = textwrap.fill(self.sanitize_text(product).strip(), width=90, initial_indent=' ' * 25, subsequent_indent=' ' * 25)
                        print(mycolors.foreground.cyan + f"{'Product:':<25}" + mycolors.reset + wrapped_product[25:])
                    
                    if 'shortDescription' in vuln and vuln['shortDescription']:
                        wrapped_desc = textwrap.fill(self.sanitize_text(vuln['shortDescription']).strip(), width=90, initial_indent=' ' * 25, subsequent_indent=' ' * 25)
                        print(mycolors.foreground.cyan + f"{'Description:':<25}" + mycolors.reset + wrapped_desc[25:])
                    
                    if 'vulnerabilityName' in vuln and vuln['vulnerabilityName']:
                        wrapped_vuln = textwrap.fill(self.sanitize_text(str(vuln['vulnerabilityName'])).strip(), width=90, initial_indent=' ' * 25, subsequent_indent=' ' * 25)
                        print(mycolors.foreground.cyan + f"{'Vulnerability:':<25}" + mycolors.reset + wrapped_vuln[25:])
                    
                    if 'requiredAction' in vuln and vuln['requiredAction']:
                        wrapped_action = textwrap.fill(self.sanitize_text(str(vuln['requiredAction'])).strip(), width=90, initial_indent=' ' * 25, subsequent_indent=' ' * 25)
                        print(mycolors.foreground.cyan + f"{'Required Action:':<25}" + mycolors.reset + wrapped_action[25:])
                    
                    if 'dateAdded' in vuln and vuln['dateAdded']:
                        print(mycolors.foreground.cyan + f"{'Date Added:':<25}" + mycolors.reset + str(vuln['dateAdded']))
                    
                    if 'dueDate' in vuln and vuln['dueDate']:
                        print(mycolors.foreground.cyan + f"{'Due Date:':<25}" + mycolors.reset + str(vuln['dueDate']))
                    
                    if 'knownRansomware' in vuln:
                        ransomware_status = "Yes" if vuln['knownRansomware'] else "No"
                        color = mycolors.foreground.red if vuln['knownRansomware'] else mycolors.foreground.green
                        print(mycolors.foreground.cyan + f"{'Known Ransomware:':<25}" + color + ransomware_status + mycolors.reset)
                    
                    if 'notes' in vuln and vuln['notes']:
                        notes_text = ' '.join(vuln['notes']) if isinstance(vuln['notes'], list) else str(vuln['notes'])
                        wrapped_notes = textwrap.fill(self.sanitize_text(notes_text).strip(), width=90, initial_indent=' ' * 25, subsequent_indent=' ' * 25)
                        print(mycolors.foreground.cyan + f"{'Notes:':<25}" + mycolors.reset + wrapped_notes[25:])
            else:
                print(mycolors.foreground.yellow + f"\nCVE {cve_id} not found in VulnCheck KEV database.\n")

        except requests.exceptions.Timeout:
            print(mycolors.foreground.red + "\nError: Request timed out.\n")
        except requests.exceptions.ConnectionError as e:
            print(mycolors.foreground.red + f"\nError: Connection error: {str(e)}\n")
        except requests.exceptions.HTTPError as e:
            print(mycolors.foreground.red + f"\nError: HTTP error: {str(e)}\n")
        except json.JSONDecodeError:
            print(mycolors.foreground.red + "\nError: Invalid JSON response.\n")
        except Exception as e:
            print(mycolors.foreground.red + f"\nError: {str(e)}\n")

    def vulncheck_backup_kev(self):
        
        self.requestVULNCHECKAPI()
        
        try:
            print("\n")
            print((mycolors.reset + "VULNCHECK - KEV BACKUP DOWNLOAD".center(100)), end='')
            print((mycolors.reset + "".center(28)), end='')
            print("\n" + (100 * '-').center(50))

            requestsession = requests.Session()
            requestsession.headers.update({'Accept': 'application/json'})
            requestsession.headers.update({'Authorization': f'Bearer {self.VULNCHECKAPI}'})

            response = requestsession.get(
                url=f'{self.base_url}/backup/vulncheck-kev',
                timeout=30
            )

            if response.status_code == 401:
                print(mycolors.foreground.red + "\nError: Invalid API token (401 Unauthorized).\n")
                return
            elif response.status_code == 402:
                print(mycolors.foreground.red + "\nError: Subscription required to view this data (402 Payment Required).\n")
                return
            elif response.status_code == 429:
                print(mycolors.foreground.red + "\nError: Rate limit exceeded (429 Too Many Requests).\n")
                return
            
            response.raise_for_status()
            data = response.json()

            backup_url = None
            
            if isinstance(data, dict):
                if 'url' in data:
                    backup_url = data['url']
                elif 'data' in data and isinstance(data['data'], dict):
                    if 'url' in data['data']:
                        backup_url = data['data']['url']
                elif 'data' in data and isinstance(data['data'], list) and len(data['data']) > 0:
                    if isinstance(data['data'][0], dict) and 'url' in data['data'][0]:
                        backup_url = data['data'][0]['url']
                elif 'download_url' in data:
                    backup_url = data['download_url']
                elif 'data' in data and isinstance(data['data'], dict) and 'download_url' in data['data']:
                    backup_url = data['data']['download_url']
            
            if backup_url:
                if cv.bkg == 1:
                    print(mycolors.foreground.yellow + f"\n{'Backup Download URL:':<25}" + mycolors.reset + backup_url)
                    
                    metadata = data.get('data', data)
                    if isinstance(metadata, list) and len(metadata) > 0:
                        metadata = metadata[0]
                    if isinstance(metadata, dict):
                        if 'date_added' in metadata:
                            print(mycolors.foreground.lightcyan + f"{'Date Added:':<25}" + mycolors.reset + str(metadata['date_added']))
                        if 'date_modified' in metadata or 'modified' in metadata:
                            mod_date = metadata.get('date_modified', metadata.get('modified'))
                            print(mycolors.foreground.lightcyan + f"{'Last Modified:':<25}" + mycolors.reset + str(mod_date))
                        if 'size' in metadata:
                            print(mycolors.foreground.lightcyan + f"{'Size:':<25}" + mycolors.reset + str(metadata['size']) + " bytes")
                        if 'sha256' in metadata or 'checksum' in metadata:
                            checksum = metadata.get('sha256', metadata.get('checksum'))
                            print(mycolors.foreground.lightcyan + f"{'SHA256:':<25}" + mycolors.reset + str(checksum))
                        if 'filename' in metadata:
                            print(mycolors.foreground.lightcyan + f"{'Filename:':<25}" + mycolors.reset + str(metadata['filename']))
                        if 'url_expires' in metadata:
                            print(mycolors.foreground.lightcyan + f"{'URL Expires:':<25}" + mycolors.reset + str(metadata['url_expires']))
                else:
                    print(mycolors.foreground.red + f"\n{'Backup Download URL:':<25}" + mycolors.reset + backup_url)
                    
                    metadata = data.get('data', data)
                    if isinstance(metadata, list) and len(metadata) > 0:
                        metadata = metadata[0]
                    if isinstance(metadata, dict):
                        if 'date_added' in metadata:
                            print(mycolors.foreground.cyan + f"{'Date Added:':<25}" + mycolors.reset + str(metadata['date_added']))
                        if 'date_modified' in metadata or 'modified' in metadata:
                            mod_date = metadata.get('date_modified', metadata.get('modified'))
                            print(mycolors.foreground.cyan + f"{'Last Modified:':<25}" + mycolors.reset + str(mod_date))
                        if 'size' in metadata:
                            print(mycolors.foreground.cyan + f"{'Size:':<25}" + mycolors.reset + str(metadata['size']) + " bytes")
                        if 'sha256' in metadata or 'checksum' in metadata:
                            checksum = metadata.get('sha256', metadata.get('checksum'))
                            print(mycolors.foreground.cyan + f"{'SHA256:':<25}" + mycolors.reset + str(checksum))
                        if 'filename' in metadata:
                            print(mycolors.foreground.cyan + f"{'Filename:':<25}" + mycolors.reset + str(metadata['filename']))
                        if 'url_expires' in metadata:
                            print(mycolors.foreground.cyan + f"{'URL Expires:':<25}" + mycolors.reset + str(metadata['url_expires']))
                
                print("\n" + mycolors.foreground.green + "Note: Download this URL to get the complete KEV dataset as a JSON file." + mycolors.reset)
            else:
                print(mycolors.foreground.yellow + f"\n{'Response structure:':<25}" + mycolors.reset + str(type(data)))
                if isinstance(data, dict):
                    print(mycolors.foreground.yellow + f"{'Top-level keys:':<25}" + mycolors.reset + str(list(data.keys())))
                    if 'data' in data:
                        print(mycolors.foreground.yellow + f"{'data type:':<25}" + mycolors.reset + str(type(data['data'])))
                        if isinstance(data['data'], dict):
                            print(mycolors.foreground.yellow + f"{'data keys:':<25}" + mycolors.reset + str(list(data['data'].keys())[:10]))
                        elif isinstance(data['data'], list) and len(data['data']) > 0:
                            print(mycolors.foreground.yellow + f"{'data is list, length:':<25}" + mycolors.reset + str(len(data['data'])))
                            print(mycolors.foreground.yellow + f"{'first item keys:':<25}" + mycolors.reset + str(list(data['data'][0].keys()) if isinstance(data['data'][0], dict) else 'not a dict'))
                print(mycolors.foreground.red + "\nUnable to find backup download URL in API response.\n")

        except requests.exceptions.Timeout:
            print(mycolors.foreground.red + "\nError: Request timed out.\n")
        except requests.exceptions.ConnectionError as e:
            print(mycolors.foreground.red + f"\nError: Connection error: {str(e)}\n")
        except requests.exceptions.HTTPError as e:
            print(mycolors.foreground.red + f"\nError: HTTP error: {str(e)}\n")
        except json.JSONDecodeError:
            print(mycolors.foreground.red + "\nError: Invalid JSON response.\n")
        except Exception as e:
            print(mycolors.foreground.red + f"\nError: {str(e)}\n")

    def vulncheck_mitre_list(self, max_results=100):
        
        self.requestVULNCHECKAPI()
        
        try:
            print("\n")
            print((mycolors.reset + "VULNCHECK - MITRE CVE LIST".center(100)), end='')
            print((mycolors.reset + "".center(28)), end='')
            print("\n" + (100 * '-').center(50))

            requestsession = requests.Session()
            requestsession.headers.update({'Accept': 'application/json'})
            requestsession.headers.update({'Authorization': f'Bearer {self.VULNCHECKAPI}'})

            response = requestsession.get(
                url=f'{self.base_url}/index/mitre-cvelist-v5',
                params={'size': max_results, 'limit': max_results, 'sort': 'date_added', 'order': 'desc'},
                timeout=30
            )

            if response.status_code == 401:
                print(mycolors.foreground.red + "\nError: Invalid API token (401 Unauthorized).\n")
                return
            elif response.status_code == 402:
                print(mycolors.foreground.red + "\nError: Subscription required to view this data (402 Payment Required).\n")
                return
            elif response.status_code == 429:
                print(mycolors.foreground.red + "\nError: Rate limit exceeded (429 Too Many Requests).\n")
                return
            
            response.raise_for_status()
            data = response.json()

            if data and '_meta' in data:
                total = data.get('_meta', {}).get('total_documents', 0)
                fetched = len(data.get('data', []))
                
                if cv.bkg == 1:
                    print(mycolors.foreground.lightcyan + f"\n{'Total CVE Entries:':<25}" + mycolors.reset + str(total))
                    print(mycolors.foreground.lightcyan + f"{'Fetched:':<25}" + mycolors.reset + str(fetched))
                else:
                    print(mycolors.foreground.cyan + f"\n{'Total CVE Entries:':<25}" + mycolors.reset + str(total))
                    print(mycolors.foreground.cyan + f"{'Fetched:':<25}" + mycolors.reset + str(fetched))

            if data and 'data' in data:
                cves = data['data']
                
                for idx, cve_entry in enumerate(cves, 1):
                    print("\n" + (90 * '-').center(45))
                    
                    if cv.bkg == 1:
                        if 'cve' in cve_entry:
                            cve_list = cve_entry['cve']
                            cve_id = ', '.join(cve_list) if isinstance(cve_list, list) else str(cve_list)
                            label = f"[{idx}] CVE ID:"
                            print(mycolors.foreground.yellow + f"\n{label:<25}" + mycolors.reset + cve_id)
                        
                        if 'title' in cve_entry and cve_entry['title']:
                            wrapped_title = textwrap.fill(self.sanitize_text(str(cve_entry['title'])).strip(), width=90, initial_indent=' ' * 25, subsequent_indent=' ' * 25)
                            print(mycolors.foreground.lightcyan + f"{'Title:':<25}" + mycolors.reset + wrapped_title[25:])
                        
                        if 'summary' in cve_entry and cve_entry['summary']:
                            wrapped_summary = textwrap.fill(self.sanitize_text(str(cve_entry['summary'])).strip(), width=90, initial_indent=' ' * 25, subsequent_indent=' ' * 25)
                            print(mycolors.foreground.lightcyan + f"{'Summary:':<25}" + mycolors.reset + wrapped_summary[25:])
                        
                        if 'date_added' in cve_entry and cve_entry['date_added']:
                            print(mycolors.foreground.lightcyan + f"{'Date Added:':<25}" + mycolors.reset + str(cve_entry['date_added']))
                        
                        if 'updated_at' in cve_entry and cve_entry['updated_at']:
                            print(mycolors.foreground.lightcyan + f"{'Last Updated:':<25}" + mycolors.reset + str(cve_entry['updated_at']))
                    
                    else:
                        if 'cve' in cve_entry:
                            cve_list = cve_entry['cve']
                            cve_id = ', '.join(cve_list) if isinstance(cve_list, list) else str(cve_list)
                            label = f"[{idx}] CVE ID:"
                            print(mycolors.foreground.red + f"\n{label:<25}" + mycolors.reset + cve_id)
                        
                        if 'title' in cve_entry and cve_entry['title']:
                            wrapped_title = textwrap.fill(self.sanitize_text(str(cve_entry['title'])).strip(), width=90, initial_indent=' ' * 25, subsequent_indent=' ' * 25)
                            print(mycolors.foreground.cyan + f"{'Title:':<25}" + mycolors.reset + wrapped_title[25:])
                        
                        if 'summary' in cve_entry and cve_entry['summary']:
                            wrapped_summary = textwrap.fill(self.sanitize_text(str(cve_entry['summary'])).strip(), width=90, initial_indent=' ' * 25, subsequent_indent=' ' * 25)
                            print(mycolors.foreground.cyan + f"{'Summary:':<25}" + mycolors.reset + wrapped_summary[25:])
                        
                        if 'date_added' in cve_entry and cve_entry['date_added']:
                            print(mycolors.foreground.cyan + f"{'Date Added:':<25}" + mycolors.reset + str(cve_entry['date_added']))
                        
                        if 'updated_at' in cve_entry and cve_entry['updated_at']:
                            print(mycolors.foreground.cyan + f"{'Last Updated:':<25}" + mycolors.reset + str(cve_entry['updated_at']))
            else:
                print(mycolors.foreground.yellow + "\nNo CVEs found.\n")

        except requests.exceptions.Timeout:
            print(mycolors.foreground.red + "\nError: Request timed out.\n")
        except requests.exceptions.ConnectionError as e:
            print(mycolors.foreground.red + f"\nError: Connection error: {str(e)}\n")
        except requests.exceptions.HTTPError as e:
            print(mycolors.foreground.red + f"\nError: HTTP error: {str(e)}\n")
        except json.JSONDecodeError:
            print(mycolors.foreground.red + "\nError: Invalid JSON response.\n")
        except Exception as e:
            print(mycolors.foreground.red + f"\nError: {str(e)}\n")

    def vulncheck_nist_list(self, max_results=100):
        
        self.requestVULNCHECKAPI()
        
        try:
            print("\n")
            print((mycolors.reset + "VULNCHECK - NIST NVD2 LIST".center(100)), end='')
            print((mycolors.reset + "".center(28)), end='')
            print("\n" + (100 * '-').center(50))

            requestsession = requests.Session()
            requestsession.headers.update({'Accept': 'application/json'})
            requestsession.headers.update({'Authorization': f'Bearer {self.VULNCHECKAPI}'})

            response = requestsession.get(
                url=f'{self.base_url}/index/nist-nvd2',
                params={'size': max_results, 'limit': max_results},
                timeout=30
            )

            if response.status_code == 401:
                print(mycolors.foreground.red + "\nError: Invalid API token (401 Unauthorized).\n")
                return
            elif response.status_code == 402:
                print(mycolors.foreground.red + "\nError: Subscription required to view this data (402 Payment Required).\n")
                return
            elif response.status_code == 429:
                print(mycolors.foreground.red + "\nError: Rate limit exceeded (429 Too Many Requests).\n")
                return
            
            response.raise_for_status()
            data = response.json()

            if data and '_meta' in data:
                total = data.get('_meta', {}).get('total_documents', 0)
                fetched = len(data.get('data', []))
                
                if cv.bkg == 1:
                    print(mycolors.foreground.lightcyan + f"\n{'Total CVE Entries:':<25}" + mycolors.reset + str(total))
                    print(mycolors.foreground.lightcyan + f"{'Fetched:':<25}" + mycolors.reset + str(fetched))
                else:
                    print(mycolors.foreground.cyan + f"\n{'Total CVE Entries:':<25}" + mycolors.reset + str(total))
                    print(mycolors.foreground.cyan + f"{'Fetched:':<25}" + mycolors.reset + str(fetched))

            if data and 'data' in data:
                cves = data['data']
                
                for idx, vuln in enumerate(cves, 1):
                    print("\n" + (90 * '-').center(45))
                    
                    if cv.bkg == 1:
                        if 'id' in vuln:
                            label = f"[{idx}] CVE ID:"
                            print(mycolors.foreground.yellow + f"\n{label:<25}" + mycolors.reset + str(vuln['id']))
                        
                        if 'vulnStatus' in vuln and vuln['vulnStatus']:
                            print(mycolors.foreground.lightcyan + f"{'Status:':<25}" + mycolors.reset + str(vuln['vulnStatus']))
                        
                        if 'published' in vuln and vuln['published']:
                            print(mycolors.foreground.lightcyan + f"{'Published:':<25}" + mycolors.reset + str(vuln['published']))
                        
                        if 'descriptions' in vuln and vuln['descriptions']:
                            desc_items = vuln['descriptions']
                            if isinstance(desc_items, list) and len(desc_items) > 0:
                                desc = desc_items[0]
                                if isinstance(desc, dict) and 'value' in desc:
                                    wrapped_desc = textwrap.fill(self.sanitize_text(desc['value']).strip(), width=90, initial_indent=' ' * 25, subsequent_indent=' ' * 25)
                                    print(mycolors.foreground.lightcyan + f"{'Description:':<25}" + mycolors.reset + wrapped_desc[25:])
                        
                        if 'metrics' in vuln and vuln['metrics']:
                            metrics = vuln['metrics']
                            if isinstance(metrics, dict) and 'cvssMetricV31' in metrics:
                                cvss_list = metrics['cvssMetricV31']
                                if isinstance(cvss_list, list) and len(cvss_list) > 0:
                                    cvss = cvss_list[0]
                                    if isinstance(cvss, dict) and 'cvssData' in cvss:
                                        cvss_data = cvss['cvssData']
                                        if isinstance(cvss_data, dict) and 'baseScore' in cvss_data:
                                            score = cvss_data['baseScore']
                                            severity = cvss_data.get('baseSeverity', 'N/A')
                                            score_color = mycolors.foreground.red if float(score) >= 7.0 else mycolors.foreground.yellow if float(score) >= 4.0 else mycolors.foreground.lightgreen
                                            print(mycolors.foreground.lightcyan + f"{'CVSS v3.1:':<25}" + score_color + f"{score} ({severity})" + mycolors.reset)
                        
                        if 'cisaExploitAdd' in vuln and vuln['cisaExploitAdd']:
                            print(mycolors.foreground.red + f"{'CISA KEV:':<25}" + mycolors.reset + "Yes (actively exploited)")
                    
                    else:
                        if 'id' in vuln:
                            label = f"[{idx}] CVE ID:"
                            print(mycolors.foreground.red + f"\n{label:<25}" + mycolors.reset + str(vuln['id']))
                        
                        if 'vulnStatus' in vuln and vuln['vulnStatus']:
                            print(mycolors.foreground.cyan + f"{'Status:':<25}" + mycolors.reset + str(vuln['vulnStatus']))
                        
                        if 'published' in vuln and vuln['published']:
                            print(mycolors.foreground.cyan + f"{'Published:':<25}" + mycolors.reset + str(vuln['published']))
                        
                        if 'descriptions' in vuln and vuln['descriptions']:
                            desc_items = vuln['descriptions']
                            if isinstance(desc_items, list) and len(desc_items) > 0:
                                desc = desc_items[0]
                                if isinstance(desc, dict) and 'value' in desc:
                                    wrapped_desc = textwrap.fill(self.sanitize_text(desc['value']).strip(), width=90, initial_indent=' ' * 25, subsequent_indent=' ' * 25)
                                    print(mycolors.foreground.cyan + f"{'Description:':<25}" + mycolors.reset + wrapped_desc[25:])
                        
                        if 'metrics' in vuln and vuln['metrics']:
                            metrics = vuln['metrics']
                            if isinstance(metrics, dict) and 'cvssMetricV31' in metrics:
                                cvss_list = metrics['cvssMetricV31']
                                if isinstance(cvss_list, list) and len(cvss_list) > 0:
                                    cvss = cvss_list[0]
                                    if isinstance(cvss, dict) and 'cvssData' in cvss:
                                        cvss_data = cvss['cvssData']
                                        if isinstance(cvss_data, dict) and 'baseScore' in cvss_data:
                                            score = cvss_data['baseScore']
                                            severity = cvss_data.get('baseSeverity', 'N/A')
                                            score_color = mycolors.foreground.red if float(score) >= 7.0 else mycolors.foreground.blue if float(score) >= 4.0 else mycolors.foreground.purple
                                            print(mycolors.foreground.cyan + f"{'CVSS v3.1:':<25}" + score_color + f"{score} ({severity})" + mycolors.reset)
                        
                        if 'cisaExploitAdd' in vuln and vuln['cisaExploitAdd']:
                            print(mycolors.foreground.red + f"{'CISA KEV:':<25}" + mycolors.reset + "Yes (actively exploited)")
            else:
                msg_color = mycolors.foreground.blue if cv.bkg == 0 else mycolors.foreground.yellow
                print(msg_color + "\nNo CVEs found.\n")

        except requests.exceptions.Timeout:
            print(mycolors.foreground.red + "\nError: Request timed out.\n")
        except requests.exceptions.ConnectionError as e:
            print(mycolors.foreground.red + f"\nError: Connection error: {str(e)}\n")
        except requests.exceptions.HTTPError as e:
            print(mycolors.foreground.red + f"\nError: HTTP error: {str(e)}\n")
        except json.JSONDecodeError:
            print(mycolors.foreground.red + "\nError: Invalid JSON response.\n")
        except Exception as e:
            print(mycolors.foreground.red + f"\nError: {str(e)}\n")

    def vulncheck_mitre_search(self, cve_id):
        
        self.requestVULNCHECKAPI()
        
        if not cve_id:
            print(mycolors.foreground.red + "\nError: CVE ID is required for this search. Use -VC or --VULNCHECK to specify a CVE ID." + mycolors.reset)
            ex_color = mycolors.foreground.blue if cv.bkg == 0 else mycolors.foreground.yellow
            print(ex_color + "Example: python malwoverview.py -vc 7 -VC CVE-2024-21412 -o 0\n" + mycolors.reset)
            return
        
        try:
            print("\n")
            print((mycolors.reset + f"VULNCHECK - MITRE CVE SEARCH: {cve_id}".center(100)), end='')
            print((mycolors.reset + "".center(28)), end='')
            print("\n" + (100 * '-').center(50))

            requestsession = requests.Session()
            requestsession.headers.update({'Accept': 'application/json'})
            requestsession.headers.update({'Authorization': f'Bearer {self.VULNCHECKAPI}'})

            response = requestsession.get(
                url=f'{self.base_url}/index/mitre-cvelist-v5',
                params={'cve': cve_id},
                timeout=30
            )

            if response.status_code == 401:
                print(mycolors.foreground.red + "\nError: Invalid API token (401 Unauthorized).\n")
                return
            elif response.status_code == 402:
                print(mycolors.foreground.red + "\nError: Subscription required to view this data (402 Payment Required).\n")
                return
            elif response.status_code == 429:
                print(mycolors.foreground.red + "\nError: Rate limit exceeded (429 Too Many Requests).\n")
                return
            
            response.raise_for_status()
            data = response.json()

            if data and 'data' in data and len(data['data']) > 0:
                vuln = data['data'][0]
                
                if cv.bkg == 1:
                    if 'cve' in vuln:
                        cve_list = vuln['cve']
                        cve_result = ', '.join(cve_list) if isinstance(cve_list, list) else str(cve_list)
                        print(mycolors.foreground.yellow + f"\n{'CVE ID:':<25}" + mycolors.reset + cve_result)
                    
                    if 'title' in vuln and vuln['title']:
                        wrapped_title = textwrap.fill(self.sanitize_text(str(vuln['title'])).strip(), width=90, initial_indent=' ' * 25, subsequent_indent=' ' * 25)
                        print(mycolors.foreground.lightcyan + f"{'Title:':<25}" + mycolors.reset + wrapped_title[25:])
                    
                    if 'summary' in vuln and vuln['summary']:
                        wrapped_summary = textwrap.fill(self.sanitize_text(str(vuln['summary'])).strip(), width=90, initial_indent=' ' * 25, subsequent_indent=' ' * 25)
                        print(mycolors.foreground.lightcyan + f"{'Summary:':<25}" + mycolors.reset + wrapped_summary[25:])
                    
                    if 'url' in vuln and vuln['url']:
                        print(mycolors.foreground.lightcyan + f"{'URL:':<25}" + mycolors.reset + str(vuln['url']))
                    
                    if 'date_added' in vuln and vuln['date_added']:
                        print(mycolors.foreground.lightcyan + f"{'Date Added:':<25}" + mycolors.reset + str(vuln['date_added']))
                    
                    if 'updated_at' in vuln and vuln['updated_at']:
                        print(mycolors.foreground.lightcyan + f"{'Last Updated:':<25}" + mycolors.reset + str(vuln['updated_at']))
                    
                    if 'references' in vuln and vuln['references']:
                        refs = vuln['references']
                        if isinstance(refs, list) and len(refs) > 0:
                            print(mycolors.foreground.lightcyan + f"{'References:':<25}" + mycolors.reset)
                            for ref in refs[:5]:
                                wrapped_ref = textwrap.fill(str(ref), width=90, initial_indent=' ' * 25, subsequent_indent=' ' * 25)
                                print(mycolors.foreground.lightcyan + f"{'  -':<25}" + mycolors.reset + wrapped_ref[25:])
                            if len(refs) > 5:
                                print(mycolors.foreground.lightcyan + f"{'  ...':<25}" + mycolors.reset + f"({len(refs) - 5} more)")
                
                else:
                    if 'cve' in vuln:
                        cve_list = vuln['cve']
                        cve_result = ', '.join(cve_list) if isinstance(cve_list, list) else str(cve_list)
                        print(mycolors.foreground.red + f"\n{'CVE ID:':<25}" + mycolors.reset + cve_result)
                    
                    if 'title' in vuln and vuln['title']:
                        wrapped_title = textwrap.fill(self.sanitize_text(str(vuln['title'])).strip(), width=90, initial_indent=' ' * 25, subsequent_indent=' ' * 25)
                        print(mycolors.foreground.cyan + f"{'Title:':<25}" + mycolors.reset + wrapped_title[25:])
                    
                    if 'summary' in vuln and vuln['summary']:
                        wrapped_summary = textwrap.fill(self.sanitize_text(str(vuln['summary'])).strip(), width=90, initial_indent=' ' * 25, subsequent_indent=' ' * 25)
                        print(mycolors.foreground.cyan + f"{'Summary:':<25}" + mycolors.reset + wrapped_summary[25:])
                    
                    if 'url' in vuln and vuln['url']:
                        print(mycolors.foreground.cyan + f"{'URL:':<25}" + mycolors.reset + str(vuln['url']))
                    
                    if 'date_added' in vuln and vuln['date_added']:
                        print(mycolors.foreground.cyan + f"{'Date Added:':<25}" + mycolors.reset + str(vuln['date_added']))
                    
                    if 'updated_at' in vuln and vuln['updated_at']:
                        print(mycolors.foreground.cyan + f"{'Last Updated:':<25}" + mycolors.reset + str(vuln['updated_at']))
                    
                    if 'references' in vuln and vuln['references']:
                        refs = vuln['references']
                        if isinstance(refs, list) and len(refs) > 0:
                            print(mycolors.foreground.cyan + f"{'References:':<25}" + mycolors.reset)
                            for ref in refs[:5]:
                                wrapped_ref = textwrap.fill(str(ref), width=90, initial_indent=' ' * 25, subsequent_indent=' ' * 25)
                                print(mycolors.foreground.cyan + f"{'  -':<25}" + mycolors.reset + wrapped_ref[25:])
                            if len(refs) > 5:
                                print(mycolors.foreground.cyan + f"{'  ...':<25}" + mycolors.reset + f"({len(refs) - 5} more)")
            else:
                msg_color = mycolors.foreground.blue if cv.bkg == 0 else mycolors.foreground.yellow
                print(msg_color + f"\nCVE {cve_id} not found in MITRE CVE database.\n")

        except requests.exceptions.Timeout:
            print(mycolors.foreground.red + "\nError: Request timed out.\n")
        except requests.exceptions.ConnectionError as e:
            print(mycolors.foreground.red + f"\nError: Connection error: {str(e)}\n")
        except requests.exceptions.HTTPError as e:
            print(mycolors.foreground.red + f"\nError: HTTP error: {str(e)}\n")
        except json.JSONDecodeError:
            print(mycolors.foreground.red + "\nError: Invalid JSON response.\n")
        except Exception as e:
            print(mycolors.foreground.red + f"\nError: {str(e)}\n")

    def vulncheck_nist_search(self, cve_id):
        
        self.requestVULNCHECKAPI()
        
        if not cve_id:
            print(mycolors.foreground.red + "\nError: CVE ID is required for this search. Use -VC or --VULNCHECK to specify a CVE ID." + mycolors.reset)
            ex_color = mycolors.foreground.blue if cv.bkg == 0 else mycolors.foreground.yellow
            print(ex_color + "Example: python malwoverview.py -vc 8 -VC CVE-2024-21412 -o 0\n" + mycolors.reset)
            return
        
        try:
            print("\n")
            print((mycolors.reset + f"VULNCHECK - NIST NVD2 SEARCH: {cve_id}".center(100)), end='')
            print((mycolors.reset + "".center(28)), end='')
            print("\n" + (100 * '-').center(50))

            requestsession = requests.Session()
            requestsession.headers.update({'Accept': 'application/json'})
            requestsession.headers.update({'Authorization': f'Bearer {self.VULNCHECKAPI}'})

            response = requestsession.get(
                url=f'{self.base_url}/index/nist-nvd2',
                params={'cve': cve_id},
                timeout=30
            )

            if response.status_code == 401:
                print(mycolors.foreground.red + "\nError: Invalid API token (401 Unauthorized).\n")
                return
            elif response.status_code == 402:
                print(mycolors.foreground.red + "\nError: Subscription required to view this data (402 Payment Required).\n")
                return
            elif response.status_code == 429:
                print(mycolors.foreground.red + "\nError: Rate limit exceeded (429 Too Many Requests).\n")
                return
            
            response.raise_for_status()
            data = response.json()

            if data and 'data' in data and len(data['data']) > 0:
                vuln = data['data'][0]
                
                if cv.bkg == 1:
                    if 'id' in vuln:
                        print(mycolors.foreground.yellow + f"\n{'CVE ID:':<25}" + mycolors.reset + str(vuln['id']))
                    
                    if 'vulnStatus' in vuln and vuln['vulnStatus']:
                        print(mycolors.foreground.lightcyan + f"{'Status:':<25}" + mycolors.reset + str(vuln['vulnStatus']))
                    
                    if 'published' in vuln and vuln['published']:
                        print(mycolors.foreground.lightcyan + f"{'Published:':<25}" + mycolors.reset + str(vuln['published']))
                    
                    if 'lastModified' in vuln and vuln['lastModified']:
                        print(mycolors.foreground.lightcyan + f"{'Last Modified:':<25}" + mycolors.reset + str(vuln['lastModified']))
                    
                    if 'descriptions' in vuln and vuln['descriptions']:
                        desc_items = vuln['descriptions']
                        if isinstance(desc_items, list) and len(desc_items) > 0:
                            desc = desc_items[0]
                            if isinstance(desc, dict) and 'value' in desc:
                                wrapped_desc = textwrap.fill(self.sanitize_text(desc['value']).strip(), width=90, initial_indent=' ' * 25, subsequent_indent=' ' * 25)
                                print(mycolors.foreground.lightcyan + f"{'Description:':<25}" + mycolors.reset + wrapped_desc[25:])
                    
                    if 'metrics' in vuln and vuln['metrics']:
                        metrics = vuln['metrics']
                        if isinstance(metrics, dict) and 'cvssMetricV31' in metrics:
                            cvss_list = metrics['cvssMetricV31']
                            if isinstance(cvss_list, list) and len(cvss_list) > 0:
                                cvss = cvss_list[0]
                                if isinstance(cvss, dict) and 'cvssData' in cvss:
                                    cvss_data = cvss['cvssData']
                                    if isinstance(cvss_data, dict):
                                        if 'baseScore' in cvss_data:
                                            score = cvss_data['baseScore']
                                            severity = cvss_data.get('baseSeverity', 'N/A')
                                            score_color = mycolors.foreground.red if float(score) >= 7.0 else mycolors.foreground.yellow if float(score) >= 4.0 else mycolors.foreground.lightgreen
                                            print(mycolors.foreground.lightcyan + f"{'CVSS v3.1 Score:':<25}" + score_color + f"{score} ({severity})" + mycolors.reset)
                                        
                                        if 'vectorString' in cvss_data:
                                            print(mycolors.foreground.lightcyan + f"{'CVSS Vector:':<25}" + mycolors.reset + str(cvss_data['vectorString']))
                    
                    if 'cisaExploitAdd' in vuln and vuln['cisaExploitAdd']:
                        print(mycolors.foreground.lightcyan + f"{'CISA KEV Added:':<25}" + mycolors.reset + str(vuln['cisaExploitAdd']))
                        
                        if 'cisaActionDue' in vuln and vuln['cisaActionDue']:
                            print(mycolors.foreground.lightcyan + f"{'CISA Action Due:':<25}" + mycolors.reset + str(vuln['cisaActionDue']))
                        
                        if 'cisaVulnerabilityName' in vuln and vuln['cisaVulnerabilityName']:
                            wrapped_cisa = textwrap.fill(self.sanitize_text(str(vuln['cisaVulnerabilityName'])).strip(), width=90, initial_indent=' ' * 25, subsequent_indent=' ' * 25)
                            print(mycolors.foreground.lightcyan + f"{'CISA Vuln Name:':<25}" + mycolors.reset + wrapped_cisa[25:])
                        
                        if 'cisaRequiredAction' in vuln and vuln['cisaRequiredAction']:
                            wrapped_action = textwrap.fill(self.sanitize_text(str(vuln['cisaRequiredAction'])).strip(), width=90, initial_indent=' ' * 25, subsequent_indent=' ' * 25)
                            print(mycolors.foreground.lightcyan + f"{'CISA Action:':<25}" + mycolors.reset + wrapped_action[25:])
                    
                    if 'weaknesses' in vuln and vuln['weaknesses']:
                        weak_list = vuln['weaknesses']
                        if isinstance(weak_list, list) and len(weak_list) > 0:
                            for weak_item in weak_list:
                                if isinstance(weak_item, dict) and 'description' in weak_item:
                                    desc_list = weak_item['description']
                                    if isinstance(desc_list, list) and len(desc_list) > 0:
                                        for desc_item in desc_list:
                                            if isinstance(desc_item, dict) and 'value' in desc_item:
                                                print(mycolors.foreground.lightcyan + f"{'CWE:':<25}" + mycolors.reset + str(desc_item['value']))
                                                break
                                        break
                    
                    if 'references' in vuln and vuln['references']:
                        refs = vuln['references']
                        if isinstance(refs, list) and len(refs) > 0:
                            print(mycolors.foreground.lightcyan + f"{'References:':<25}" + mycolors.reset)
                            for ref in refs[:3]:
                                if isinstance(ref, dict) and 'url' in ref:
                                    wrapped_ref = textwrap.fill(str(ref['url']), width=90, initial_indent=' ' * 25, subsequent_indent=' ' * 25)
                                    print(mycolors.foreground.lightcyan + f"{'  -':<25}" + mycolors.reset + wrapped_ref[25:])
                            if len(refs) > 3:
                                print(mycolors.foreground.lightcyan + f"{'  ...':<25}" + mycolors.reset + f"({len(refs) - 3} more)")
                
                else:
                    if 'id' in vuln:
                        print(mycolors.foreground.red + f"\n{'CVE ID:':<25}" + mycolors.reset + str(vuln['id']))
                    
                    if 'vulnStatus' in vuln and vuln['vulnStatus']:
                        print(mycolors.foreground.cyan + f"{'Status:':<25}" + mycolors.reset + str(vuln['vulnStatus']))
                    
                    if 'published' in vuln and vuln['published']:
                        print(mycolors.foreground.cyan + f"{'Published:':<25}" + mycolors.reset + str(vuln['published']))
                    
                    if 'lastModified' in vuln and vuln['lastModified']:
                        print(mycolors.foreground.cyan + f"{'Last Modified:':<25}" + mycolors.reset + str(vuln['lastModified']))
                    
                    if 'descriptions' in vuln and vuln['descriptions']:
                        desc_items = vuln['descriptions']
                        if isinstance(desc_items, list) and len(desc_items) > 0:
                            desc = desc_items[0]
                            if isinstance(desc, dict) and 'value' in desc:
                                wrapped_desc = textwrap.fill(self.sanitize_text(desc['value']).strip(), width=90, initial_indent=' ' * 25, subsequent_indent=' ' * 25)
                                print(mycolors.foreground.cyan + f"{'Description:':<25}" + mycolors.reset + wrapped_desc[25:])
                    
                    if 'metrics' in vuln and vuln['metrics']:
                        metrics = vuln['metrics']
                        if isinstance(metrics, dict) and 'cvssMetricV31' in metrics:
                            cvss_list = metrics['cvssMetricV31']
                            if isinstance(cvss_list, list) and len(cvss_list) > 0:
                                cvss = cvss_list[0]
                                if isinstance(cvss, dict) and 'cvssData' in cvss:
                                    cvss_data = cvss['cvssData']
                                    if isinstance(cvss_data, dict):
                                        if 'baseScore' in cvss_data:
                                            score = cvss_data['baseScore']
                                            severity = cvss_data.get('baseSeverity', 'N/A')
                                            score_color = mycolors.foreground.red if float(score) >= 7.0 else mycolors.foreground.blue if float(score) >= 4.0 else mycolors.foreground.purple
                                            print(mycolors.foreground.cyan + f"{'CVSS v3.1 Score:':<25}" + score_color + f"{score} ({severity})" + mycolors.reset)
                                        
                                        if 'vectorString' in cvss_data:
                                            print(mycolors.foreground.cyan + f"{'CVSS Vector:':<25}" + mycolors.reset + str(cvss_data['vectorString']))
                    
                    if 'cisaExploitAdd' in vuln and vuln['cisaExploitAdd']:
                        print(mycolors.foreground.cyan + f"{'CISA KEV Added:':<25}" + mycolors.reset + str(vuln['cisaExploitAdd']))
                        
                        if 'cisaActionDue' in vuln and vuln['cisaActionDue']:
                            print(mycolors.foreground.cyan + f"{'CISA Action Due:':<25}" + mycolors.reset + str(vuln['cisaActionDue']))
                        
                        if 'cisaVulnerabilityName' in vuln and vuln['cisaVulnerabilityName']:
                            wrapped_cisa = textwrap.fill(self.sanitize_text(str(vuln['cisaVulnerabilityName'])).strip(), width=90, initial_indent=' ' * 25, subsequent_indent=' ' * 25)
                            print(mycolors.foreground.cyan + f"{'CISA Vuln Name:':<25}" + mycolors.reset + wrapped_cisa[25:])
                        
                        if 'cisaRequiredAction' in vuln and vuln['cisaRequiredAction']:
                            wrapped_action = textwrap.fill(self.sanitize_text(str(vuln['cisaRequiredAction'])).strip(), width=90, initial_indent=' ' * 25, subsequent_indent=' ' * 25)
                            print(mycolors.foreground.cyan + f"{'CISA Action:':<25}" + mycolors.reset + wrapped_action[25:])
                    
                    if 'weaknesses' in vuln and vuln['weaknesses']:
                        weak_list = vuln['weaknesses']
                        if isinstance(weak_list, list) and len(weak_list) > 0:
                            for weak_item in weak_list:
                                if isinstance(weak_item, dict) and 'description' in weak_item:
                                    desc_list = weak_item['description']
                                    if isinstance(desc_list, list) and len(desc_list) > 0:
                                        for desc_item in desc_list:
                                            if isinstance(desc_item, dict) and 'value' in desc_item:
                                                print(mycolors.foreground.cyan + f"{'CWE:':<25}" + mycolors.reset + str(desc_item['value']))
                                                break
                                        break
                    
                    if 'references' in vuln and vuln['references']:
                        refs = vuln['references']
                        if isinstance(refs, list) and len(refs) > 0:
                            print(mycolors.foreground.cyan + f"{'References:':<25}" + mycolors.reset)
                            for ref in refs[:3]:
                                if isinstance(ref, dict) and 'url' in ref:
                                    wrapped_ref = textwrap.fill(str(ref['url']), width=90, initial_indent=' ' * 25, subsequent_indent=' ' * 25)
                                    print(mycolors.foreground.cyan + f"{'  -':<25}" + mycolors.reset + wrapped_ref[25:])
                            if len(refs) > 3:
                                print(mycolors.foreground.cyan + f"{'  ...':<25}" + mycolors.reset + f"({len(refs) - 3} more)")
            else:
                msg_color = mycolors.foreground.blue if cv.bkg == 0 else mycolors.foreground.yellow
                print(msg_color + f"\nCVE {cve_id} not found in NIST NVD2 database.\n")

        except requests.exceptions.Timeout:
            print(mycolors.foreground.red + "\nError: Request timed out.\n")
        except requests.exceptions.ConnectionError as e:
            print(mycolors.foreground.red + f"\nError: Connection error: {str(e)}\n")
        except requests.exceptions.HTTPError as e:
            print(mycolors.foreground.red + f"\nError: HTTP error: {str(e)}\n")
        except json.JSONDecodeError:
            print(mycolors.foreground.red + "\nError: Invalid JSON response.\n")
        except Exception as e:
            print(mycolors.foreground.red + f"\nError: {str(e)}\n")
