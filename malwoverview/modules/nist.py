import requests
import json
import textwrap
from datetime import datetime, timedelta
from malwoverview.utils.colors import mycolors, printr
import malwoverview.modules.configvars as cv


class NISTExtractor():
    
    base_url = 'https://services.nvd.nist.gov/rest/json/cves/2.0'
    
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': 'MalwoOverview/1.0'})

    def query_cve(self, query_type, query_value, results_per_page=100, start_index=0, last_n_years=None):
        
        if not query_value:
            print(mycolors.foreground.red + "\nError: No query value provided.\n")
            return None
        if results_per_page > 2000:
            results_per_page = 2000
        elif results_per_page < 1:
            results_per_page = 1
        
        params = {'resultsPerPage': results_per_page, 'startIndex': start_index}

        try:
            if query_type == 1:
                if query_value.lower().startswith('cpe:'):
                    params['cpeName'] = query_value
                    query_desc = f"CPE Name: {query_value}"
                else:
                    params['keywordSearch'] = query_value
                    query_desc = f"Keyword Search: {query_value}"
            elif query_type == 2:
                params['cveId'] = query_value
                query_desc = f"CVE ID: {query_value}"
            elif query_type == 3:
                params['cvssV3Severity'] = query_value
                if last_n_years:
                    query_desc = f"CVSS v3 Severity: {query_value} (last {last_n_years} years)"
                else:
                    query_desc = f"CVSS v3 Severity: {query_value}"
            elif query_type == 4:
                params['keywordSearch'] = query_value
                if last_n_years:
                    query_desc = f"Keyword Search: {query_value} (last {last_n_years} years)"
                else:
                    query_desc = f"Keyword Search: {query_value}"
            elif query_type == 5:
                params['cweId'] = query_value
                if last_n_years:
                    query_desc = f"CWE ID Search: {query_value} (last {last_n_years} years)"
                else:
                    query_desc = f"CWE ID Search: {query_value}"
            else:
                print(mycolors.foreground.red + f"\nError: Unknown query type '{query_type}'.\n")
                return None

            # First request: Get a small batch to determine total results (needed for smart start_index)
            response = self.session.get(self.base_url, params=params, timeout=30)
            response.raise_for_status()
            data = response.json()
            if 'vulnerabilities' not in data:
                print(mycolors.foreground.yellow + "\nWarning: Unexpected API response structure.\n")
            
            total_results = data.get('totalResults', 0)
            
            # Smart positioning for recent vulnerabilities (except Type 2 - specific CVE search)
            # Type 2 searches entire database to find specific CVE in any year
            if start_index == 0 and total_results > 0 and query_type in [1, 3, 4, 5]:
                calculated_start = max(0, int(total_results * 0.99))
                params['startIndex'] = calculated_start
                params['resultsPerPage'] = 2000
                
                response = self.session.get(self.base_url, params=params, timeout=30)
                response.raise_for_status()
                data = response.json()
            
            # Apply date filtering or sorting for recent vulnerability discovery
            if last_n_years and query_type in [1, 3, 4, 5]:
                data = self._filter_by_date(data, last_n_years)
            elif query_type in [1, 3, 4, 5]:
                # Filter to current year only by default, then sort
                data = self._filter_to_current_year(data)
                data = self._sort_by_date_descending(data)
            
            return data

        except requests.exceptions.Timeout:
            print(mycolors.foreground.red + "\nError: Request timed out.\n")
            return None
        except requests.exceptions.ConnectionError as e:
            print(mycolors.foreground.red + f"\nError: Connection error: {str(e)}\n")
            return None
        except requests.exceptions.HTTPError as e:
            print(mycolors.foreground.red + f"\nError: HTTP error: {str(e)}\n")
            return None
        except json.JSONDecodeError:
            print(mycolors.foreground.red + "\nError: Invalid JSON response.\n")
            return None
        except Exception as e:
            print(mycolors.foreground.red + f"\nError: {str(e)}\n")
            return None

    def print_results(self, data, verbose=False, color_scheme=1, max_cves=None):
        
        if not data or 'vulnerabilities' not in data:
            print(mycolors.foreground.red + "\nNo results found.\n")
            return
        vulnerabilities = data.get('vulnerabilities', [])
        
        vulnerabilities_sorted = sorted(
            vulnerabilities,
            key=lambda x: x.get('cve', {}).get('published', '9999-01-01'),
            reverse=True
        )
        
        if max_cves is not None:
            vulnerabilities_sorted = vulnerabilities_sorted[:max_cves]
        
        if color_scheme == 0:
            cve_id_color = mycolors.foreground.red
            field_color = mycolors.foreground.blue
        else:
            cve_id_color = mycolors.foreground.yellow
            field_color = mycolors.foreground.lightcyan

        print()

        for idx, vuln in enumerate(vulnerabilities_sorted, 1):
            cve_data = vuln.get('cve', {})
            cve_id = cve_data.get('id', 'N/A')
            published = cve_data.get('published', 'N/A')
            last_modified = cve_data.get('lastModified', 'N/A')
            vuln_status = cve_data.get('vulnStatus', 'N/A')
            descriptions = cve_data.get('descriptions', [])
            description = 'N/A'
            for desc in descriptions:
                if desc.get('lang') == 'en':
                    description = desc.get('value', 'N/A')
                    break
            metrics = cve_data.get('metrics', {})
            cvss_v2 = metrics.get('cvssMetricV2', [])
            cvss_v3 = metrics.get('cvssMetricV31', []) or metrics.get('cvssMetricV3', [])
            
            print(f"{cve_id_color}[{idx}] CVE ID: {cve_id}{mycolors.reset}")
            print(f"    {field_color}Status:{mycolors.reset} {vuln_status}")
            print(f"    {field_color}Published:{mycolors.reset} {published}")
            print(f"    {field_color}Last Modified:{mycolors.reset} {last_modified}")
            if cvss_v2:
                for cv2 in cvss_v2:
                    score = cv2.get('cvssData', {}).get('baseScore', 'N/A')
                    severity = cv2.get('baseSeverity', 'N/A')
                    print(f"    {field_color}CVSS v2.0:{mycolors.reset} {score} ({severity})")
            
            if cvss_v3:
                for cv3 in cvss_v3:
                    score = cv3.get('cvssData', {}).get('baseScore', 'N/A')
                    severity = cv3.get('baseSeverity', 'N/A')
                    print(f"    {field_color}CVSS v3.1:{mycolors.reset} {score} ({severity})")
            
            print(f"    {field_color}Description:{mycolors.reset}")
            wrapped_desc = textwrap.fill(description, width=75, initial_indent='    ', subsequent_indent='    ')
            try:
                print(wrapped_desc.encode('utf-8', 'replace').decode('utf-8'))
            except:
                print(wrapped_desc.encode('ascii', 'replace').decode('ascii'))
            print()
            if verbose:
                configurations = cve_data.get('configurations', [])
                if configurations:
                    print(f"    {field_color}Affected Products:{mycolors.reset}")
                    for config in configurations[:3]:
                        nodes = config.get('nodes', [])
                        for node in nodes[:2]:
                            cpe_matches = node.get('cpeMatch', [])
                            for cpe in cpe_matches[:2]:
                                criteria = cpe.get('criteria', 'N/A')
                                if len(criteria) > 65:
                                    criteria = criteria[:62] + '...'
                                print(f"      - {criteria}")
                references = cve_data.get('references', [])
                if references:
                    print(f"    {field_color}References:{mycolors.reset}")
                    for ref in references[:2]:
                        url = ref.get('url', 'N/A')
                        if len(url) > 65:
                            url = url[:62] + '...'
                        print(f"      - {url}")

    def _sort_by_date_descending(self, data):
        if not data or 'vulnerabilities' not in data:
            return data
        
        def get_cve_year_and_id(vuln):
            """Extract year from CVE ID for sorting by actual threat year"""
            cve_id = vuln.get('cve', {}).get('id', '')
            # CVE ID format: CVE-YYYY-NNNNN
            try:
                if cve_id.startswith('CVE-'):
                    year = int(cve_id.split('-')[1])
                    # Return tuple: (year descending, full CVE ID for secondary sort)
                    return (year, cve_id)
            except (IndexError, ValueError):
                pass
            # Fallback for invalid CVE IDs
            return (0, cve_id)
        
        sorted_vulns = sorted(
            data.get('vulnerabilities', []),
            key=get_cve_year_and_id,
            reverse=True
        )
        
        data['vulnerabilities'] = sorted_vulns
        return data
    
    def _filter_to_current_year(self, data):
        """Filter vulnerabilities to include last 2 years by default (current + previous year)"""
        if not data or 'vulnerabilities' not in data:
            return data
        
        current_year = datetime.now().year
        previous_year = current_year - 1
        filtered_vulns = []
        
        for vuln in data.get('vulnerabilities', []):
            cve_id = vuln.get('cve', {}).get('id', '')
            # Extract year from CVE ID (CVE-YYYY-NNNNN)
            try:
                if cve_id.startswith('CVE-'):
                    cve_year = int(cve_id.split('-')[1])
                    if cve_year >= previous_year:  # Include current + previous year
                        filtered_vulns.append(vuln)
            except (ValueError, IndexError):
                pass
        
        data['vulnerabilities'] = filtered_vulns
        return data
    
    def _filter_by_date(self, data, last_n_years):
        if not data or 'vulnerabilities' not in data:
            return data
        
        current_year = datetime.now().year
        cutoff_year = current_year - last_n_years
        filtered_vulns = []
        
        for vuln in data.get('vulnerabilities', []):
            cve_id = vuln.get('cve', {}).get('id', '')
            # Extract year from CVE ID (CVE-YYYY-NNNNN)
            try:
                if cve_id.startswith('CVE-'):
                    cve_year = int(cve_id.split('-')[1])
                    if cve_year >= cutoff_year:
                        filtered_vulns.append(vuln)
                else:
                    filtered_vulns.append(vuln)
            except (ValueError, IndexError):
                filtered_vulns.append(vuln)
        
        # Sort by CVE year descending
        def get_cve_year_and_id(vuln):
            cve_id = vuln.get('cve', {}).get('id', '')
            try:
                if cve_id.startswith('CVE-'):
                    year = int(cve_id.split('-')[1])
                    return (year, cve_id)
            except (IndexError, ValueError):
                pass
            return (0, cve_id)
        
        filtered_vulns.sort(key=get_cve_year_and_id, reverse=True)
        
        data['vulnerabilities'] = filtered_vulns
        data['resultsPerPage'] = len(filtered_vulns)
        return data
    
    def get_query_type_description(self, query_type):
        types = {
            1: "CPE/Product Search",
            2: "CVE ID Search",
            3: "CVSS v3 Severity Search",
            4: "Keyword Search",
            5: "CWE ID Search"
        }
        return types.get(query_type, "Unknown Query Type")
