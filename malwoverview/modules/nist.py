import os
import json
import time
import textwrap
import requests
from datetime import datetime
from malwoverview.utils.colors import (mycolors, strip_json_escapes, strip_terminal_escapes,
                                       bullet, column, display_width, divider, fit, pad,
                                       report_header)
from malwoverview.utils.output import collector
from malwoverview.utils.session import create_session, failure_message
from malwoverview.utils.cache import cached
import malwoverview.modules.configvars as cv


MAX_PAGE_SIZE = 2000
MAX_PAGES = 25
PAGE_DELAY = 6
REPORT_WIDTH = 100

COL_GUTTER = 2
COL_DESCRIPTION_MAX = 100
COL_VENDOR_MAX = 20
TABLE_KEYS = ('cve', 'vendor', 'published', 'cvss', 'description')
TABLE_HEADERS = ('CVE', 'Vendor', 'Published', 'CVSS', 'Description')
TABLE_CAPS = {'description': COL_DESCRIPTION_MAX, 'vendor': COL_VENDOR_MAX}
DEFAULT_COMPONENT_LIMIT = 25

NAME_KEYS = ('InternalName', 'OriginalFilename')
DESCRIPTION_KEY = 'FileDescription'

WINDOWS_BINARY_SUFFIXES = ('.sys', '.dll', '.exe', '.ocx', '.drv', '.cpl', '.efi', '.scr')

LABEL_NAME = 'file name'
LABEL_INTERNAL = 'internal name'
LABEL_DESCRIPTION = 'component description'

HIGH_SEVERITIES = ('CRITICAL', 'HIGH')
MAX_VENDORS_REPORTED = 6
MAX_KEY_LENGTH = 200

SORT_BY_CVE = 'cve'
SORT_BY_PUBLISHED = 'published'
SORT_CHOICES = (SORT_BY_CVE, SORT_BY_PUBLISHED)
DEFAULT_SORT_BY = SORT_BY_CVE
SORT_LABELS = {SORT_BY_CVE: 'CVE ID', SORT_BY_PUBLISHED: 'publication date'}


class NISTExtractor():

    base_url = 'https://services.nvd.nist.gov/rest/json/cves/2.0'

    def __init__(self):
        self.session = create_session()
        self.session.headers.update({'User-Agent': 'MalwoOverview/1.0'})

    @staticmethod
    def _cpe_has_version(value):
        parts = value.split(':')
        if len(parts) < 6:
            return False
        return parts[5] not in ('', '*', '-')

    def _build_params(self, query_type, query_value, last_n_years):
        params = {}
        if query_type == 1:
            if query_value.lower().startswith('cpe:'):
                if self._cpe_has_version(query_value):
                    params['cpeName'] = query_value
                    return params, f"CPE Name: {query_value}"
                params['virtualMatchString'] = query_value
                return params, f"CPE Match: {query_value}"
            params['keywordSearch'] = query_value
            return params, f"Keyword Search: {query_value}"
        if query_type == 2:
            params['cveId'] = query_value
            return params, f"CVE ID: {query_value}"
        if query_type == 3:
            params['cvssV3Severity'] = query_value
            suffix = f" (last {last_n_years} years)" if last_n_years else ''
            return params, f"CVSS v3 Severity: {query_value}{suffix}"
        if query_type in (4, 6):
            params['keywordSearch'] = query_value
            suffix = f" (last {last_n_years} years)" if last_n_years else ''
            return params, f"Keyword Search: {query_value}{suffix}"
        if query_type == 5:
            params['cweId'] = query_value
            suffix = f" (last {last_n_years} years)" if last_n_years else ''
            return params, f"CWE ID Search: {query_value}{suffix}"
        return None, None

    def _collect(self, params, results_per_page, start_index):
        page_size = max(1, min(int(results_per_page or MAX_PAGE_SIZE), MAX_PAGE_SIZE))
        index = max(0, int(start_index or 0))
        collected = []
        seen = set()
        total = 0
        pages = 0
        announced = False

        while pages < MAX_PAGES:
            params['resultsPerPage'] = page_size
            params['startIndex'] = index
            response = self.session.get(self.base_url, params=params)
            response.raise_for_status()
            data = strip_json_escapes(response.json())
            if 'vulnerabilities' not in data:
                print(mycolors.foreground.warning(cv.bkg) + "\nWarning: Unexpected API response structure.\n" + mycolors.reset)
            total = data.get('totalResults', 0)
            batch = data.get('vulnerabilities', [])
            if not batch:
                break
            for item in batch:
                cve_id = item.get('cve', {}).get('id')
                if cve_id:
                    if cve_id in seen:
                        continue
                    seen.add(cve_id)
                collected.append(item)
            pages = pages + 1
            index = index + len(batch)
            if index >= total:
                break
            if not announced:
                announced = True
                print(bullet("Retrieving %d matching CVEs from NIST NVD in pages of %d."
                             % (total, page_size), REPORT_WIDTH))
            time.sleep(PAGE_DELAY)

        return {
            'vulnerabilities': collected,
            'totalResults': total,
            'retrieved': len(collected),
            'resultsPerPage': len(collected),
            'truncated': index < total,
        }

    @cached("nist_cve")
    def query_cve(self, query_type, query_value, results_per_page=MAX_PAGE_SIZE, start_index=0, last_n_years=None, sort_by=DEFAULT_SORT_BY):

        if not query_value:
            print(mycolors.foreground.error(cv.bkg) + "\nError: No query value provided.\n" + mycolors.reset)
            return None

        params, query_desc = self._build_params(query_type, query_value, last_n_years)
        if params is None:
            print(mycolors.foreground.error(cv.bkg) + f"\nError: Unknown query type '{query_type}'.\n" + mycolors.reset)
            return None

        try:
            data = self._collect(params, results_per_page, start_index)

            if last_n_years:
                data = self._filter_by_date(data, last_n_years, sort_by)

            return self._sort_descending(data, sort_by)

        except requests.exceptions.RequestException as e:
            print(mycolors.foreground.error(cv.bkg) + failure_message(e, 'services.nvd.nist.gov') + mycolors.reset)
            return None
        except json.JSONDecodeError:
            print(mycolors.foreground.error(cv.bkg) + "\nError: Invalid JSON response.\n" + mycolors.reset)
            return None
        except Exception as e:
            print(mycolors.foreground.error(cv.bkg) + f"\nError: {str(e)}\n" + mycolors.reset)
            return None

    def print_results(self, data, verbose=False, color_scheme=1, max_cves=None, sort_by=DEFAULT_SORT_BY):

        if not data or 'vulnerabilities' not in data:
            print(mycolors.foreground.error(cv.bkg) + "\nNo results found.\n" + mycolors.reset)
            return
        vulnerabilities = data.get('vulnerabilities', [])

        vulnerabilities_sorted = sorted(
            vulnerabilities,
            key=self._sort_key(sort_by),
            reverse=True
        )

        if max_cves is not None and max_cves > 0:
            vulnerabilities_sorted = vulnerabilities_sorted[:max_cves]

        if data.get('truncated'):
            print()
            print(bullet("Only the first %d of %d matching CVEs were retrieved, so the most "
                         "recent ones are missing. Narrow the query, or use --startindex to "
                         "reach the rest."
                         % (data.get('retrieved', 0), data.get('totalResults', 0)),
                         REPORT_WIDTH, mycolors.foreground.warning(cv.bkg)))

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

            collector.add({
                'service': 'nist',
                'query_type': 'query_cve',
                'cve': cve_id,
                'published': published,
                'last_modified': last_modified,
                'status': vuln_status,
                'description': description,
            })
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
            except Exception:
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

    @staticmethod
    def _entry_key(entry, sort_by):
        cve_key = NISTExtractor._cve_id_key(entry.get('cve', ''))
        published = str(entry.get('published') or '')
        if NISTExtractor._normalize_sort(sort_by) == SORT_BY_PUBLISHED:
            return (published, cve_key)
        return (cve_key, published)

    @staticmethod
    def _normalize_sort(sort_by):
        if sort_by in SORT_CHOICES:
            return sort_by
        return DEFAULT_SORT_BY

    @staticmethod
    def _cve_id_key(cve_id):
        parts = str(cve_id or '').split('-')
        if len(parts) >= 3 and parts[0].upper() == 'CVE':
            try:
                return (1, int(parts[1]), int(parts[2]))
            except ValueError:
                pass
        return (0, 0, 0)

    @staticmethod
    def _published_value(vuln):
        published = vuln.get('cve', {}).get('published', '')
        if not published or published == 'N/A':
            return ''
        return str(published)

    @staticmethod
    def _published_key(vuln):
        return (NISTExtractor._published_value(vuln),
                NISTExtractor._cve_id_key(vuln.get('cve', {}).get('id', '')))

    @staticmethod
    def _cve_key(vuln):
        return (NISTExtractor._cve_id_key(vuln.get('cve', {}).get('id', '')),
                NISTExtractor._published_value(vuln))

    def _sort_key(self, sort_by):
        if self._normalize_sort(sort_by) == SORT_BY_PUBLISHED:
            return self._published_key
        return self._cve_key

    def _sort_descending(self, data, sort_by=DEFAULT_SORT_BY):
        if not data or 'vulnerabilities' not in data:
            return data

        data['vulnerabilities'] = sorted(
            data.get('vulnerabilities', []),
            key=self._sort_key(sort_by),
            reverse=True
        )
        return data

    @staticmethod
    def _reference_year(vuln, by_published):
        if by_published:
            published = NISTExtractor._published_value(vuln)
            try:
                return int(published[:4])
            except ValueError:
                return None
        cve_id = vuln.get('cve', {}).get('id', '')
        valid, year, _ = NISTExtractor._cve_id_key(cve_id)
        return year if valid else None

    def _filter_by_date(self, data, last_n_years, sort_by=DEFAULT_SORT_BY):
        if not data or 'vulnerabilities' not in data:
            return data
        if last_n_years <= 0:
            return data

        current_year = datetime.now().year
        cutoff_year = current_year - last_n_years
        by_published = self._normalize_sort(sort_by) == SORT_BY_PUBLISHED
        filtered_vulns = []

        for vuln in data.get('vulnerabilities', []):
            year = self._reference_year(vuln, by_published)
            if year is None or year >= cutoff_year:
                filtered_vulns.append(vuln)

        data['vulnerabilities'] = filtered_vulns
        data['resultsPerPage'] = len(filtered_vulns)
        return data

    def get_query_type_description(self, query_type):
        types = {
            1: "CPE/Product Search",
            2: "CVE ID Search",
            3: "CVSS v3 Severity Search",
            4: "Keyword Search",
            5: "CWE ID Search",
            6: "Component Search"
        }
        return types.get(query_type, "Unknown Query Type")

    def _versioninfo(self, path):
        try:
            import pefile
        except ImportError:
            return None, "pefile is not installed, so the component description cannot be read."
        try:
            binary = pefile.PE(path, fast_load=True)
        except Exception:
            return None, ("No component metadata could be read from %s, because it is not a "
                          "Windows PE file." % os.path.basename(path))

        info = {}
        try:
            binary.parse_data_directories(
                directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_RESOURCE']])
            for fileinfo in getattr(binary, 'FileInfo', []) or []:
                entries = fileinfo if isinstance(fileinfo, list) else [fileinfo]
                for entry in entries:
                    if getattr(entry, 'Key', b'') != b'StringFileInfo':
                        continue
                    for stringtable in getattr(entry, 'StringTable', []):
                        for key, value in stringtable.entries.items():
                            info[self._clean(key)] = self._clean(value)
        except Exception:
            return None, ("No component metadata could be read from %s, because it is not a "
                          "Windows PE file." % os.path.basename(path))
        finally:
            try:
                binary.close()
            except Exception:
                pass
        return info, None

    @staticmethod
    def _clean(value):
        if isinstance(value, bytes):
            value = value.decode('utf-8', 'replace')
        value = strip_terminal_escapes(str(value)).replace('\x00', '').strip()
        return value[:MAX_KEY_LENGTH]

    def _component_keys(self, target):
        if not os.path.isfile(target):
            return [(self._clean(target), LABEL_NAME)], None

        keys = []
        seen = set()

        def _append(value, label):
            value = self._clean(value or '')
            if not value or value.lower() in seen:
                return
            seen.add(value.lower())
            keys.append((value, label))

        _append(os.path.basename(target), LABEL_NAME)

        info, error = self._versioninfo(target)
        if error:
            return keys, error

        for key in NAME_KEYS:
            if info.get(key):
                _append(info[key], LABEL_INTERNAL)
                break
        _append(info.get(DESCRIPTION_KEY, ''), LABEL_DESCRIPTION)
        return keys, None

    @staticmethod
    def _severity(cve_data):
        metrics = cve_data.get('metrics', {})
        for key in ('cvssMetricV40', 'cvssMetricV31', 'cvssMetricV3', 'cvssMetricV30'):
            for metric in metrics.get(key, []) or []:
                data = metric.get('cvssData', {})
                score = data.get('baseScore')
                severity = data.get('baseSeverity') or metric.get('baseSeverity') or ''
                if score is not None:
                    return score, str(severity).upper()
        for metric in metrics.get('cvssMetricV2', []) or []:
            score = metric.get('cvssData', {}).get('baseScore')
            severity = metric.get('baseSeverity') or ''
            if score is not None:
                return score, str(severity).upper()
        return None, ''

    def _summarize(self, vuln):
        cve_data = vuln.get('cve', {})
        cve_id = cve_data.get('id')
        if not cve_id:
            return None

        description = ''
        for desc in cve_data.get('descriptions', []):
            if desc.get('lang') == 'en':
                description = desc.get('value', '')
                break

        score, severity = self._severity(cve_data)
        published = cve_data.get('published', '') or ''

        return {
            'cve': cve_id,
            'published': published,
            'score': score,
            'severity': severity,
            'vendors': self._vendors(cve_data),
            'description': ' '.join(description.split()),
            'matched_by': [],
        }

    @staticmethod
    def _vendors(cve_data):
        found = set()
        for configuration in cve_data.get('configurations', []) or []:
            for node in configuration.get('nodes', []) or []:
                for match in node.get('cpeMatch', []) or []:
                    parts = str(match.get('criteria', '')).split(':')
                    if len(parts) > 4 and parts[3]:
                        found.add(parts[3])
        return sorted(found)

    def _severity_color(self, severity):
        if severity in HIGH_SEVERITIES:
            return mycolors.foreground.error(cv.bkg)
        if severity == 'MEDIUM':
            return mycolors.foreground.warning(cv.bkg)
        if severity == 'LOW':
            return mycolors.foreground.ok(cv.bkg)
        return mycolors.foreground.neutral(cv.bkg)

    @staticmethod
    def _cvss_cell(entry):
        if entry['score'] is None:
            return 'n/a'
        if entry['severity']:
            return '%s %s' % (entry['score'], entry['severity'])
        return str(entry['score'])

    def _rows(self, entries):
        rows = []
        for entry in entries:
            rows.append((
                entry['cve'],
                ', '.join(entry['vendors']) or 'n/a',
                (entry['published'] or 'n/a')[:10],
                self._cvss_cell(entry),
                entry['description'] or 'n/a',
            ))
        return rows

    def _widths(self, rows):
        widths = {}
        for index, key in enumerate(TABLE_KEYS):
            values = [row[index] for row in rows]
            last = index == len(TABLE_KEYS) - 1
            widths[key] = column(
                TABLE_HEADERS[index], values,
                cap=TABLE_CAPS.get(key),
                gutter=0 if last else COL_GUTTER,
            )
        widths['total'] = sum(widths[key] for key in TABLE_KEYS)
        return widths

    def _print_table(self, rows, entries, widths, component, matched, sort_by=DEFAULT_SORT_BY):
        structure = mycolors.foreground.neutral(cv.bkg)
        print()
        print(report_header("NIST NVD - CVEs BY COMPONENT", widths['total']))
        print()
        header = "".join(pad(TABLE_HEADERS[i], widths[key])
                         for i, key in enumerate(TABLE_KEYS)).rstrip()
        print(structure + header + mycolors.reset)
        print(divider(widths['total']))

        for index, row in enumerate(rows):
            cve_id, vendor, published, cvss, description = row
            print(
                mycolors.foreground.accent(cv.bkg) + pad(cve_id, widths['cve'])
                + mycolors.foreground.warning(cv.bkg)
                + pad(fit(vendor, widths['vendor'] - COL_GUTTER), widths['vendor'])
                + mycolors.foreground.info(cv.bkg) + pad(published, widths['published'])
                + self._severity_color(entries[index]['severity']) + pad(cvss, widths['cvss'])
                + mycolors.foreground.success(cv.bkg) + fit(description, widths['description'])
                + mycolors.reset
            )

        print(divider(widths['total']))
        sort_by = self._normalize_sort(sort_by)
        other = SORT_BY_PUBLISHED if sort_by == SORT_BY_CVE else SORT_BY_CVE
        if matched > len(rows):
            print(bullet("The %d most recent of %d CVE(s) found for %s, ordered by %s. Use "
                         "--ncves <number> for more, --ncves 0 for all of them, --time <years> "
                         "to bound them by year, or --sort-by %s to order them by %s."
                         % (len(rows), matched, component, SORT_LABELS[sort_by], other,
                            SORT_LABELS[other]), widths['total']))
        else:
            print(bullet("%d CVE(s) found for %s, ordered by %s. Use --sort-by %s to order them "
                         "by %s." % (len(rows), component, SORT_LABELS[sort_by], other,
                                     SORT_LABELS[other]), widths['total']))

    def component_cve(self, target, max_cves=None, last_n_years=None, results_per_page=MAX_PAGE_SIZE,
                      sort_by=DEFAULT_SORT_BY):
        sort_by = self._normalize_sort(sort_by)
        keys, metadata_note = self._component_keys(target)

        if not keys:
            print(bullet("No component name could be derived from %s." % target,
                         REPORT_WIDTH, mycolors.foreground.error(cv.bkg)))
            return None

        found = {}
        queried = []
        for value, label in keys:
            data = self.query_cve(6, value, results_per_page, 0, last_n_years, sort_by)
            if data is None:
                continue
            queried.append((value, label))
            for vuln in data.get('vulnerabilities', []):
                entry = self._summarize(vuln)
                if not entry:
                    continue
                record = found.setdefault(entry['cve'], entry)
                if label not in record['matched_by']:
                    record['matched_by'].append(label)

        if not queried:
            return None

        entries = sorted(found.values(),
                         key=lambda e: self._entry_key(e, sort_by),
                         reverse=True)
        all_entries = entries
        matched = len(all_entries)
        limit = DEFAULT_COMPONENT_LIMIT if max_cves is None else max(0, max_cves)
        if limit:
            entries = entries[:limit]

        name_key = keys[0][0]
        description_key = ''
        for value, label in keys:
            if label == LABEL_DESCRIPTION:
                description_key = value

        component = '%s (%s)' % (name_key, description_key) if description_key else name_key

        if not entries:
            print(bullet("No CVE found for %s." % component, REPORT_WIDTH))
            print(bullet("An empty result is not a verdict that the component is free of "
                         "vulnerabilities. NVD descriptions do not always name the component, "
                         "and Apple's modern entries never do, so search the product instead "
                         "with --nist 1 and a CPE, such as cpe:2.3:o:apple:iphone_os.",
                         REPORT_WIDTH))
            self._print_advisories(REPORT_WIDTH, queried, {}, 0, False, target,
                                   metadata_note=metadata_note)
            return None

        for entry in entries:
            collector.add({
                'service': 'nist',
                'query_type': 'component_cve',
                'component': name_key,
                'component_description': description_key or 'n/a',
                'cve': entry['cve'],
                'published': entry['published'] or 'n/a',
                'cvss_score': entry['score'] if entry['score'] is not None else 'n/a',
                'cvss_severity': entry['severity'] or 'n/a',
                'matched_by': ', '.join(entry['matched_by']),
                'vendors': ', '.join(entry['vendors']) or 'n/a',
                'description': entry['description'],
            })

        rows = self._rows(entries)
        widths = self._widths(rows)
        self._print_table(rows, entries, widths, component, matched, sort_by)

        counts = {}
        for value, label in queried:
            counts[value] = sum(1 for e in all_entries if label in e['matched_by'])
        overlap = sum(1 for e in all_entries if len(e['matched_by']) > 1)
        truncated = any(display_width(row[-1]) > widths['description'] for row in rows)
        self._print_advisories(widths['total'], queried, counts, overlap, truncated, target,
                               self._vendor_counts(all_entries), metadata_note)
        return None

    @staticmethod
    def _looks_like_windows_binary(value):
        return value.lower().endswith(WINDOWS_BINARY_SUFFIXES)

    @staticmethod
    def _join(parts):
        if len(parts) == 1:
            return parts[0]
        return ', '.join(parts[:-1]) + ' and ' + parts[-1]

    @staticmethod
    def _vendor_counts(entries):
        counts = {}
        for entry in entries:
            for vendor in entry['vendors']:
                counts[vendor] = counts.get(vendor, 0) + 1
        return sorted(counts.items(), key=lambda item: (-item[1], item[0]))

    def _print_advisories(self, width, queried, counts, overlap, truncated, target,
                          vendors=(), metadata_note=None):
        if len(queried) > 1:
            sentence = self._join(["%d matched the %s '%s'" % (counts.get(value, 0), label, value)
                                   for value, label in queried])
            if overlap:
                sentence = sentence + '; %d matched more than one key' % overlap
            print(bullet(sentence + '.', width))
        elif metadata_note:
            print(bullet("%s Only '%s' was searched. Outside Windows a component is better named "
                         "than pointed at: try the project or framework name, such as openssl, "
                         "systemd or WebKit." % (metadata_note, queried[0][0]), width))
        elif not os.path.isfile(target):
            if self._looks_like_windows_binary(queried[0][0]):
                print(bullet("Only '%s' was searched. If this is a Windows binary, passing the "
                             "path to the file searches the component description in its "
                             "VERSIONINFO as well, which is the wording modern NVD entries use."
                             % queried[0][0], width))
        else:
            print(bullet("The VERSIONINFO of this binary carries no component description, so "
                         "only '%s' was searched. Modern NVD entries are written against the "
                         "component description, so they cannot be matched." % queried[0][0],
                         width))

        if len(vendors) > 1:
            shown = vendors[:MAX_VENDORS_REPORTED]
            listed = ', '.join('%s (%d)' % (vendor, count) for vendor, count in shown)
            if len(vendors) > len(shown):
                listed = listed + ', and %d more' % (len(vendors) - len(shown))
            print(bullet("The affected products of these CVEs name %d vendors: %s. A row whose "
                         "vendor is not the vendor of this component is a different product with "
                         "a similar name." % (len(vendors), listed), width))

        if truncated:
            print(bullet("Descriptions are truncated to fit the table. Use --nist 2 --NIST <CVE> "
                         "for the full text of any row.", width))

        print(bullet("This is a keyword search over CVE descriptions. NVD has no file-level "
                     "mapping, so a match means the text mentions the component, not that this "
                     "build is affected.", width))
