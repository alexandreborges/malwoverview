#!/usr/bin/env python3

# Copyright (C)  2018-2026 Alexandre Borges <https://exploitreversing.com>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# See GNU Public License on <http://www.gnu.org/licenses/>.

# CONTRIBUTORS

# Alexandre Borges (project owner)
# Artur Marzano (https://github.com/Macmod)
# Corey Forman (https://github.com/digitalsleuth)
# Christian Clauss (https://github.com/cclauss)

# Malwoverview.py: version 8.0  (codename: Revolutions)

import os
import sys
import argparse
import configparser
import platform
import signal
from colorama import init
from pathlib import Path
from malwoverview.modules.alienvault import AlienVaultExtractor
from malwoverview.modules.android import AndroidExtractor
from malwoverview.modules.bazaar import BazaarExtractor
from malwoverview.modules.hybrid import HybridAnalysisExtractor
from malwoverview.modules.malpedia import MalpediaExtractor
from malwoverview.modules.malshare import MalshareExtractor
from malwoverview.modules.polyswarm import PolyswarmExtractor
from malwoverview.modules.threatfox import ThreatFoxExtractor
from malwoverview.modules.triage import TriageExtractor
from malwoverview.modules.urlhaus import URLHausExtractor
from malwoverview.modules.virustotal import VirusTotalExtractor
from malwoverview.modules.ipinfo import IPInfoExtractor
from malwoverview.modules.bgpview import BGPViewExtractor
from malwoverview.modules.multipleip import MultipleIPExtractor
from malwoverview.modules.nist import NISTExtractor
from malwoverview.modules.vulncheck import VulnCheckExtractor
from malwoverview.modules.shodan_mod import ShodanExtractor
from malwoverview.modules.abuseipdb import AbuseIPDBExtractor
from malwoverview.modules.greynoise import GreyNoiseExtractor
from malwoverview.modules.whois_mod import WhoisExtractor
from malwoverview.modules.multiplehash import MultipleHashExtractor
from malwoverview.modules.urlscanio import URLScanIOExtractor

from malwoverview.utils.colors import printr
from malwoverview.utils.hash import calchash, detect_hash_type
from malwoverview.utils.output import collector, is_text_output
from malwoverview.utils.config import validate_config
from malwoverview.utils.sanitize import (
    sanitize_hash, sanitize_ip, sanitize_domain, sanitize_url,
    sanitize_cve, sanitize_path, sanitize_tag, sanitize_general,
    sanitize_uuid,
)
import malwoverview.modules.configvars as cv

__author__ = "Alexandre Borges"
__copyright__ = "Copyright 2018-2026 Alexandre Borges"
__license__ = "GNU General Public License v3.0"
__version__ = "8.0"
__email__ = "reverseexploit at proton.me"

def finish_hook(signum, frame):
    printr()
    exit(1)


class _TeeWriter:
    """Write to two streams simultaneously (for capturing output while still printing)."""
    def __init__(self, original, capture):
        self.original = original
        self.capture = capture

    def write(self, data):
        self.original.write(data)
        self.capture.write(data)

    def flush(self):
        self.original.flush()
        self.capture.flush()

    @property
    def encoding(self):
        return getattr(self.original, 'encoding', 'utf-8')


def main():
    FINISH_SIGNALS = [signal.SIGINT, signal.SIGTERM]
    for signal_to_hook in FINISH_SIGNALS:
        signal.signal(signal_to_hook, finish_hook)

    cv.windows = ''
    if platform.system() == 'Windows':
        USER_HOME_DIR = str(Path.home()) + '\\'
        init(convert=True)
        cv.windows = 1
    else:
        USER_HOME_DIR = str(Path.home()) + '/'
        cv.windows = 0

    parser = argparse.ArgumentParser(prog=None, description="Malwoverview is a first response tool for threat hunting written by Alexandre Borges. This version is " + __version__, usage="usage: python malwoverview.py -c <API configuration file> -d <directory> -o <0|1> -v <1-13> -V <virustotal arg> -a <1-17> -A <filename> -l <1-7> -L <hash> -j <1-7> -J <URLhaus argument> -p <1-8> -P <polyswarm argument> -y <1-5> -Y <file name> -n <1-5> -N <argument> -m <1-8> -M <argument> -b <1-12> -B <arg> -x <1-9> -X <arg> --nist <1-5> --NIST <argument> -O <output directory> -ip <1-7> -IP <IP address> -vc <1-8> -VC <argument> -s <1-2> -S <arg> -ab <1> -AB <arg> -gn <1> -GN <arg> -wh <1-2> -WH <arg> -u <1-5> -U <arg> --correlate-hash <hash> --extract-iocs <file> --yara <rules> --yara-target <target> --output-format text|json|csv --proxy <url> --quiet --verbose --no-cache --interactive --attack-map")
    
    malware_group = parser.add_argument_group('MALWARE OPTIONS', 'Malware analysis and intelligence query options')
    malware_group.add_argument('-c', '--config', dest='config', type=str, metavar="CONFIG FILE", default=(USER_HOME_DIR + '.malwapi.conf'), help='Use a custom config file to specify API\'s.')
    malware_group.add_argument('-d', '--directory', dest='direct', type=str, default='', metavar="DIRECTORY", help='Specifies the directory containing malware samples to be checked against VIRUS TOTAL. Use the option -D to decide whether you are being using a public VT API or a Premium VT API.')
    malware_group.add_argument('-o', '--background', dest='backg', type=int, default=1, metavar="BACKGROUND", help='Adapts the output colors to a light background color terminal. The default is dark background color terminal.')
    malware_group.add_argument('-v', '--virustotal_option', dest='virustotaloption', type=int, default=0, metavar="VIRUSTOTAL", help='-v 1: given a file using -V option, it queries the VIRUS TOTAL database (API v.3) to get the report for the given file through -V option.; -v 2: it shows an antivirus report for a given file using -V option (API v.3); -v 3: equal to -v2, but the binary\'s IAT and EAT are also shown (API v.3); -v 4: it extracts the overlay; -v 5: submits an URL to VT scanning; -v 6: submits an IP address to Virus Total; -v 7: this options gets a report on the provided domain from Virus Total; -v 8: verifies a given hash against Virus Total; -v 9: submits a sample to VT (up to 32 MB). Use forward slash to specify the target file on Windows systems. Demands passing sample file with -V option; -v 10: verifies hashes from a provided file through option -V. This option uses public VT API v.3; -v 11: verifies hashes from a provided file through option -V. This option uses Premium API v.3; -v 12: it shows behaviour information of a sample given a hash through option -V. This option uses VT API v.3; -v 13: it submits LARGE files (above 32 MB) to VT using API v.3;')
    malware_group.add_argument('-V', '--virustotal_arg', dest='virustotalarg', type=str, default='', metavar="VIRUSTOTAL_ARG", help='Provides argument for -v option. If "-v 1" to "-v 4" then -V must be a file path; If "-v 5" then -V must be a URL; If "-v 6" then -V must be an IP address; If "-v 7" then -V must be a domain; If "-v 8" then -V must be a hash (MD5/SHA1/SHA256); If "-v 9" or "-v 13" then -V must be a file path to submit; If "-v 10" or "-v 11" then -V must be a file containing hashes (one per line); If "-v 12" then -V must be a hash for behavior analysis.')
    malware_group.add_argument('-a', '--hybrid_option', dest='haoption', type=int, default=0, metavar="HYBRID_ANALYSIS", help='This parameter fetches reports from HYBRID ANALYSIS, download samples and submits samples to be analyzed. The possible values are: 1: gets a report for a given hash or sample from a Windows 7 32-bit environment; 2: gets a report for a given hash or sample from a Windows 7 32-bit environment (HWP Support); 3: gets a report for given hash or sample from a Windows 64-bit environment; 4: gets a report for a given hash or sample from an Android environment; 5: gets a report for a given hash or sample from a Linux 64-bit environment; 6: submits a sample to Windows 7 32-bit environment; 7. submits a sample to Windows 7 32-bit environment with HWP support environment; 8. submits a sample to Windows 7 64-bit environment ; 9. submits a sample to an Android environment ; 10. submits a sample to a Linux 64-bit environment; 11. downloads a sample from a Windows 7 32-bit environment; 12. downloads a sample from a Windows 7 32-bit HWP environment; 13. downloads a sample from a Windows 7 64-bit environment; 14. downloads a sample from an Android environment; 15. downloads a sample from a Linux 64-bit environment; 16. batch hash check from a file (one hash per line); 17. directory scan - computes SHA256 for each file and checks against Hybrid Analysis.')
    malware_group.add_argument('-A', '--ha_arg', dest='haarg', type=str, metavar="SUBMIT_HA", help='Provides argument for -a option from HYBRID ANALYSIS. If "-a 1" to "-a 5" then -A must be a hash or a file path (auto-detected); If "-a 6" to "-a 10" then -A must be a file path to submit; If "-a 11" to "-a 15" then -A must be a hash to download; If "-a 16" then -A must be a file containing hashes (one per line); If "-a 17" then -A must be a directory path to scan.')
    malware_group.add_argument('-D', '--vtpubpremium', dest='vtpubpremium', type=int, default=0, metavar="VT_PUBLIC_PREMIUM", help='This option must be used with -d option. Possible values: <0> it uses the Premium VT API v3 (default); <1> it uses the Public VT API v3.')
    malware_group.add_argument('-l', '--malsharelist', dest='malsharelist', type=int, default=0, metavar="MALSHARE_HASHES", help='This option performs download a sample and shows hashes of a specific type from the last 24 hours from MALSHARE repository. Possible values are: 1: Download a sample; 2: PE32 (default) ; 3: ELF ; 4: Java; 5: PDF ; 6: Composite(OLE); 7: List of hashes from past 24 hours.')
    malware_group.add_argument('-L', '--malshare_hash', dest='malsharehash', type=str, metavar="MALSHARE_HASH_SEARCH", help='Provides a hash as argument for downloading a sample from MALSHARE repository.')
    malware_group.add_argument('-j', '--haus_option', dest='hausoption', type=int, default=0, metavar="HAUS_OPTION", help='This option fetches information from URLHaus depending of the value passed as argument: 1: performs download of the given sample; 2: queries information about a provided hash ; 3: searches information about a given URL; 4: searches a malicious URL by a given tag (case sensitive); 5: searches for payloads given a tag; 6: retrives a list of downloadable links to recent payloads; 7: retrives a list of recent malicious URLs.')
    malware_group.add_argument('-J', '--haus_arg', dest='hausarg', type=str, metavar="HAUS_ARG", help='Provides argument for -j option from URLHaus. If "-j 1" then -J must be a SHA256 hash to download the sample; If "-j 2" then -J must be a hash (MD5/SHA1/SHA256) to search; If "-j 3" then -J must be a URL to check; If "-j 4" then -J must be a tag (case sensitive); If "-j 5" then -J must be a signature name.')
    malware_group.add_argument('-p', '--poly_option', dest='polyoption', type=int, default=0, metavar="POLY_OPTION", help='(Only for Linux) This option is related to POLYSWARM operations: 1. searches information related to a given hash provided using -P option; 2. submits a sample provided by -P option to be analyzed by Polyswarm engine ; 3. Downloads a sample from Polyswarm by providing the hash throught option -P .Attention: Polyswarm enforces a maximum of 20 samples per month; 4. searches for similar samples given a sample file thought option -P; 5. searches for samples related to a provided IP address through option -P; 6. searches for samples related to a given domain provided by option -P; 7. searches for samples related to a provided URL throught option -P; 8. searches for samples related to a provided malware family given by option -P.')
    malware_group.add_argument('-P', '--poly_arg', dest='polyarg', type=str, metavar="POLYSWARM_ARG", help='(Only for Linux) Provides an argument for -p option from POLYSWARM.')
    malware_group.add_argument('-y', '--android_option', dest='androidoption', type=int, default=0, metavar="ANDROID_OPTION", help='This ANDROID option has multiple possible values: <1>: Check all third-party APK packages from the USB-connected Android device against Hybrid Analysis using multithreads. Notes: the Android device does not need to be rooted and the system does need to have the adb tool in the PATH environment variable; <2>: Check all third-party APK packages from the USB-connected Android device against VirusTotal using Public API (slower because of 60 seconds delay for each 4 hashes). Notes: the Android device does not need to be rooted and the system does need to have adb tool in the PATH environment variable; <3>: Check all third-party APK packages from the USB-connected Android device against VirusTotal using multithreads (only for Private Virus API). Notes: the Android device does not need to be rooted and the system needs to have adb tool in the PATH environment variable; <4> Sends an third-party APK from your USB-connected Android device to Hybrid Analysis; 5. Sends an third-party APK from your USB-connected Android device to Virus-Total.')
    malware_group.add_argument('-Y', '--android_arg', dest='androidarg', type=str, default='', metavar="ANDROID_ARG", help='This option provides the argument for -y from ANDROID.')
    malware_group.add_argument('-n', '--alienvault', dest='alienvault', type=int, default=0, metavar="ALIENVAULT", help='Checks multiple information from ALIENVAULT. The possible values are: 1: Get the subscribed pulses ; 2: Get information about an IP address; 3: Get information about a domain; 4: Get information about a hash; 5: Get information about a URL.')
    malware_group.add_argument('-N', '--alienvaultargs', dest='alienvaultargs', type=str, default='', metavar="ALIENVAULT_ARGS", help='Provides argument for -n option from ALIENVAULT. If "-n 1" then -N must be the number of subscribed pulses to retrieve; If "-n 2" then -N must be an IP address; If "-n 3" then -N must be a domain; If "-n 4" then -N must be a hash (MD5/SHA256); If "-n 5" then -N must be a URL.')
    malware_group.add_argument('-m', '--malpedia', dest='malpedia', type=int, default=0, metavar="MALPEDIA", help='This option is related to MALPEDIA and presents different meanings depending on the chosen value. Thus, 1: List meta information for all families ; 2: List all actors ID ; 3: List all available payloads organized by family from Malpedia; 4: Get meta information from an specific actor, so it is necessary to use the -M option. Additionally, try to confirm the correct actor ID by executing malwoverview with option -m 3; 5: List all families IDs; 6: Get meta information from an specific family, so it is necessary to use the -M option. Additionally, try to confirm the correct family ID by executing malwoverview with option -m 5; 7: Get a malware sample from malpedia (zip format -- password: infected). It is necessary to specify the requested hash by using -M option; 8: Get a zip file containing Yara rules for a specific family (get the possible families using -m 5), which must be specified by using -M option.')
    malware_group.add_argument('-M', '--malpediarg', dest='malpediaarg', type=str, default='', metavar="MALPEDIAARG", help='Provides argument for -m option from MALPEDIA. If "-m 4" then -M must be an actor name (confirm with -m 2); If "-m 6" then -M must be a family name (confirm with -m 5); If "-m 7" then -M must be a hash to download the sample; If "-m 8" then -M must be a family name to get YARA rules.')
    malware_group.add_argument('-b', '--bazaar', dest='bazaar', type=int, default=0, metavar="BAZAAR", help='Checks multiple information from MALWARE BAZAAR and THREATFOX. The possible values are: 1: (Bazaar) Query information about a malware hash sample ; 2: (Bazaar) Get information and a list of malware samples associated and according to a specific tag; 3: (Bazaar) Get a list of malware samples according to a given imphash; 4: (Bazaar) Query latest malware samples; 5: (Bazaar) Download a malware sample from Malware Bazaar by providing a SHA256 hash. The downloaded sample is zipped using the following password: infected; 6: (ThreatFox) Get current IOC dataset from last x days given by option -B (maximum of 7 days); 7: (ThreatFox) Search for the specified IOC on ThreatFox given by option -B; 8: (ThreatFox) Search IOCs according to the specified tag given by option -B; 9: (ThreatFox) Search IOCs according to the specified malware family provided by option -B; 10. (ThreatFox) List all available malware families; 11: (Bazaar) Batch hash check from a file (one hash per line); 12: (Bazaar) Directory scan - computes SHA256 for each file and checks against Malware Bazaar.')
    malware_group.add_argument('-B', '--bazaararg', dest='bazaararg', type=str, metavar = "BAZAAR_ARG", help='Provides argument to -b MALWARE BAZAAR and THREAT FOX option. If you specified "-b 1" then the -B\'s argument must be a hash and a report about the sample will be retrieved; If you specified "-b 2" then -B\'s argument must be a malware tag and last samples matching this tag will be shown; If you specified "-b 3" then the argument must be a imphash and last samples matching this impshash will be shown; If you specified "-b 4", so the argument must be "100 or time", where "100" lists last "100 samples" and "time" lists last samples added to Malware Bazaar in the last 60 minutes; If you specified "-b 5", so the sample will be downloaded and -B\'s argument must be a SHA256 hash of the sample that you want to download from Malware Bazaar; If you specified "-b 6" then a list of IOCs will be retrieved and the -B\'s value is the number of DAYS to filter such IOCs. The maximum time is 7 (days); If you used "-b 7" so the -B\'s argument is the IOC you want to search for; If you used "-b 8", so the -B\'s argument is the IOC\'s TAG that you want search for; If you used "-b 9", so the -B argument is the malware family that you want to search for IOCs;')
    malware_group.add_argument('-x', '--triage', dest='triage', type=int, default=0, metavar="TRIAGE", help='Provides information from TRIAGE according to the specified value: <1> this option gets sample\'s general information by providing an argument with -X option in the following possible formats: sha256:<value>, sha1:<value>, md5:<value>, family:<value>, score:<value>, tag:<value>, url:<value>, wallet:<value>, ip:<value>; <2> Get a sumary report for a given Triage ID (got from option -x 1) ; <3> Submit a sample for analysis ; <4> Submit a sample through a URL for analysis ; <5> Download sample specified by the Triage ID; <6> Download pcapng file from sample associated to given Triage ID; <7> Get a dynamic report for the given Triage ID (got from option -x 1); <8> Batch hash check from a file (one hash per line); <9> Directory scan - computes SHA256 for each file and checks against Triage.')
    malware_group.add_argument('-X', '--triagearg', dest='triagearg', type=str, default='', metavar="TRIAGE_ARG", help='Provides argument for -x option from TRIAGE. If "-x 1" then -X must be a search query (e.g., sha256:<hash>, family:<name>, tag:<tag>, ip:<ip>); If "-x 2" then -X must be a Triage sample ID (obtained from -x 1); If "-x 3" then -X must be a file path to submit; If "-x 4" then -X must be a URL to submit; If "-x 5" or "-x 6" then -X must be a Triage sample ID to download; If "-x 7" then -X must be a Triage sample ID for dynamic report; If "-x 8" then -X must be a file containing hashes (one per line); If "-x 9" then -X must be a directory path to scan.')
    malware_group.add_argument('-O', '--output-dir', dest='output_dir', type=str, default='.', help='Set output directory for all sample downloads.')
    malware_group.add_argument('-ip', '--ip', dest='ipoption', type=int, default=0, metavar="IP", help='Get IP information from various sources. The possible values are: 1: Get details for an IP address provided with -IP from IPInfo; 2: Get details for an IP address provided with -IP from BGPView; 3: Get details for an IP address provided with -IP from all available intel services (VirusTotal/Alienvault); 4: Get details from Shodan; 5: Get details from AbuseIPDB; 6: Get details from GreyNoise; 7: Get details from all services (comprehensive).')
    malware_group.add_argument('-IP', '--iparg', dest='iparg', type=str, metavar="IP_ARG", help='Provides an IP address for the -ip option. All -ip options (1 through 7) require a valid IPv4 or IPv6 address.')
    malware_group.add_argument('-s', '--shodan', dest='shodanoption', type=int, default=0, metavar="SHODAN", help='SHODAN options: 1: IP lookup; 2: Search query.')
    malware_group.add_argument('-S', '--shodanarg', dest='shodanarg', type=str, default='', metavar="SHODAN_ARG", help='Provides argument for -s option from SHODAN. If "-s 1" then -S must be an IP address; If "-s 2" then -S must be a search query (e.g., "apache", "port:22 country:BR").')
    malware_group.add_argument('-ab', '--abuseipdb', dest='abuseipdb', type=int, default=0, metavar="ABUSEIPDB", help='ABUSEIPDB options: 1: Check IP reputation.')
    malware_group.add_argument('-AB', '--abuseipdbarg', dest='abuseipdbarg', type=str, default='', metavar="ABUSEIPDB_ARG", help='Provides an IP address for -ab option from ABUSEIPDB.')
    malware_group.add_argument('-gn', '--greynoise', dest='greynoise', type=int, default=0, metavar="GREYNOISE", help='GREYNOISE options: 1: Quick IP check (community API).')
    malware_group.add_argument('-GN', '--greynoisearg', dest='greynoisearg', type=str, default='', metavar="GREYNOISE_ARG", help='Provides an IP address for -gn option from GREYNOISE.')
    malware_group.add_argument('-wh', '--whois', dest='whois', type=int, default=0, metavar="WHOIS", help='WHOIS options: 1: Domain whois lookup; 2: IP whois/RDAP lookup.')
    malware_group.add_argument('-WH', '--whoisarg', dest='whoisarg', type=str, default='', metavar="WHOIS_ARG", help='Provides argument for -wh option from WHOIS. If "-wh 1" then -WH must be a domain name; If "-wh 2" then -WH must be an IP address.')
    malware_group.add_argument('-u', '--urlscanio', dest='urlscanio', type=int, default=0, metavar="URLSCANIO", help='URLSCAN.IO options: 1: Submit a URL for scanning; 2: Get scan result by UUID; 3: Search scans using Elasticsearch query syntax (e.g., "page.server:nginx", "filename:malware.exe", "task.tags:phishing", or a plain keyword); 4: Search scans by domain; 5: Search scans by IP.')
    malware_group.add_argument('-U', '--urlscanioarg', dest='urlscanioarg', type=str, default='', metavar="URLSCANIO_ARG", help='Provides argument for -u option from URLSCAN.IO. If "-u 1" then -U must be a URL to submit for scanning; If "-u 2" then -U must be a UUID (obtained from -u 1); If "-u 3" then -U must be an Elasticsearch query (e.g., "page.server:nginx", "task.tags:phishing"); If "-u 4" then -U must be a domain; If "-u 5" then -U must be an IP address.')
    malware_group.add_argument('--correlate-hash', dest='correlate_hash', type=str, default='', metavar="HASH", help='Cross-service hash correlation: queries a hash across VirusTotal, Hybrid Analysis, Triage, and AlienVault producing a consolidated report.')
    malware_group.add_argument('--extract-iocs', dest='extract_iocs', type=str, default='', metavar="SOURCE", help='Extract IOCs (hashes, IPs, URLs, domains, CVEs) from a file (.txt, .pdf, .eml) or URL (http/https).')
    malware_group.add_argument('--yara', dest='yara_rules', type=str, default='', metavar="RULES_FILE", help='YARA rules file to use for scanning.')
    malware_group.add_argument('--yara-target', dest='yara_target', type=str, default='', metavar="TARGET", help='File or directory to scan with YARA rules.')
    malware_group.add_argument('--attack-map', dest='attack_map', action='store_true', default=False, help='Enable MITRE ATT&CK technique mapping for behavior reports.')
    
    vuln_section = parser.add_argument_group('VULNERABILITY OPTIONS', 'Vulnerability database query options')
    
    nist_group = parser.add_argument_group('  NIST CVE Database Query', 'Query options for NIST CVE database (Query type and value are required; other options are optional)')
    nist_group.add_argument('--nist', dest='nistoption', type=int, default=0, metavar="NIST_OPTION", help='Query type: 1=CPE/Product Search, 2=CVE ID Search, 3=CVSS v3 Severity, 4=Keyword Search, 5=CWE ID Search')
    nist_group.add_argument('--NIST', dest='nistarg', type=str, metavar="NIST_ARG", help='Search value (format depends on query type)')
    nist_group.add_argument('--time', dest='nisttime', type=int, default=None, metavar="YEARS", help='Limit results to last N years')
    nist_group.add_argument('--rpp', dest='nistrpp', type=int, default=100, metavar="NUM", help='Results per page (default: 100, max: 2000)')
    nist_group.add_argument('--startindex', dest='niststartindex', type=int, default=0, metavar="NUM", help='Pagination start index (default: 0)')
    nist_group.add_argument('--ncves', dest='nistncves', type=int, default=None, metavar="NUM", help='Limit output to first N CVEs')
    
    vulncheck_group = parser.add_argument_group('  VulnCheck Database Query', 'Query options for VulnCheck vulnerability database (Community/Free tier)')
    vulncheck_group.add_argument('-vc', '--vulncheck', dest='vulncheckoption', type=int, default=0, metavar="VULNCHECK_OPTION", help='Query type: 1=List available indexes, 2=Get KEV (Known Exploited Vulnerabilities), 3=Search CVE in KEV, 4=Get KEV backup link, 5=List MITRE CVEs, 6=List NIST NVD2 CVEs, 7=Search CVE in MITRE, 8=Search CVE in NIST NVD2')
    vulncheck_group.add_argument('-VC', '--VULNCHECK', dest='vulncheckarg', type=str, metavar="VULNCHECK_ARG", help='Search value (CVE ID for options 3/7/8, max results for options 2/5/6, e.g., 50)')

    general_group = parser.add_argument_group('GENERAL OPTIONS', 'Output format, proxy, cache, and verbosity options')
    general_group.add_argument('--output-format', dest='output_format', type=str, default='text', choices=['text', 'json', 'csv'], help='Output format: text (default, colored terminal), json, or csv.')
    general_group.add_argument('--proxy', dest='proxy', type=str, default='', metavar="URL", help='HTTP/HTTPS/SOCKS5 proxy URL (e.g., socks5://127.0.0.1:9050).')
    general_group.add_argument('--quiet', dest='quiet', action='store_true', default=False, help='Suppress banner and cosmetic output.')
    general_group.add_argument('--verbose', dest='verbose', action='store_true', default=False, help='Show debug information (request URLs, timing, etc.).')
    general_group.add_argument('--no-cache', dest='no_cache', action='store_true', default=False, help='Disable result caching.')
    general_group.add_argument('--cache-ttl', dest='cache_ttl', type=int, default=3600, metavar="SECONDS", help='Cache time-to-live in seconds (default: 3600).')
    general_group.add_argument('--report', dest='report_format', type=str, default='', choices=['', 'html', 'pdf'], help='Generate a report in the specified format.')
    general_group.add_argument('--report-file', dest='report_file', type=str, default='', metavar="PATH", help='Output path for the generated report.')
    general_group.add_argument('--interactive', dest='interactive', action='store_true', default=False, help='Launch interactive REPL mode.')
    general_group.add_argument('--tui', dest='tui', action='store_true', default=False, help='Launch TUI (Text User Interface) dashboard mode. Requires: pip install malwoverview[tui]')
    general_group.add_argument('--enrich', dest='enrich', action='store_true', default=False, help='Enable LLM enrichment of results. Appends an AI-generated threat assessment (risk level, malware family, MITRE ATT&CK TTPs, recommendations) after any query result including malware lookups, IP checks, CVE searches, and correlation. Requires LLM provider configured in .malwapi.conf [LLM] section or --llm flag.')
    general_group.add_argument('--llm', dest='llm_provider', type=str, default='', choices=['claude', 'gemini', 'openai', 'ollama'], metavar="PROVIDER", help='Override LLM provider: claude, gemini, openai, or ollama.')

    subparsers = parser.add_subparsers(dest='command', help='Service subcommands (alternative to flag-based syntax)')

    vt_parser = subparsers.add_parser('vt', help='VirusTotal operations')
    vt_sub = vt_parser.add_subparsers(dest='vt_action')
    vt_file = vt_sub.add_parser('file', help='Check a file (report)')
    vt_file.add_argument('target', help='File path')
    vt_av = vt_sub.add_parser('av', help='AV report for a file')
    vt_av.add_argument('target', help='File path')
    vt_hash = vt_sub.add_parser('hash', help='Check a hash')
    vt_hash.add_argument('target', help='Hash value')
    vt_url = vt_sub.add_parser('url', help='Submit URL for scanning')
    vt_url.add_argument('target', help='URL')
    vt_ip = vt_sub.add_parser('ip', help='Check an IP address')
    vt_ip.add_argument('target', help='IP address')
    vt_domain = vt_sub.add_parser('domain', help='Check a domain')
    vt_domain.add_argument('target', help='Domain name')
    vt_submit = vt_sub.add_parser('submit', help='Submit a sample (up to 32 MB)')
    vt_submit.add_argument('target', help='File path')
    vt_behavior = vt_sub.add_parser('behavior', help='Behavior report for a hash')
    vt_behavior.add_argument('target', help='Hash value')
    vt_batch = vt_sub.add_parser('batch', help='Batch hash check from file')
    vt_batch.add_argument('target', help='File with hashes (one per line)')
    vt_batch.add_argument('--public', action='store_true', help='Use public API (default: premium)')

    ha_parser = subparsers.add_parser('ha', help='Hybrid Analysis operations')
    ha_sub = ha_parser.add_subparsers(dest='ha_action')
    ha_report = ha_sub.add_parser('report', help='Get report for a hash/sample')
    ha_report.add_argument('target', help='Hash or file path')
    ha_report.add_argument('--env', type=int, default=1, choices=[1, 2, 3, 4, 5], help='Environment: 1=Win32, 2=Win32HWP, 3=Win64, 4=Android, 5=Linux64')
    ha_submit = ha_sub.add_parser('submit', help='Submit a sample')
    ha_submit.add_argument('target', help='File path')
    ha_submit.add_argument('--env', type=int, default=1, choices=[1, 2, 3, 4, 5], help='Environment: 1=Win32, 2=Win32HWP, 3=Win64, 4=Android, 5=Linux64')
    ha_download = ha_sub.add_parser('download', help='Download a sample')
    ha_download.add_argument('target', help='Hash value')
    ha_batchhash = ha_sub.add_parser('batch', help='Batch hash check from file')
    ha_batchhash.add_argument('target', help='File with hashes (one per line)')
    ha_dircheck = ha_sub.add_parser('dir', help='Directory scan')
    ha_dircheck.add_argument('target', help='Directory path')

    bz_parser = subparsers.add_parser('bazaar', help='Malware Bazaar operations')
    bz_sub = bz_parser.add_subparsers(dest='bz_action')
    bz_hash = bz_sub.add_parser('hash', help='Query a malware hash')
    bz_hash.add_argument('target', help='Hash value')
    bz_tag = bz_sub.add_parser('tag', help='Search by tag')
    bz_tag.add_argument('target', help='Tag name')
    bz_download = bz_sub.add_parser('download', help='Download a sample')
    bz_download.add_argument('target', help='SHA256 hash')
    bz_batch = bz_sub.add_parser('batch', help='Batch hash check from file')
    bz_batch.add_argument('target', help='File with hashes (one per line)')
    bz_dir = bz_sub.add_parser('dir', help='Directory scan')
    bz_dir.add_argument('target', help='Directory path')

    tr_parser = subparsers.add_parser('triage', help='Triage operations')
    tr_sub = tr_parser.add_subparsers(dest='tr_action')
    tr_search = tr_sub.add_parser('search', help='Search samples')
    tr_search.add_argument('target', help='Search query (e.g. sha256:<value>, family:<value>)')
    tr_summary = tr_sub.add_parser('summary', help='Summary report for a Triage ID')
    tr_summary.add_argument('target', help='Triage ID')
    tr_submit = tr_sub.add_parser('submit', help='Submit a sample')
    tr_submit.add_argument('target', help='File path')
    tr_dynamic = tr_sub.add_parser('dynamic', help='Dynamic report for a Triage ID')
    tr_dynamic.add_argument('target', help='Triage ID')
    tr_batch = tr_sub.add_parser('batch', help='Batch hash check from file')
    tr_batch.add_argument('target', help='File with hashes (one per line)')
    tr_dir = tr_sub.add_parser('dir', help='Directory scan')
    tr_dir.add_argument('target', help='Directory path')

    uh_parser = subparsers.add_parser('urlhaus', help='URLHaus operations')
    uh_sub = uh_parser.add_subparsers(dest='uh_action')
    uh_hash = uh_sub.add_parser('hash', help='Query a hash')
    uh_hash.add_argument('target', help='Hash value')
    uh_url = uh_sub.add_parser('url', help='Search a URL')
    uh_url.add_argument('target', help='URL')
    uh_tag = uh_sub.add_parser('tag', help='Search by tag')
    uh_tag.add_argument('target', help='Tag name')
    uh_download = uh_sub.add_parser('download', help='Download a sample')
    uh_download.add_argument('target', help='Hash value')

    ip_parser = subparsers.add_parser('ip', help='IP address lookups')
    ip_sub = ip_parser.add_subparsers(dest='ip_action')
    ip_info = ip_sub.add_parser('info', help='IPInfo lookup')
    ip_info.add_argument('target', help='IP address')
    ip_bgp = ip_sub.add_parser('bgp', help='BGPView lookup')
    ip_bgp.add_argument('target', help='IP address')
    ip_shodan = ip_sub.add_parser('shodan', help='Shodan lookup')
    ip_shodan.add_argument('target', help='IP address')
    ip_abuse = ip_sub.add_parser('abuse', help='AbuseIPDB lookup')
    ip_abuse.add_argument('target', help='IP address')
    ip_greynoise = ip_sub.add_parser('greynoise', help='GreyNoise lookup')
    ip_greynoise.add_argument('target', help='IP address')
    ip_all = ip_sub.add_parser('all', help='All services lookup')
    ip_all.add_argument('target', help='IP address')

    wh_parser = subparsers.add_parser('whois', help='Whois/RDAP lookups')
    wh_sub = wh_parser.add_subparsers(dest='wh_action')
    wh_domain = wh_sub.add_parser('domain', help='Domain whois lookup')
    wh_domain.add_argument('target', help='Domain name')
    wh_ip = wh_sub.add_parser('ip', help='IP whois/RDAP lookup')
    wh_ip.add_argument('target', help='IP address')

    corr_parser = subparsers.add_parser('correlate', help='Cross-service correlation')
    corr_sub = corr_parser.add_subparsers(dest='corr_action')
    corr_hash = corr_sub.add_parser('hash', help='Hash correlation across services')
    corr_hash.add_argument('target', help='Hash value')

    ext_parser = subparsers.add_parser('extract', help='IOC extraction from files or URLs')
    ext_parser.add_argument('target', help='File (.txt, .pdf, .eml) or URL (http/https) to extract IOCs from')

    yara_parser = subparsers.add_parser('yara', help='YARA rule scanning')
    yara_parser.add_argument('rules', help='YARA rules file')
    yara_parser.add_argument('target', help='File or directory to scan')

    sh_parser = subparsers.add_parser('shodan', help='Shodan operations')
    sh_sub = sh_parser.add_subparsers(dest='sh_action')
    sh_ip = sh_sub.add_parser('ip', help='IP lookup')
    sh_ip.add_argument('target', help='IP address')
    sh_search = sh_sub.add_parser('search', help='Search query')
    sh_search.add_argument('target', help='Search query')

    nist_parser = subparsers.add_parser('nist', help='NIST CVE database queries')
    nist_parser.add_argument('query_type', type=int, choices=[1, 2, 3, 4, 5], help='1=CPE, 2=CVE ID, 3=CVSS Severity, 4=Keyword, 5=CWE ID')
    nist_parser.add_argument('query', help='Search value')
    nist_parser.add_argument('--ncves', type=int, default=None, help='Limit output to first N CVEs')

    vck_parser = subparsers.add_parser('vulncheck', help='VulnCheck database queries')
    vck_parser.add_argument('query_type', type=int, choices=[1, 2, 3, 4, 5, 6, 7, 8], help='Query type (1-8)')
    vck_parser.add_argument('query', nargs='?', default='', help='Search value')

    args = parser.parse_args()

    if args.command == 'vt':
        vt_map = {'file': 1, 'av': 2, 'hash': 8, 'url': 5, 'ip': 6, 'domain': 7, 'submit': 9, 'behavior': 12, 'batch': 10}
        if args.vt_action:
            args.virustotaloption = vt_map.get(args.vt_action, 0)
            args.virustotalarg = args.target
            if args.vt_action == 'batch' and not getattr(args, 'public', False):
                args.virustotaloption = 11
    elif args.command == 'ha':
        if args.ha_action == 'report':
            args.haoption = args.env
            args.haarg = args.target
        elif args.ha_action == 'submit':
            args.haoption = args.env + 5
            args.haarg = args.target
        elif args.ha_action == 'download':
            args.haoption = 11
            args.haarg = args.target
        elif args.ha_action == 'batch':
            args.haoption = 16
            args.haarg = args.target
        elif args.ha_action == 'dir':
            args.haoption = 17
            args.haarg = args.target
    elif args.command == 'bazaar':
        bz_map = {'hash': 1, 'tag': 2, 'download': 5, 'batch': 11, 'dir': 12}
        if args.bz_action:
            args.bazaar = bz_map.get(args.bz_action, 0)
            args.bazaararg = args.target
    elif args.command == 'triage':
        tr_map = {'search': 1, 'summary': 2, 'submit': 3, 'dynamic': 7, 'batch': 8, 'dir': 9}
        if args.tr_action:
            args.triage = tr_map.get(args.tr_action, 0)
            args.triagearg = args.target
    elif args.command == 'urlhaus':
        uh_map = {'download': 1, 'hash': 2, 'url': 3, 'tag': 4}
        if args.uh_action:
            args.hausoption = uh_map.get(args.uh_action, 0)
            args.hausarg = args.target
    elif args.command == 'ip':
        ip_map = {'info': 1, 'bgp': 2, 'shodan': 4, 'abuse': 5, 'greynoise': 6, 'all': 7}
        if args.ip_action:
            args.ipoption = ip_map.get(args.ip_action, 0)
            args.iparg = args.target
    elif args.command == 'whois':
        wh_map = {'domain': 1, 'ip': 2}
        if args.wh_action:
            args.whois = wh_map.get(args.wh_action, 0)
            args.whoisarg = args.target
    elif args.command == 'correlate':
        if args.corr_action == 'hash':
            args.correlate_hash = args.target
    elif args.command == 'extract':
        args.extract_iocs = args.target
    elif args.command == 'yara':
        args.yara_rules = args.rules
        args.yara_target = args.target
    elif args.command == 'shodan':
        sh_map = {'ip': 1, 'search': 2}
        if args.sh_action:
            args.shodanoption = sh_map.get(args.sh_action, 0)
            args.shodanarg = args.target
    elif args.command == 'nist':
        args.nistoption = args.query_type
        args.nistarg = args.query
        if not hasattr(args, 'nistncves') or args.nistncves is None:
            args.nistncves = getattr(args, 'ncves', None)
    elif args.command == 'vulncheck':
        args.vulncheckoption = args.query_type
        args.vulncheckarg = args.query if args.query else None

    cv.output_format = args.output_format
    cv.proxy = args.proxy
    if args.quiet:
        cv.verbosity = -1
    elif args.verbose:
        cv.verbosity = 1
    cv.cache_enabled = not args.no_cache
    cv.cache_ttl = args.cache_ttl
    cv.attack_map = args.attack_map

    if args.interactive:
        from malwoverview.interactive import InteractiveSession
        InteractiveSession(args).cmdloop()
        exit(0)

    if args.tui:
        try:
            from malwoverview.tui import MalwoverviewTUI
        except ImportError:
            print("TUI mode requires the 'textual' package. Install it with: pip install malwoverview[tui]")
            exit(1)
        MalwoverviewTUI(args).run()
        exit(0)

    config_file = configparser.ConfigParser()
    config_file.read(args.config)
    config_dict = config_file

    def getoption(section, name):
        if config_dict.has_option(section,name):
            return config_dict.get(section,name)
        else:
            return ''

    VTAPI = getoption('VIRUSTOTAL', 'VTAPI')
    HAAPI = getoption('HYBRID-ANALYSIS', 'HAAPI')
    MALSHAREAPI = getoption('MALSHARE', 'MALSHAREAPI')
    URLHAUSAPI = getoption('URLHAUS', 'URLHAUSAPI')
    POLYAPI = getoption('POLYSWARM', 'POLYAPI')
    ALIENAPI = getoption('ALIENVAULT', 'ALIENAPI')
    MALPEDIAAPI = getoption('MALPEDIA', 'MALPEDIAAPI')
    TRIAGEAPI = getoption('TRIAGE', 'TRIAGEAPI')
    IPINFOAPI = getoption('IPINFO', 'IPINFOAPI')
    BAZAARAPI = getoption('BAZAAR', 'BAZAARAPI')
    THREATFOXAPI = getoption('THREATFOX', 'THREATFOXAPI')
    VULNCHECKAPI = getoption('VULNCHECK', 'VULNCHECKAPI')
    SHODANAPI = getoption('SHODAN', 'SHODANAPI')
    ABUSEIPDBAPI = getoption('ABUSEIPDB', 'ABUSEIPDBAPI')
    GREYNOISEAPI = getoption('GREYNOISE', 'GREYNOISEAPI')
    URLSCANIOAPI = getoption('URLSCANIO', 'URLSCANIOAPI')

    LLM_PROVIDER = getoption('LLM', 'PROVIDER')
    LLM_CLAUDE_KEY = getoption('LLM', 'CLAUDE_API_KEY')
    LLM_GEMINI_KEY = getoption('LLM', 'GEMINI_API_KEY')
    LLM_GEMINI_MODEL = getoption('LLM', 'GEMINI_MODEL')
    LLM_OPENAI_KEY = getoption('LLM', 'OPENAI_API_KEY')
    LLM_OPENAI_MODEL = getoption('LLM', 'OPENAI_MODEL')
    LLM_OLLAMA_URL = getoption('LLM', 'OLLAMA_URL')
    LLM_OLLAMA_MODEL = getoption('LLM', 'OLLAMA_MODEL')

    optval = range(2)
    optval1 = range(3)
    optval2 = range(5)
    optval3 = range(7)
    optval5 = range(6)
    optval6 = range(9)
    optval7 = range(13)
    optval8 = range(10)
    optval9 = range(14)
    optval10 = range(18)
    repo = args.direct
    cv.output_dir = args.output_dir
    cv.bkg = args.backg
    virustotaloptionx = args.virustotaloption
    haoptionx = args.haoption
    haargx = args.haarg
    vtpubpremiumx = args.vtpubpremium
    mallist = args.malsharelist
    maltype = args.malsharelist
    malhash = args.malsharehash
    hausoptionx = args.hausoption
    hausargx = args.hausarg
    polyoptionx = args.polyoption
    polyargx = args.polyarg
    androidoptionx = args.androidoption
    androidargx = args.androidarg
    alienx = args.alienvault
    alienargsx = args.alienvaultargs
    malpediax = args.malpedia
    malpediaargx = args.malpediaarg
    bazaarx = args.bazaar
    bazaarargx = args.bazaararg
    triagex = args.triage
    triageargx = args.triagearg
    virustotalargx = args.virustotalarg
    ipoptionx = args.ipoption
    ipargx = args.iparg
    nistoption = args.nistoption
    nistarg = args.nistarg
    nisttime = args.nisttime
    nistrpp = args.nistrpp
    niststartindex = args.niststartindex
    nistncves = args.nistncves
    vulncheckoption = args.vulncheckoption
    vulncheckarg = args.vulncheckarg
    config = args.config
    shodanoptionx = args.shodanoption
    shodanargx = args.shodanarg
    abuseipdbx = args.abuseipdb
    abuseipdbargx = args.abuseipdbarg
    greynoisex = args.greynoise
    greynoiseargx = args.greynoisearg
    whoisx = args.whois
    whoisargx = args.whoisarg
    urlscaniox = args.urlscanio
    urlscanioargx = args.urlscanioarg
    correlate_hashx = args.correlate_hash
    extract_iocsx = args.extract_iocs
    yara_rulesx = args.yara_rules
    yara_targetx = args.yara_target

    _CLI_VALIDATORS = {
        'vt_hash':   (virustotaloptionx, virustotalargx, [1, 2, 3, 4, 8, 10, 11, 12], sanitize_hash),
        'vt_url':    (virustotaloptionx, virustotalargx, [5], sanitize_url),
        'vt_ip':     (virustotaloptionx, virustotalargx, [6], sanitize_ip),
        'vt_domain': (virustotaloptionx, virustotalargx, [7], sanitize_domain),
        'vt_path':   (virustotaloptionx, virustotalargx, [9, 13], sanitize_path),
        'ha_hash':   (haoptionx, haargx, list(range(1, 16)), sanitize_hash),
        'ha_path':   (haoptionx, haargx, [6, 7, 8, 9, 10, 16, 17], sanitize_path),
        'bz_hash':   (bazaarx, bazaarargx, [1, 3, 5], sanitize_hash),
        'bz_tag':    (bazaarx, bazaarargx, [2, 8], sanitize_tag),
        'bz_path':   (bazaarx, bazaarargx, [11, 12], sanitize_path),
        'bz_gen':    (bazaarx, bazaarargx, [7, 9], sanitize_general),
        'tr_gen':    (triagex, triageargx, [1], sanitize_general),
        'tr_id':     (triagex, triageargx, [2, 5, 6, 7], sanitize_general),
        'tr_path':   (triagex, triageargx, [3, 8, 9], sanitize_path),
        'tr_url':    (triagex, triageargx, [4], sanitize_url),
        'al_ip':     (alienx, alienargsx, [2], sanitize_ip),
        'al_domain': (alienx, alienargsx, [3], sanitize_domain),
        'al_hash':   (alienx, alienargsx, [4], sanitize_hash),
        'al_url':    (alienx, alienargsx, [5], sanitize_url),
        'mp_hash':   (malpediax, malpediaargx, [7], sanitize_hash),
        'mp_gen':    (malpediax, malpediaargx, [4, 6, 8], sanitize_general),
        'uh_hash':   (hausoptionx, hausargx, [1, 2], sanitize_hash),
        'uh_url':    (hausoptionx, hausargx, [3], sanitize_url),
        'uh_tag':    (hausoptionx, hausargx, [4, 5], sanitize_tag),
        'ip_addr':   (ipoptionx, ipargx, [1, 2, 3, 4, 5, 6, 7], sanitize_ip),
        'sh_ip':     (shodanoptionx, shodanargx, [1], sanitize_ip),
        'sh_gen':    (shodanoptionx, shodanargx, [2], sanitize_general),
        'ab_ip':     (abuseipdbx, abuseipdbargx, [1], sanitize_ip),
        'gn_ip':     (greynoisex, greynoiseargx, [1], sanitize_ip),
        'wh_domain': (whoisx, whoisargx, [1], sanitize_domain),
        'wh_ip':     (whoisx, whoisargx, [2], sanitize_ip),
        'us_url':    (urlscaniox, urlscanioargx, [1], sanitize_url),
        'us_uuid':   (urlscaniox, urlscanioargx, [2], sanitize_uuid),
        'us_gen':    (urlscaniox, urlscanioargx, [3], sanitize_general),
        'us_domain': (urlscaniox, urlscanioargx, [4], sanitize_domain),
        'us_ip':     (urlscaniox, urlscanioargx, [5], sanitize_ip),
        'vc_cve':    (vulncheckoption, vulncheckarg, [3, 7, 8], sanitize_cve),
        'nist_cve':  (nistoption, nistarg, [2], sanitize_cve),
        'nist_gen':  (nistoption, nistarg, [1, 3, 4, 5], sanitize_general),
        'bz_sel':    (bazaarx, bazaarargx, [4], sanitize_general),
        'bz_days':   (bazaarx, bazaarargx, [6], sanitize_general),
    }

    for flag, arg, opts, validator in _CLI_VALIDATORS.values():
        if flag in opts and arg:
            _, err = validator(arg)
            if err:
                print(f"\nInput validation error: {err}")
                exit(1)

    if correlate_hashx:
        _, err = sanitize_hash(correlate_hashx)
        if err:
            print(f"\nInput validation error: {err}")
            exit(1)

    if extract_iocsx and not extract_iocsx.startswith(('http://', 'https://')):
        _, err = sanitize_path(extract_iocsx)
        if err:
            print(f"\nInput validation error: {err}")
            exit(1)

    if yara_rulesx:
        _, err = sanitize_path(yara_rulesx)
        if err:
            print(f"\nInput validation error (--yara): {err}")
            exit(1)

    if yara_targetx:
        _, err = sanitize_path(yara_targetx)
        if err:
            print(f"\nInput validation error (--yara-target): {err}")
            exit(1)

    ffpname = ''
    if (virustotaloptionx in range(1, 5)):
        ffpname = virustotalargx
    if (haoptionx in range(1, 6)):
        ffpname = haargx

    fprovided = 0
    if (os.path.isfile(ffpname)):
        fprovided = 1

    INVALID_ARG_CONDITIONS = [
        args.haoption not in optval10,
        args.alienvault not in optval5,
        args.hausoption not in optval8,
        args.polyoption not in optval6,
        args.bazaar not in optval7,
        args.malpedia not in optval6,
        args.triage not in optval8,
        args.backg not in optval,
        args.malsharelist not in optval8,
        args.virustotaloption not in optval9,
        args.vtpubpremium not in optval,
        args.ipoption not in range(8),
        args.androidoption not in optval5,
        args.shodanoption not in range(3),
        args.abuseipdb not in range(2),
        args.greynoise not in range(3),
        args.whois not in range(3),
        args.urlscanio not in range(6),
    ]

    MIN_OPTIONS = [
        virustotaloptionx in range(5, 10) and virustotalargx,
        virustotaloptionx and virustotalargx, args.direct, fprovided,
        haoptionx and haargx, mallist, args.malsharehash, args.hausoption,
        polyoptionx and polyargx,
        androidoptionx and androidargx, alienx and alienargsx,
        malpediax, bazaarx, triagex and triageargx,
        ipoptionx and ipargx,
        nistoption and nistarg,
        vulncheckoption,
        shodanoptionx and shodanargx,
        abuseipdbx and abuseipdbargx,
        greynoisex and greynoiseargx,
        whoisx and whoisargx,
        urlscaniox and urlscanioargx,
        correlate_hashx,
        extract_iocsx,
        yara_rulesx and yara_targetx,
    ]

    if any(INVALID_ARG_CONDITIONS) or not any(MIN_OPTIONS):
        parser.print_help()
        printr()
        exit(0)

    polyswarm = PolyswarmExtractor(POLYAPI)
    alien = AlienVaultExtractor(ALIENAPI)
    bazaar = BazaarExtractor(BAZAARAPI)
    threatfox = ThreatFoxExtractor(THREATFOXAPI)
    triage = TriageExtractor(TRIAGEAPI)
    malpedia = MalpediaExtractor(MALPEDIAAPI)
    virustotal = VirusTotalExtractor(VTAPI)
    hybrid = HybridAnalysisExtractor(HAAPI)
    malshare = MalshareExtractor(MALSHAREAPI)
    haus = URLHausExtractor(URLHAUSAPI)
    android = AndroidExtractor(hybrid, virustotal)
    ipinfo = IPInfoExtractor(IPINFOAPI)
    bgpview = BGPViewExtractor()
    nist = NISTExtractor()
    vulncheck = VulnCheckExtractor(VULNCHECKAPI)
    shodan_ext = ShodanExtractor(SHODANAPI)
    abuseipdb_ext = AbuseIPDBExtractor(ABUSEIPDBAPI)
    greynoise_ext = GreyNoiseExtractor(GREYNOISEAPI)
    whois_ext = WhoisExtractor()
    urlscanio_ext = URLScanIOExtractor(URLSCANIOAPI)

    llm_enricher = None
    llm_active_provider = args.llm_provider or LLM_PROVIDER
    if args.enrich and llm_active_provider:
        from malwoverview.utils.llm import LLMEnricher
        llm_enricher = LLMEnricher(
            llm_active_provider, LLM_CLAUDE_KEY, LLM_GEMINI_KEY,
            LLM_OLLAMA_URL, LLM_OLLAMA_MODEL, LLM_GEMINI_MODEL,
            LLM_OPENAI_KEY, LLM_OPENAI_MODEL,
        )
        if not llm_enricher.is_configured():
            print(f"\nWarning: LLM provider '{llm_active_provider}' is not configured. "
                  f"Check API key in .malwapi.conf [LLM] section.")
            llm_enricher = None
    elif args.enrich and not llm_active_provider:
        print("\nWarning: --enrich requires a provider. Use --llm claude|gemini|ollama "
              "or set PROVIDER in .malwapi.conf [LLM] section.")
        llm_enricher = None

    multipleip = MultipleIPExtractor(
        {
            "VirusTotal": virustotal,
            "AlienVault": alien,
            "Shodan": shodan_ext,
            "AbuseIPDB": abuseipdb_ext,
            "GreyNoise": greynoise_ext,
        }
    )
    multiplehash = MultipleHashExtractor({
        "VirusTotal": virustotal,
        "HybridAnalysis": hybrid,
        "Triage": triage,
        "AlienVault": alien,
    })

    query = haargx
    if haoptionx in range(6) and haargx and os.path.isfile(haargx):
        query = calchash(haargx)

    def ha_show_and_down(haargx, xx=0):
        hybrid.downhash(haargx)

    OPTIONS_MAPS = [
        {
            'flag': polyoptionx,
            'actions': {
                1: (polyswarm.polyhashsearch, [polyargx, 0]),
                2: (polyswarm.polyfile, [polyargx]),
                3: (polyswarm.polyhashsearch, [polyargx, 1]),
                4: (polyswarm.polymetasearch, [polyargx, polyoptionx]),
                5: (polyswarm.polymetasearch, [polyargx, polyoptionx]),
                6: (polyswarm.polymetasearch, [polyargx, polyoptionx]),
                7: (polyswarm.polymetasearch, [polyargx, polyoptionx]),
                8: (polyswarm.polymetasearch, [polyargx, polyoptionx])
            },
        },
        {
            'flag': alienx,
            'actions': {
                1: (alien.alien_subscribed, [alienargsx]),
                2: (alien.alien_ipv4, [alienargsx]),
                3: (alien.alien_domain, [alienargsx]),
                4: (alien.alien_hash, [alienargsx]),
                5: (alien.alien_url, [alienargsx])
            }
        },
        {
            'flag': bazaarx,
            'actions': {
                1: (bazaar.bazaar_hash, [bazaarargx]),
                2: (bazaar.bazaar_tag, [bazaarargx]),
                3: (bazaar.bazaar_imphash, [bazaarargx]),
                4: (bazaar.bazaar_lastsamples, [bazaarargx]),
                5: (bazaar.bazaar_download, [bazaarargx]),
                11: (bazaar.bazaar_batchcheck, [bazaarargx]),
                12: (bazaar.bazaar_dircheck, [bazaarargx])
            }
        },
        {
            'flag': bazaarx,
            'actions': {
                6: (threatfox.threatfox_listiocs, [bazaarargx]),
                7: (threatfox.threatfox_searchiocs, [bazaarargx]),
                8: (threatfox.threatfox_searchtags, [bazaarargx]),
                9: (threatfox.threatfox_searchmalware, [bazaarargx]),
                10: (threatfox.threatfox_listmalware, [])
            }
        },
        {
            'flag': triagex,
            'actions': {
                1: (triage.triage_search, [triageargx]),
                2: (triage.triage_summary, [triageargx]),
                3: (triage.triage_sample_submit, [triageargx]),
                4: (triage.triage_url_sample_submit, [triageargx]),
                5: (triage.triage_download, [triageargx]),
                6: (triage.triage_download_pcap, [triageargx]),
                7: (triage.triage_dynamic, [triageargx]),
                8: (triage.triage_batchcheck, [triageargx]),
                9: (triage.triage_dircheck, [triageargx])
            }
        },
        {
            'flag': malpediax,
            'actions': {
                1: (malpedia.malpedia_families, []),
                2: (malpedia.malpedia_actors, []),
                3: (malpedia.malpedia_payloads, []),
                4: (malpedia.malpedia_get_actor, [malpediaargx]),
                5: (malpedia.malpedia_families, []),
                6: (malpedia.malpedia_get_family, [malpediaargx]),
                7: (malpedia.malpedia_get_sample, [malpediaargx]),
                8: (malpedia.malpedia_get_yara, [malpediaargx])
            }
        },
        {
            'flag': virustotaloptionx,
            'actions': {
                1: (virustotal.filechecking_v3, [virustotalargx, 0, 0, 0]),
                2: (virustotal.filechecking_v3, [virustotalargx, 1, 0, 0]),
                3: (virustotal.filechecking_v3, [virustotalargx, 1, 1, 0]),
                4: (virustotal.filechecking_v3, [virustotalargx, 1, 0, 1]),
                5: (virustotal.vturlwork, [virustotalargx]),
                6: (virustotal.vtipwork, [virustotalargx]),
                7: (virustotal.vtdomainwork, [virustotalargx]),
                8: (virustotal.vthashwork, [virustotalargx, 1]),
                9: (virustotal.vtuploadfile, [virustotalargx]),
                10: (virustotal.vtbatchcheck, [virustotalargx, 1]),
                11: (virustotal.vtbatchcheck, [virustotalargx, 0]),
                12: (virustotal.vtbehavior, [virustotalargx]),
                13: (virustotal.vtlargefile, [virustotalargx])
            }
        },
        {
            'flag': repo,
            'actions': (virustotal.vtdirchecking, [repo, vtpubpremiumx])
        },
        {
            'flag': haoptionx,
            'actions': {
                1: (hybrid.hashow, [query], {'xx': 0}),
                2: (hybrid.hashow, [query], {'xx': 1}),
                3: (hybrid.hashow, [query], {'xx': 2}),
                4: (hybrid.hashow, [query], {'xx': 3}),
                5: (hybrid.hashow, [query], {'xx': 4}),
                6: (hybrid.hafilecheck, [haargx], {'xx': 0}),
                7: (hybrid.hafilecheck, [haargx], {'xx': 1}),
                8: (hybrid.hafilecheck, [haargx], {'xx': 2}),
                9: (hybrid.hafilecheck, [haargx], {'xx': 3}),
                10: (hybrid.hafilecheck, [haargx], {'xx': 4}),
                11: (ha_show_and_down, [haargx], {'xx': 0}),
                12: (ha_show_and_down, [haargx], {'xx': 1}),
                13: (ha_show_and_down, [haargx], {'xx': 2}),
                14: (ha_show_and_down, [haargx], {'xx': 3}),
                15: (ha_show_and_down, [haargx], {'xx': 4}),
                16: (hybrid.habatchcheck, [haargx]),
                17: (hybrid.habatchdircheck, [haargx])
            }
        },
        {
            'flag': mallist,
            'actions': {
                1: (malshare.malsharedown, [malhash]),
                2: (malshare.malsharelastlist, [maltype]),
                3: (malshare.malsharelastlist, [maltype]),
                4: (malshare.malsharelastlist, [maltype]),
                5: (malshare.malsharelastlist, [maltype]),
                6: (malshare.malsharelastlist, [maltype]),
                7: (malshare.malsharelastlist, [maltype])
            }
        },
        {
            'flag': hausoptionx,
            'actions': {
                1: (haus.haussample, [hausargx]),
                2: (haus.haushashsearch, [hausargx]),
                3: (haus.urlhauscheck, [hausargx]),
                4: (haus.haustagsearchroutine, [hausargx]),
                5: (haus.haussigsearchroutine, [hausargx]),
                6: (haus.hauspayloadslist, []),
                7: (haus.hausgetbatch, [])
            }
        },
        {
            'flag': androidoptionx,
            'actions': {
                1: (android.checkandroid, [1]),
                2: (android.checkandroid, [2]),
                3: (android.checkandroid, [3]),
                4: (android.sendandroidha, [androidargx]),
                5: (android.sendandroidvt, [androidargx])
            }
        },
        {
            'flag': ipoptionx,
            'actions': {
                1: (ipinfo.get_ip_details, [ipargx]),
                2: (bgpview.get_ip_details, [ipargx]),
                3: (multipleip.get_multiple_ip_details, [ipargx]),
                4: (shodan_ext.shodan_ip, [ipargx]),
                5: (abuseipdb_ext.check_ip, [ipargx]),
                6: (greynoise_ext.quick_check, [ipargx]),
                7: (multipleip.get_multiple_ip_details, [ipargx])
            }
        },
        {
            'flag': nistoption,
            'actions': {
                1: (lambda: nist.query_cve(1, nistarg, nistrpp, niststartindex, nisttime), []),
                2: (lambda: nist.query_cve(2, nistarg, nistrpp, niststartindex, nisttime), []),
                3: (lambda: nist.query_cve(3, nistarg, nistrpp, niststartindex, nisttime), []),
                4: (lambda: nist.query_cve(4, nistarg, nistrpp, niststartindex, nisttime), []),
                5: (lambda: nist.query_cve(5, nistarg, nistrpp, niststartindex, nisttime), [])
            },
            'process_results': True
        },
        {
            'flag': vulncheckoption,
            'actions': {
                1: (vulncheck.vulncheck_list_indexes, []),
                2: (vulncheck.vulncheck_kev, [int(vulncheckarg) if vulncheckarg and vulncheckarg.isdigit() else 100]),
                3: (vulncheck.vulncheck_cve_search, [vulncheckarg]),
                4: (vulncheck.vulncheck_backup_kev, []),
                5: (vulncheck.vulncheck_mitre_list, [int(vulncheckarg) if vulncheckarg and vulncheckarg.isdigit() else 100]),
                6: (vulncheck.vulncheck_nist_list, [int(vulncheckarg) if vulncheckarg and vulncheckarg.isdigit() else 100]),
                7: (vulncheck.vulncheck_mitre_search, [vulncheckarg]),
                8: (vulncheck.vulncheck_nist_search, [vulncheckarg])
            }
        },
        {
            'flag': shodanoptionx,
            'actions': {
                1: (shodan_ext.shodan_ip, [shodanargx]),
                2: (shodan_ext.shodan_search, [shodanargx])
            }
        },
        {
            'flag': abuseipdbx,
            'actions': {
                1: (abuseipdb_ext.check_ip, [abuseipdbargx])
            }
        },
        {
            'flag': greynoisex,
            'actions': {
                1: (greynoise_ext.quick_check, [greynoiseargx])
            }
        },
        {
            'flag': whoisx,
            'actions': {
                1: (whois_ext.domain_whois, [whoisargx]),
                2: (whois_ext.ip_whois, [whoisargx])
            }
        },
        {
            'flag': urlscaniox,
            'actions': {
                1: (urlscanio_ext.urlscanio_submit, [urlscanioargx]),
                2: (urlscanio_ext.urlscanio_result, [urlscanioargx]),
                3: (urlscanio_ext.urlscanio_search, [urlscanioargx]),
                4: (urlscanio_ext.urlscanio_domain, [urlscanioargx]),
                5: (urlscanio_ext.urlscanio_ip, [urlscanioargx])
            }
        },
    ]

    if correlate_hashx:
        multiplehash.get_multiple_hash_details(correlate_hashx)
        collector.finalize()
        printr()
        exit(0)

    if extract_iocsx:
        from malwoverview.utils.ioc_extract import IOCExtractor
        ioc_extractor = IOCExtractor()
        ioc_extractor.extract_and_display(extract_iocsx)
        collector.finalize()
        printr()
        exit(0)

    if yara_rulesx and yara_targetx:
        from malwoverview.modules.yara_scan import YaraScanner
        yara_scanner = YaraScanner(yara_rulesx)
        yara_scanner.scan_and_display(yara_targetx)
        collector.finalize()
        printr()
        exit(0)

    for option_map in OPTIONS_MAPS:
        flag = option_map['flag']
        actions = option_map['actions']
        process_results = option_map.get('process_results', False)

        if isinstance(actions, dict) and flag in actions:
            action_obj = actions[flag]
        elif isinstance(actions, tuple) and flag:
            action_obj = actions
        else:
            continue

        import io as _io
        _capture_buf = None
        _orig_stdout = sys.stdout
        if llm_enricher:
            _capture_buf = _io.StringIO()
            sys.stdout = _TeeWriter(_orig_stdout, _capture_buf)

        try:
            if len(action_obj) == 3:
                action, action_args, action_kwargs = action_obj
                result = action(*action_args, **action_kwargs)
            elif len(action_obj) == 2:
                action, action_args = action_obj
                result = action(*action_args)
            elif len(action_obj) == 1:
                action = action_obj[0]
                result = action()
            else:
                continue

            if process_results and result:
                nist.print_results(result, verbose=False, color_scheme=args.backg, max_cves=nistncves)
        finally:
            if _capture_buf:
                sys.stdout = _orig_stdout

        if llm_enricher and _capture_buf:
            captured = _capture_buf.getvalue().strip()
            if captured:
                _prompt_type = 'cve' if (process_results or flag == vulncheckoption) else 'threat'
                llm_enricher.print_enrichment(captured, _prompt_type)

        if cv.output_format != 'text':
            collector.finalize()

        if args.report_format and args.report_file:
            from malwoverview.utils.report import ReportGenerator
            report = ReportGenerator(collector.records, "Malwoverview Report")
            if args.report_format == 'html':
                report.to_html(args.report_file)
            elif args.report_format == 'pdf':
                report.to_pdf(args.report_file)

        printr()
        status = 0
        if result is False:
            status = 1

        exit(status)

if __name__ == "__main__":
    main()
