#!/usr/bin/env python3

# Copyright (C)  2018-2022 Alexandre Borges <alexandreborges@blackstormsecurity.com>
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
# Corey Forman (https://github.com/digitalsleuth)
# Christian Clauss (https://github.com/cclauss)
# Artur Marzano (https://github.com/Macmod)

# Malwoverview.py: version 6.0.0

import os
import argparse
import configparser
import platform
import signal
from colorama import init
from pathlib import Path
from modules.alienvault import AlienVaultExtractor
from modules.android import AndroidExtractor
from modules.bazaar import BazaarExtractor
from modules.hybrid import HybridAnalysisExtractor
from modules.inquest import InQuestExtractor
from modules.malpedia import MalpediaExtractor
from modules.malshare import MalshareExtractor
from modules.polyswarm import PolyswarmExtractor
from modules.threatfox import ThreatFoxExtractor
from modules.triage import TriageExtractor
from modules.urlhaus import URLHausExtractor
from modules.virustotal import VirusTotalExtractor
from utils.colors import printr
from utils.hash import calchash
import modules.configvars as cv


# On Windows systems, it is necessary to install python-magic-bin: pip install python-magic-bin

__author__ = "Alexandre Borges"
__copyright__ = "Copyright 2018-2021, Alexandre Borges"
__license__ = "GNU General Public License v3.0"
__version__ = "5.1.1"
__email__ = "alexandreborges at blackstormsecurity.com"

if __name__ == "__main__":
    def finish_hook(signum, frame):
        printr()
        exit(1)

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

    parser = argparse.ArgumentParser(prog=None, description="Malwoverview is a first response tool for threat hunting written by Alexandre Borges. This version is 6.0.0", usage="python malwoverview.py -c <API configuration file> -d <directory> -o <0|1> -v <1-13> -V <virustotal arg> -a <1-15> -w <0|1> -A <filename> -l <1-6> -L <hash> -j <1-7> -J <URLhaus argument> -p <1-8> -P <polyswarm argument> -y <1-5> -Y <file name> -n <1-5> -N <argument> -m <1-8> -M <argument> -b <1-10> -B <arg> -x <1-7> -X <arg> -i <1-13> -I <INQUEST argument>")
    parser.add_argument('-c', '--config', dest='config', type=str, metavar="CONFIG FILE", default=(USER_HOME_DIR + '.malwapi.conf'), help='Use a custom config file to specify API\'s.')
    parser.add_argument('-d', '--directory', dest='direct', type=str, default='', metavar="DIRECTORY", help='Specifies the directory containing malware samples to be checked against VIRUS TOTAL. Use the option -D to decide whether you are being using a public VT API or a Premium VT API.')
    parser.add_argument('-o', '--background', dest='backg', type=int, default=1, metavar="BACKGROUND", help='Adapts the output colors to a light background color terminal. The default is dark background color terminal.')
    parser.add_argument('-v', '--virustotal_option', dest='virustotaloption', type=int, default=0, metavar="VIRUSTOTAL", help='-v 1: given a file using -V option, it queries the VIRUS TOTAL database (API v.3) to get the report for the given file through -V option.; -v 2: it shows an antivirus report for a given file using -V option (API v.3); -v 3: equal to -v2, but the binary\'s IAT and EAT are also shown (API v.3); -v 4: it extracts the overlay; -v 5: submits an URL to VT scanning; -v 6: submits an IP address to Virus Total; -v 7: this options gets a report on the provided domain from Virus Total; -v 8: verifies a given hash against Virus Total; -v 9: submits a sample to VT (up to 32 MB). Use forward slash to specify the target file on Windows systems. Demands passing sample file with -V option; -v 10: verifies hashes from a provided file through option -V. This option uses public VT API v.3; -v 11: verifies hashes from a provided file through option -V. This option uses Premium API v.3; -v 12: it shows behaviour information of a sample given a hash through option -V. This option uses VT API v.3; -v 13: it submits LARGE files (above 32 MB) to VT using API v.3;')
    parser.add_argument('-V', '--virustotal_arg', dest='virustotalarg', type=str, default='', metavar="VIRUSTOTAL_ARG", help='Provides arguments for -v option.')
    parser.add_argument('-a', '--hybrid_option', dest='haoption', type=int, default=0, metavar="HYBRID_ANALYSIS", help='This parameter fetches reports from HYBRID ANALYSIS, download samples and submits samples to be analyzed. The possible values are: 1: gets a report for a given hash or sample from a Windows 7 32-bit environment; 2: gets a report for a given hash or sample from a Windows 7 32-bit environment (HWP Support); 3: gets a report for given hash or sample from a Windows 64-bit environment; 4: gets a report for a given hash or sample from an Android environment; 5: gets a report for a given hash or sample from a Linux 64-bit environment; 6: submits a sample to Windows 7 32-bit environment; 7. submits a sample to Windows 7 32-bit environment with HWP support environment; 8. submits a sample to Windows 7 64-bit environment ; 9. submits a sample to an Android environment ; 10. submits a sample to a Linux 64-bit environment; 11. downloads a sample from a Windows 7 32-bit environment; 12. downloads a sample from a Windows 7 32-bit HWP environment; 13. downloads a sample from a Windows 7 64-bit environment; 14. downloads a sample from an Android environment; 15. downloads a sample from a Linux 64-bit environment.')
    parser.add_argument('-A', '--ha_arg', dest='haarg', type=str, metavar="SUBMIT_HA", help='Provides an argument for -a option from HYBRID ANALYSIS.')
    parser.add_argument('-D', '--vtpubpremium', dest='vtpubpremium', type=int, default=0, metavar="VT_PUBLIC_PREMIUM", help='This option must be used with -d option. Possible values: <0> it uses the Premium VT API v3 (default); <1> it uses the Public VT API v3.')
    parser.add_argument('-l', '--malsharelist', dest='malsharelist', type=int, default=0, metavar="MALSHARE_HASHES", help='This option performs download a sample and shows hashes of a specific type from the last 24 hours from MALSHARE repository. Possible values are: 1: Download a sample; 2: PE32 (default) ; 3: ELF ; 4: Java; 5: PDF ; 6: Composite(OLE).')
    parser.add_argument('-L', '--malshare_hash', dest='malsharehash', type=str, metavar="MALSHARE_HASH_SEARCH", help='Provides a hash as argument for downloading a sample from MALSHARE repository.')
    parser.add_argument('-j', '--haus_option', dest='hausoption', type=int, default=0, metavar="HAUS_OPTION", help='This option fetches information from URLHaus depending of the value passed as argument: 1: performs download of the given sample; 2: queries information about a provided hash ; 3: searches information about a given URL; 4: searches a malicious URL by a given tag (case sensitive); 5: searches for payloads given a tag; 6: retrives a list of downloadable links to recent payloads; 7: retrives a list of recent malicious URLs.')
    parser.add_argument('-J', '--haus_arg', dest='hausarg', type=str, metavar="HAUS_ARG", help='Provides argument to -j option from URLHaus.')
    parser.add_argument('-p', '--poly_option', dest='polyoption', type=int, default=0, metavar="POLY_OPTION", help='(Only for Linux) This option is related to POLYSWARM operations: 1. searches information related to a given hash provided using -P option; 2. submits a sample provided by -P option to be analyzed by Polyswarm engine ; 3. Downloads a sample from Polyswarm by providing the hash throught option -P .Attention: Polyswarm enforces a maximum of 20 samples per month; 4. searches for similar samples given a sample file thought option -P; 5. searches for samples related to a provided IP address through option -P; 6. searches for samples related to a given domain provided by option -P; 7. searches for samples related to a provided URL throught option -P; 8. searches for samples related to a provided malware family given by option -P.')
    parser.add_argument('-P', '--poly_arg', dest='polyarg', type=str, metavar="POLYSWARM_ARG", help='(Only for Linux) Provides an argument for -p option from POLYSWARM.')
    parser.add_argument('-y', '--android_option', dest='androidoption', type=int, default=0, metavar="ANDROID_OPTION", help='This ANDROID option has multiple possible values: <1>: Check all third-party APK packages from the USB-connected Android device against Hybrid Analysis using multithreads. Notes: the Android device does not need to be rooted and the system does need to have the adb tool in the PATH environment variable; <2>: Check all third-party APK packages from the USB-connected Android device against VirusTotal using Public API (slower because of 60 seconds delay for each 4 hashes). Notes: the Android device does not need to be rooted and the system does need to have adb tool in the PATH environment variable; <3>: Check all third-party APK packages from the USB-connected Android device against VirusTotal using multithreads (only for Private Virus API). Notes: the Android device does not need to be rooted and the system needs to have adb tool in the PATH environment variable; <4> Sends an third-party APK from your USB-connected Android device to Hybrid Analysis; 5. Sends an third-party APK from your USB-connected Android device to Virus-Total.')
    parser.add_argument('-Y', '--android_arg', dest='androidarg', type=str, default='', metavar="ANDROID_ARG", help='This option provides the argument for -y from ANDROID.')
    parser.add_argument('-n', '--alienvault', dest='alienvault', type=int, default=0, metavar="ALIENVAULT", help='Checks multiple information from ALIENVAULT. The possible values are: 1: Get the subscribed pulses ; 2: Get information about an IP address; 3: Get information about a domain; 4: Get information about a hash; 5: Get information about a URL.')
    parser.add_argument('-N', '--alienvaultargs', dest='alienvaultargs', type=str, default='', metavar="ALIENVAULT_ARGS", help='Provides argument to ALIENVAULT -n option.')
    parser.add_argument('-m', '--malpedia', dest='malpedia', type=int, default=0, metavar="MALPEDIA", help='This option is related to MALPEDIA and presents different meanings depending on the chosen value. Thus, 1: List meta information for all families ; 2: List all actors ID ; 3: List all available payloads organized by family from Malpedia; 4: Get meta information from an specific actor, so it is necessary to use the -M option. Additionally, try to confirm the correct actor ID by executing malwoverview with option -m 3; 5: List all families IDs; 6: Get meta information from an specific family, so it is necessary to use the -M option. Additionally, try to confirm the correct family ID by executing malwoverview with option -m 5; 7: Get a malware sample from malpedia (zip format -- password: infected). It is necessary to specify the requested hash by using -M option; 8: Get a zip file containing Yara rules for a specific family (get the possible families using -m 5), which must be specified by using -M option.')
    parser.add_argument('-M', '--malpediarg', dest='malpediaarg', type=str, default='', metavar="MALPEDIAARG", help='This option provides an argument to the -m option, which is related to MALPEDIA.')
    parser.add_argument('-b', '--bazaar', dest='bazaar', type=int, default=0, metavar="BAZAAR", help='Checks multiple information from MALWARE BAZAAR and THREATFOX. The possible values are: 1: (Bazaar) Query information about a malware hash sample ; 2: (Bazaar) Get information and a list of malware samples associated and according to a specific tag; 3: (Bazaar) Get a list of malware samples according to a given imphash; 4: (Bazaar) Query latest malware samples; 5: (Bazaar) Download a malware sample from Malware Bazaar by providing a SHA256 hash. The downloaded sample is zipped using the following password: infected; 6: (ThreatFox) Get current IOC dataset from last x days given by option -B (maximum of 7 days); 7: (ThreatFox) Search for the specified IOC on ThreatFox given by option -B; 8: (ThreatFox) Search IOCs according to the specified tag given by option -B; 9: (ThreatFox) Search IOCs according to the specified malware family provided by option -B; 10. (ThreatFox) List all available malware families.')
    parser.add_argument('-B', '--bazaararg', dest='bazaararg', type=str, default='', metavar="BAZAAR_ARG", help='Provides argument to -b MALWARE BAZAAR and THREAT FOX option. If you specified "-b 1" then the -B\'s argument must be a hash; If you specified "-b 2" then -B\'s argument must be a malware tag; If you specified "-b 3" then the argument must be a imphash; If you specified "-b 4", so the argument must be "100 or time", where "100" lists last "100 samples" and "time" lists last samples added to Malware Bazaar in the last 60 minutes; If you specified "-b 5" then the -B\'s argument must be a SHA256 hash; If you specified "-b 6", so the -B\'s value is the number of DAYS to filter IOCs. The maximum is 7 (days); If you used "-b 7" so the -B\'s argument is the IOC you want to search for; If you used "-b 8", so the -B\'s argument is the TAG you want search for; If you used "-b 9", so the -B argument is the malware family you want to search for;')
    parser.add_argument('-x', '--triage', dest='triage', type=int, default=0, metavar="TRIAGE", help='Provides information from TRIAGE according to the specified value: <1> this option gets sample\'s general information by providing an argument with -X option in the following possible formats: sha256:<value>, sha1:<value>, md5:<value>, family:<value>, score:<value>, tag:<value>, url:<value>, wallet:<value>, ip:<value>; <2> Get a sumary report for a given Triage ID (got from option -x 1) ; <3> Submit a sample for analysis ; <4> Submit a sample through a URL for analysis ; <5> Download sample specified by the Triage ID; <6> Download pcapng file from sample associated to given Triage ID; <7> Get a dynamic report for the given Triage ID (got from option -x 1);')
    parser.add_argument('-X', '--triagearg', dest='triagearg', type=str, default='', metavar="TRIAGE_ARG", help='Provides argument for options especified by -x option. Pay attention: the format of this argument depends on provided -x value.')
    parser.add_argument('-i', '--inquest', dest='inquest', type=int, default=0, metavar="INQUEST", help='Retrieves multiple information from INQUEST. The possible values are: 1: Downloads a sample; 2: Retrives information about a sample given a SHA256; 3: Retrieves information about a sample given a MD5 hash; 4: Gets the most recent list of threats. To this option, the -I argument must be "list" (lowercase and without double quotes) ; 5: Retrives threats related to a provided domain; 6. Retrieves a list of samples related to the given IP address; 7. Retrives a list of sample related to the given e-mail address; 8. Retrieves a list of samples related to the given filename; 9. Retrieves a list of samples related to a given URL; 10. Retrieves information about a specified IOC; 11. List a list of IOCs. Note: you must pass "list" (without double quotes) as argument to -I; 12. Check for a given keyword in the reputation database; 13. List artifacts in the reputation dabatabse. Note: you must pass "list" (without double quotes) as argument to -I.')
    parser.add_argument('-I', '--inquestarg', dest='inquestarg', type=str, metavar="INQUEST_ARG", help='Provides argument to INQUEST -i option.')

    args = parser.parse_args()

    config_file = configparser.ConfigParser()
    config_file.read(args.config)
    config_dict = config_file
    VTAPI = config_dict.get('VIRUSTOTAL', 'VTAPI')
    HAAPI = config_dict.get('HYBRID-ANALYSIS', 'HAAPI')
    MALSHAREAPI = config_dict.get('MALSHARE', 'MALSHAREAPI')
    HAUSSUBMITAPI = config_dict.get('HAUSSUBMIT', 'HAUSSUBMITAPI')
    POLYAPI = config_dict.get('POLYSWARM', 'POLYAPI')
    ALIENAPI = config_dict.get('ALIENVAULT', 'ALIENAPI')
    MALPEDIAAPI = config_dict.get('MALPEDIA', 'MALPEDIAAPI')
    TRIAGEAPI = config_dict.get('TRIAGE', 'TRIAGEAPI')
    INQUESTAPI = config_dict.get('INQUEST', 'INQUESTAPI')

    optval = range(2)
    optval1 = range(3)
    optval2 = range(5)
    optval3 = range(7)
    optval4 = range(4)
    optval5 = range(6)
    optval6 = range(9)
    optval7 = range(11)
    optval8 = range(8)
    optval9 = range(14)
    optval10 = range(16)
    repo = args.direct
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
    inquestx = args.inquest
    inquestargx = args.inquestarg
    config = args.config

    ffpname = ''
    if (virustotaloptionx in range(1, 5)):
        ffpname = virustotalargx
    if (haoptionx in range(1, 6)):
        ffpname = haargx

    fprovided = 0
    if (os.path.isfile(ffpname)):
        fprovided = 1

    INVALID_ARG_CONDITIONS = [
#        (virustotaloptionx in range(1, 5) or haoptionx in range(1, 6)) and fprovided == 0,
        args.haoption not in optval10,
        args.alienvault not in optval5,
        args.hausoption not in optval8,
        args.polyoption not in optval6,
        args.bazaar not in optval7,
        args.malpedia not in optval6,
        args.triage not in optval8,
        args.inquest not in optval9,
        args.backg not in optval,
        args.malsharelist not in optval3,
        args.virustotaloption not in optval9,
        args.vtpubpremium not in optval
    ]

    MIN_OPTIONS = [
        virustotaloptionx in range(5, 10) and virustotalargx,
        virustotalargx, virustotaloptionx, args.direct, fprovided,
        haargx, mallist, args.malsharehash, args.hausoption, polyoptionx, polyargx,
        androidoptionx, androidargx, alienx, alienargsx, malpediaargx,
        malpediax, bazaarx, bazaarargx, triagex, triageargx,
        inquestx, inquestargx
    ]

    # Show the help message if:
    # 1 - User uses invalid arg values
    # 2 - User does not specify any of the minimum options required
    if any(INVALID_ARG_CONDITIONS) or not any(MIN_OPTIONS):
        parser.print_help()
        printr()
        exit(0)

    # Module objects
    polyswarm = PolyswarmExtractor(POLYAPI)
    alien = AlienVaultExtractor(ALIENAPI)
    bazaar = BazaarExtractor()
    threatfox = ThreatFoxExtractor()
    triage = TriageExtractor(TRIAGEAPI)
    inquest = InQuestExtractor(INQUESTAPI)
    malpedia = MalpediaExtractor(MALPEDIAAPI)
    virustotal = VirusTotalExtractor(VTAPI)
    hybrid = HybridAnalysisExtractor(HAAPI)
    malshare = MalshareExtractor(MALSHAREAPI)
    haus = URLHausExtractor(HAUSSUBMITAPI)
    android = AndroidExtractor(hybrid, virustotal)

    # Special parameters for hybrid analysis module
    query = haargx
    if haoptionx in range(6) and haargx and os.path.isfile(haargx):
        query = calchash(haargx)

    def ha_show_and_down(haargx, xx=0):
        hybrid.hashow(haargx, xx=xx)
        hybrid.downhash(haargx)

    # Map from flags to actions that they specify
    # and parameters to be used with each method call
    OPTIONS_MAPS = [
        {
            'flag': polyoptionx,
            'actions': {
                1: (polyswarm.polyhashsearch, [polyargx, 0]),
                2: (polyswarm.polyhashsearch, [polyargx, 1]),
                3: (polyswarm.polyfile, [polyargx]),
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
                5: (bazaar.bazaar_download, [bazaarargx])
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
                7: (triage.triage_dynamic, [triageargx])
            }
        },
        {
            'flag': inquestx,
            'actions': {
                1: (inquest.inquest_download, [inquestargx]),
                2: (inquest.inquest_hash, [inquestargx]),
                3: (inquest.inquest_hash_md5, [inquestargx]),
                4: (inquest.inquest_list, [inquestargx]),
                5: (inquest.inquest_domain, [inquestargx]),
                6: (inquest.inquest_ip, [inquestargx]),
                7: (inquest.inquest_email, [inquestargx]),
                8: (inquest.inquest_filename, [inquestargx]),
                9: (inquest.inquest_url, [inquestargx]),
                10: (inquest.inquest_ioc_search, [inquestargx]),
                11: (inquest.inquest_ioc_list, [inquestargx]),
                12: (inquest.inquest_rep_search, [inquestargx]),
                13: (inquest.inquest_rep_list, [inquestargx])
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
                15: (ha_show_and_down, [haargx], {'xx': 4})
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
                6: (malshare.malsharelastlist, [maltype])
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
        }
    ]

    # Dispatch the first selected action with the specified parameters
    for option_map in OPTIONS_MAPS:
        flag = option_map['flag']
        actions = option_map['actions']

        if isinstance(actions, dict) and flag in actions:
            action_obj = actions[flag]
        elif isinstance(actions, tuple) and flag:
            action_obj = actions
        else:
            continue

        # If flag conditions are met, then call the appropriate function with its parameters
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

        printr()
        status = 0
        if result is False:
            status = 1

        exit(status)
