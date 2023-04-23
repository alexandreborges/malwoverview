import modules.configvars as cv
from datetime import datetime
from utils.colors import mycolors, printr
from utils.hash import sha256hash
from utils.peinfo import ftype, isoverlay, overextract, list_imports_exports
import geocoder
import validators
import requests
import base64
import textwrap
import json
import time
import re
import os


class VirusTotalExtractor():
    urlfilevt3 = 'https://www.virustotal.com/api/v3/files'
    urlurlvt3 = 'https://www.virustotal.com/api/v3/urls'
    urlipvt3 = 'https://www.virustotal.com/api/v3/ip_addresses'
    urldomainvt3 = 'https://www.virustotal.com/api/v3/domains'
    AV_LIST = [
        "AlienVault", "BitDefender", "Avira", "Comodo Valkyrie Verdict", "CyRadar",
        "Dr.Web", "Emsisoft", "ESET", "Forcepoint ThreatSeeker", "Fortinet", "G-Data",
        "Google Safebrowsing", "Kaspersky", "MalwarePatrol", "OpenPhish", "PhishLabs",
        "Phishtank", "Spamhaus", "Sophos", "Sucuri SiteCheck", "Trustwave", "URLhaus",
        "VX Vault", "Webroot"
    ]

    def __init__(self, VTAPI):
        self.VTAPI = VTAPI

    def filechecking_v3(self, ffpname2, showreport, impexp, ovrly):
        if not ffpname2 or not os.path.isfile(ffpname2):
            if cv.bkg == 0:
                print(mycolors.foreground.red + "\nYou didn't provide a valid file.\n")
            else:
                print(mycolors.foreground.yellow + "\nYou didn't provide a valid file.\n")
            return False

        targetfile = ffpname2
        mysha256hash = ''
        dname = str(os.path.dirname(targetfile))
        if not os.path.abspath(dname):
            dname = os.path.abspath('.') + "/" + dname

        try:
            mysha256hash = sha256hash(targetfile)

            magictype = ftype(targetfile)
            if re.match(r'^PE[0-9]{2}|^MS-DOS', magictype):
                ret_overlay = isoverlay(targetfile)

            if (showreport == 0):
                self.vthashwork(mysha256hash, showreport)

                if re.match(r'^PE[0-9]{2}|^MS-DOS', magictype):
                    if (cv.bkg == 1):
                        print(mycolors.foreground.lightred + "Overlay: ".ljust(21) + mycolors.reset + ret_overlay, end='\n')
                if re.match(r'^PE[0-9]{2}|^MS-DOS', magictype):
                    if (cv.bkg == 0):
                        print(mycolors.foreground.red + "Overlay: ".ljust(21) + mycolors.reset + ret_overlay, end='\n')
            else:
                self.vtreportwork(mysha256hash, 1)

                if re.match(r'^PE[0-9]{2}|^MS-DOS', magictype):
                    if (cv.bkg == 1):
                        print(mycolors.foreground.lightred + "Overlay: ".ljust(21) + mycolors.reset + ret_overlay, end='\n')
                if re.match(r'^PE[0-9]{2}|^MS-DOS', magictype):
                    if (cv.bkg == 0):
                        print(mycolors.foreground.red + "Overlay: ".ljust(21) + mycolors.reset + ret_overlay, end='\n')
            if (impexp == 1):
                list_imports_exports(targetfile)
            if (ovrly == 1):
                overextract(targetfile)
        except (AttributeError, NameError) as e:
            print(e)
            if (cv.bkg == 1):
                print((mycolors.foreground.yellow + "\nAn error has occured while handling the %s file.\n" % targetfile))
                pass
            else:
                print((mycolors.foreground.red + "\nAn error has occured while handling the %s file.\n" % targetfile))
            printr()
            exit(1)

    def vtcheck(self, myhash, showreport):
        url = VirusTotalExtractor.urlfilevt3

        try:
            finalurl = ''.join([url, "/", myhash])
            requestsession = requests.Session()
            requestsession.headers.update({'x-apikey': self.VTAPI})
            requestsession.headers.update({'content-type': 'application/json'})
            response = requestsession.get(finalurl)
            vttext = json.loads(response.text)

            if (response.status_code == 404):
                final = " NOT FOUND"
            else:
                attrs = vttext.get('data', {}).get('attributes', {})
                if ('last_analysis_stats' in attrs):
                    malicious = attrs['last_analysis_stats']['malicious']
                    undetected = attrs['last_analysis_stats']['undetected']
                    final = (str(malicious) + "/" + str(malicious + undetected))

            return final
        except ValueError:
            final = '     '
            return final

    def vt_url_ip_domain_report_dark(self, vttext):
        print(mycolors.foreground.lightred + "\n\nAV Report:", end='')

        attrs = vttext.get('data', {}).get('attributes', {})
        if ('last_analysis_results' in attrs):
            ok = "CLEAN"
            if ('AlienVault' in attrs['last_analysis_results']):
                result = attrs['last_analysis_results']['AlienVault']['result']
                if (result):
                    print(mycolors.foreground.lightcyan + "\n".ljust(26) + "AlienVault: ".ljust(15) + mycolors.reset + result, end='')
                else:
                    print(mycolors.foreground.lightcyan + "\n".ljust(26) + "AlienVault: ".ljust(15) + mycolors.reset + ok, end='')
            if ('BitDefender' in attrs['last_analysis_results']):
                result = attrs['last_analysis_results']['BitDefender']['result']
                if (result):
                    print(mycolors.foreground.lightcyan + "\n".ljust(26) + "BitDefender: ".ljust(15) + mycolors.reset + result, end='')
                else:
                    print(mycolors.foreground.lightcyan + "\n".ljust(26) + "BitDefender: ".ljust(15) + mycolors.reset + ok, end='')
            if ('Avira' in attrs['last_analysis_results']):
                result = attrs['last_analysis_results']['Avira']['result']
                if (result):
                    print(mycolors.foreground.lightcyan + "\n".ljust(26) + "Avira: ".ljust(15) + mycolors.reset + result, end='')
                else:
                    print(mycolors.foreground.lightcyan + "\n".ljust(26) + "Avira: ".ljust(15) + mycolors.reset + ok, end='')
            if ('Comodo Valkyrie Verdict' in attrs['last_analysis_results']):
                result = attrs['last_analysis_results']['Comodo Valkyrie Verdict']['result']
                if (result):
                    print(mycolors.foreground.lightcyan + "\n".ljust(26) + "Comodo: ".ljust(15) + mycolors.reset + result, end='')
                else:
                    print(mycolors.foreground.lightcyan + "\n".ljust(26) + "Comodo: ".ljust(15) + mycolors.reset + ok, end='')
            if ('CyRadar' in attrs['last_analysis_results']):
                result = attrs['last_analysis_results']['CyRadar']['result']
                if (result):
                    print(mycolors.foreground.lightcyan + "\n".ljust(26) + "CyRadar: ".ljust(15) + mycolors.reset + result, end='')
                else:
                    print(mycolors.foreground.lightcyan + "\n".ljust(26) + "CyRadar: ".ljust(15) + mycolors.reset + ok, end='')
            if ('Dr.Web' in attrs['last_analysis_results']):
                result = attrs['last_analysis_results']['Dr.Web']['result']
                if (result):
                    print(mycolors.foreground.lightcyan + "\n".ljust(26) + "Dr.Web: ".ljust(15) + mycolors.reset + result, end='')
                else:
                    print(mycolors.foreground.lightcyan + "\n".ljust(26) + "Dr.Web: ".ljust(15) + mycolors.reset + ok, end='')
            if ('Emsisoft' in attrs['last_analysis_results']):
                result = attrs['last_analysis_results']['Emsisoft']['result']
                if (result):
                    print(mycolors.foreground.lightcyan + "\n".ljust(26) + "Emsisoft: ".ljust(15) + mycolors.reset + result, end='')
                else:
                    print(mycolors.foreground.lightcyan + "\n".ljust(26) + "Emsisoft: ".ljust(15) + mycolors.reset + ok, end='')
            if ('ESET' in attrs['last_analysis_results']):
                result = attrs['last_analysis_results']['ESET']['result']
                if (result):
                    print(mycolors.foreground.lightcyan + "\n".ljust(26) + "ESET: ".ljust(15) + mycolors.reset + result, end='')
                else:
                    print(mycolors.foreground.lightcyan + "\n".ljust(26) + "ESET: ".ljust(15) + mycolors.reset + ok, end='')
            if ('Forcepoint ThreatSeeker' in attrs['last_analysis_results']):
                result = attrs['last_analysis_results']['Forcepoint ThreatSeeker']['result']
                if (result):
                    print(mycolors.foreground.lightcyan + "\n".ljust(26) + "Forcepoint: ".ljust(15) + mycolors.reset + result, end='')
                else:
                    print(mycolors.foreground.lightcyan + "\n".ljust(26) + "Forcepoint: ".ljust(15) + mycolors.reset + ok, end='')
            if ('Fortinet' in attrs['last_analysis_results']):
                result = attrs['last_analysis_results']['Fortinet']['result']
                if (result):
                    print(mycolors.foreground.lightcyan + "\n".ljust(26) + "Fortinet: ".ljust(15) + mycolors.reset + result, end='')
                else:
                    print(mycolors.foreground.lightcyan + "\n".ljust(26) + "Fortinet: ".ljust(15) + mycolors.reset + ok, end='')
            if ('G-Data' in attrs['last_analysis_results']):
                result = attrs['last_analysis_results']['G-Data']['result']
                if (result):
                    print(mycolors.foreground.lightcyan + "\n".ljust(26) + "G-Data: ".ljust(15) + mycolors.reset + result, end='')
                else:
                    print(mycolors.foreground.lightcyan + "\n".ljust(26) + "G-Data: ".ljust(15) + mycolors.reset + ok, end='')
            if ('Google Safebrowsing' in attrs['last_analysis_results']):
                result = attrs['last_analysis_results']['Google Safebrowsing']['result']
                if (result):
                    print(mycolors.foreground.lightcyan + "\n".ljust(26) + "Google: ".ljust(15) + mycolors.reset + result, end='')
                else:
                    print(mycolors.foreground.lightcyan + "\n".ljust(26) + "Google: ".ljust(15) + mycolors.reset + ok, end='')
            if ('Kaspersky' in attrs['last_analysis_results']):
                result = attrs['last_analysis_results']['Kaspersky']['result']
                if (result):
                    print(mycolors.foreground.lightcyan + "\n".ljust(26) + "Kaspersky: ".ljust(15) + mycolors.reset + result, end='')
                else:
                    print(mycolors.foreground.lightcyan + "\n".ljust(26) + "Kaspersky: ".ljust(15) + mycolors.reset + ok, end='')
            if ('MalwarePatrol' in attrs['last_analysis_results']):
                result = attrs['last_analysis_results']['MalwarePatrol']['result']
                if (result):
                    print(mycolors.foreground.lightcyan + "\n".ljust(26) + "MalwarePatrol: ".ljust(15) + mycolors.reset + result, end='')
                else:
                    print(mycolors.foreground.lightcyan + "\n".ljust(26) + "MalwarePatrol: ".ljust(15) + mycolors.reset + ok, end='')
            if ('OpenPhish' in attrs['last_analysis_results']):
                result = attrs['last_analysis_results']['OpenPhish']['result']
                if (result):
                    print(mycolors.foreground.lightcyan + "\n".ljust(26) + "OpenPhish: ".ljust(15) + mycolors.reset + result, end='')
                else:
                    print(mycolors.foreground.lightcyan + "\n".ljust(26) + "OpenPhish: ".ljust(15) + mycolors.reset + ok, end='')
            if ('PhishLabs' in attrs['last_analysis_results']):
                result = attrs['last_analysis_results']['PhishLabs']['result']
                if (result):
                    print(mycolors.foreground.lightcyan + "\n".ljust(26) + "PhishLabs: ".ljust(15) + mycolors.reset + result, end='')
                else:
                    print(mycolors.foreground.lightcyan + "\n".ljust(26) + "PhishLabs: ".ljust(15) + mycolors.reset + ok, end='')
            if ('Phishtank' in attrs['last_analysis_results']):
                result = attrs['last_analysis_results']['Phishtank']['result']
                if (result):
                    print(mycolors.foreground.lightcyan + "\n".ljust(26) + "Phishtank: ".ljust(15) + mycolors.reset + result, end='')
                else:
                    print(mycolors.foreground.lightcyan + "\n".ljust(26) + "Phishtank: ".ljust(15) + mycolors.reset + ok, end='')
            if ('Spamhaus' in attrs['last_analysis_results']):
                result = attrs['last_analysis_results']['Spamhaus']['result']
                if (result):
                    print(mycolors.foreground.lightcyan + "\n".ljust(26) + "Spamhaus: ".ljust(15) + mycolors.reset + result, end='')
                else:
                    print(mycolors.foreground.lightcyan + "\n".ljust(26) + "Spamhaus: ".ljust(15) + mycolors.reset + ok, end='')
            if ('Sophos' in attrs['last_analysis_results']):
                result = attrs['last_analysis_results']['Sophos']['result']
                if (result):
                    print(mycolors.foreground.lightcyan + "\n".ljust(26) + "Sophos: ".ljust(15) + mycolors.reset + result, end='')
                else:
                    print(mycolors.foreground.lightcyan + "\n".ljust(26) + "Sophos: ".ljust(15) + mycolors.reset + ok, end='')
            if ('Sucuri SiteCheck' in attrs['last_analysis_results']):
                result = attrs['last_analysis_results']['Sucuri SiteCheck']['result']
                if (result):
                    print(mycolors.foreground.lightcyan + "\n".ljust(26) + "Sucuri: ".ljust(15) + mycolors.reset + result, end='')
                else:
                    print(mycolors.foreground.lightcyan + "\n".ljust(26) + "Sucuri: ".ljust(15) + mycolors.reset + ok, end='')
            if ('Trustwave' in attrs['last_analysis_results']):
                result = attrs['last_analysis_results']['Trustwave']['result']
                if (result):
                    print(mycolors.foreground.lightcyan + "\n".ljust(26) + "Trustwave: ".ljust(15) + mycolors.reset + result, end='')
                else:
                    print(mycolors.foreground.lightcyan + "\n".ljust(26) + "Trustwave: ".ljust(15) + mycolors.reset + ok, end='')
            if ('URLhaus' in attrs['last_analysis_results']):
                result = attrs['last_analysis_results']['URLhaus']['result']
                if (result):
                    print(mycolors.foreground.lightcyan + "\n".ljust(26) + "URLhaus: ".ljust(15) + mycolors.reset + result, end='')
                else:
                    print(mycolors.foreground.lightcyan + "\n".ljust(26) + "URLhaus: ".ljust(15) + mycolors.reset + ok, end='')
            if ('VX Vault' in attrs['last_analysis_results']):
                result = attrs['last_analysis_results']['VX Vault']['result']
                if (result):
                    print(mycolors.foreground.lightcyan + "\n".ljust(26) + "VX Vault: ".ljust(15) + mycolors.reset + result, end='')
                else:
                    print(mycolors.foreground.lightcyan + "\n".ljust(26) + "VX Vault: ".ljust(15) + mycolors.reset + ok, end='')
            if ('Webroot' in attrs['last_analysis_results']):
                result = attrs['last_analysis_results']['Webroot']['result']
                if (result):
                    print(mycolors.foreground.lightcyan + "\n".ljust(26) + "Webroot: ".ljust(15) + mycolors.reset + result, end='')
                else:
                    print(mycolors.foreground.lightcyan + "\n".ljust(26) + "Webroot: ".ljust(15) + mycolors.reset + ok, end='')

    def vt_url_ip_domain_report_light(self, vttext):
        print(mycolors.foreground.red + "\n\nAV Report:", end='')
        attrs = vttext.get('data', {}).get('attributes', {})

        if ('last_analysis_results' in attrs):
            ok = "CLEAN"
            if ('AlienVault' in attrs['last_analysis_results']):
                result = attrs['last_analysis_results']['AlienVault']['result']
                if (result):
                    print(mycolors.foreground.cyan + "\n".ljust(26) + "AlienVault: ".ljust(15) + mycolors.reset + result, end='')
                else:
                    print(mycolors.foreground.cyan + "\n".ljust(26) + "AlienVault: ".ljust(15) + mycolors.reset + ok, end='')
            if ('BitDefender' in attrs['last_analysis_results']):
                result = attrs['last_analysis_results']['BitDefender']['result']
                if (result):
                    print(mycolors.foreground.cyan + "\n".ljust(26) + "BitDefender: ".ljust(15) + mycolors.reset + result, end='')
                else:
                    print(mycolors.foreground.cyan + "\n".ljust(26) + "BitDefender: ".ljust(15) + mycolors.reset + ok, end='')
            if ('Avira' in attrs['last_analysis_results']):
                result = attrs['last_analysis_results']['Avira']['result']
                if (result):
                    print(mycolors.foreground.cyan + "\n".ljust(26) + "Avira: ".ljust(15) + mycolors.reset + result, end='')
                else:
                    print(mycolors.foreground.cyan + "\n".ljust(26) + "Avira: ".ljust(15) + mycolors.reset + ok, end='')
            if ('Comodo Valkyrie Verdict' in attrs['last_analysis_results']):
                result = attrs['last_analysis_results']['Comodo Valkyrie Verdict']['result']
                if (result):
                    print(mycolors.foreground.cyan + "\n".ljust(26) + "Comodo: ".ljust(15) + mycolors.reset + result, end='')
                else:
                    print(mycolors.foreground.cyan + "\n".ljust(26) + "Comodo: ".ljust(15) + mycolors.reset + ok, end='')
            if ('CyRadar' in attrs['last_analysis_results']):
                result = attrs['last_analysis_results']['CyRadar']['result']
                if (result):
                    print(mycolors.foreground.cyan + "\n".ljust(26) + "CyRadar: ".ljust(15) + mycolors.reset + result, end='')
                else:
                    print(mycolors.foreground.cyan + "\n".ljust(26) + "CyRadar: ".ljust(15) + mycolors.reset + ok, end='')
            if ('Dr.Web' in attrs['last_analysis_results']):
                result = attrs['last_analysis_results']['Dr.Web']['result']
                if (result):
                    print(mycolors.foreground.cyan + "\n".ljust(26) + "Dr.Web: ".ljust(15) + mycolors.reset + result, end='')
                else:
                    print(mycolors.foreground.cyan + "\n".ljust(26) + "Dr.Web: ".ljust(15) + mycolors.reset + ok, end='')
            if ('Emsisoft' in attrs['last_analysis_results']):
                result = attrs['last_analysis_results']['Emsisoft']['result']
                if (result):
                    print(mycolors.foreground.cyan + "\n".ljust(26) + "Emsisoft: ".ljust(15) + mycolors.reset + result, end='')
                else:
                    print(mycolors.foreground.cyan + "\n".ljust(26) + "Emsisoft: ".ljust(15) + mycolors.reset + ok, end='')
            if ('ESET' in attrs['last_analysis_results']):
                result = attrs['last_analysis_results']['ESET']['result']
                if (result):
                    print(mycolors.foreground.cyan + "\n".ljust(26) + "ESET: ".ljust(15) + mycolors.reset + result, end='')
                else:
                    print(mycolors.foreground.cyan + "\n".ljust(26) + "ESET: ".ljust(15) + mycolors.reset + ok, end='')
            if ('Forcepoint ThreatSeeker' in attrs['last_analysis_results']):
                result = attrs['last_analysis_results']['Forcepoint ThreatSeeker']['result']
                if (result):
                    print(mycolors.foreground.cyan + "\n".ljust(26) + "Forcepoint: ".ljust(15) + mycolors.reset + result, end='')
                else:
                    print(mycolors.foreground.cyan + "\n".ljust(26) + "Forcepoint: ".ljust(15) + mycolors.reset + ok, end='')
            if ('Fortinet' in attrs['last_analysis_results']):
                result = attrs['last_analysis_results']['Fortinet']['result']
                if (result):
                    print(mycolors.foreground.cyan + "\n".ljust(26) + "Fortinet: ".ljust(15) + mycolors.reset + result, end='')
                else:
                    print(mycolors.foreground.cyan + "\n".ljust(26) + "Fortinet: ".ljust(15) + mycolors.reset + ok, end='')
            if ('G-Data' in attrs['last_analysis_results']):
                result = attrs['last_analysis_results']['G-Data']['result']
                if (result):
                    print(mycolors.foreground.cyan + "\n".ljust(26) + "G-Data: ".ljust(15) + mycolors.reset + result, end='')
                else:
                    print(mycolors.foreground.cyan + "\n".ljust(26) + "G-Data: ".ljust(15) + mycolors.reset + ok, end='')
            if ('Google Safebrowsing' in attrs['last_analysis_results']):
                result = attrs['last_analysis_results']['Google Safebrowsing']['result']
                if (result):
                    print(mycolors.foreground.cyan + "\n".ljust(26) + "Google: ".ljust(15) + mycolors.reset + result, end='')
                else:
                    print(mycolors.foreground.cyan + "\n".ljust(26) + "Google: ".ljust(15) + mycolors.reset + ok, end='')
            if ('Kaspersky' in attrs['last_analysis_results']):
                result = attrs['last_analysis_results']['Kaspersky']['result']
                if (result):
                    print(mycolors.foreground.cyan + "\n".ljust(26) + "Kaspersky: ".ljust(15) + mycolors.reset + result, end='')
                else:
                    print(mycolors.foreground.cyan + "\n".ljust(26) + "Kaspersky: ".ljust(15) + mycolors.reset + ok, end='')
            if ('MalwarePatrol' in attrs['last_analysis_results']):
                result = attrs['last_analysis_results']['MalwarePatrol']['result']
                if (result):
                    print(mycolors.foreground.cyan + "\n".ljust(26) + "MalwarePatrol: ".ljust(15) + mycolors.reset + result, end='')
                else:
                    print(mycolors.foreground.cyan + "\n".ljust(26) + "MalwarePatrol: ".ljust(15) + mycolors.reset + ok, end='')
            if ('OpenPhish' in attrs['last_analysis_results']):
                result = attrs['last_analysis_results']['OpenPhish']['result']
                if (result):
                    print(mycolors.foreground.cyan + "\n".ljust(26) + "OpenPhish: ".ljust(15) + mycolors.reset + result, end='')
                else:
                    print(mycolors.foreground.cyan + "\n".ljust(26) + "OpenPhish: ".ljust(15) + mycolors.reset + ok, end='')
            if ('PhishLabs' in attrs['last_analysis_results']):
                result = attrs['last_analysis_results']['PhishLabs']['result']
                if (result):
                    print(mycolors.foreground.cyan + "\n".ljust(26) + "PhishLabs: ".ljust(15) + mycolors.reset + result, end='')
                else:
                    print(mycolors.foreground.cyan + "\n".ljust(26) + "PhishLabs: ".ljust(15) + mycolors.reset + ok, end='')
            if ('Phishtank' in attrs['last_analysis_results']):
                result = attrs['last_analysis_results']['Phishtank']['result']
                if (result):
                    print(mycolors.foreground.cyan + "\n".ljust(26) + "Phishtank: ".ljust(15) + mycolors.reset + result, end='')
                else:
                    print(mycolors.foreground.cyan + "\n".ljust(26) + "Phishtank: ".ljust(15) + mycolors.reset + ok, end='')
            if ('Spamhaus' in attrs['last_analysis_results']):
                result = attrs['last_analysis_results']['Spamhaus']['result']
                if (result):
                    print(mycolors.foreground.cyan + "\n".ljust(26) + "Spamhaus: ".ljust(15) + mycolors.reset + result, end='')
                else:
                    print(mycolors.foreground.cyan + "\n".ljust(26) + "Spamhaus: ".ljust(15) + mycolors.reset + ok, end='')
            if ('Sophos' in attrs['last_analysis_results']):
                result = attrs['last_analysis_results']['Sophos']['result']
                if (result):
                    print(mycolors.foreground.cyan + "\n".ljust(26) + "Sophos: ".ljust(15) + mycolors.reset + result, end='')
                else:
                    print(mycolors.foreground.cyan + "\n".ljust(26) + "Sophos: ".ljust(15) + mycolors.reset + ok, end='')
            if ('Sucuri SiteCheck' in attrs['last_analysis_results']):
                result = attrs['last_analysis_results']['Sucuri SiteCheck']['result']
                if (result):
                    print(mycolors.foreground.cyan + "\n".ljust(26) + "Sucuri: ".ljust(15) + mycolors.reset + result, end='')
                else:
                    print(mycolors.foreground.cyan + "\n".ljust(26) + "Sucuri: ".ljust(15) + mycolors.reset + ok, end='')
            if ('Trustwave' in attrs['last_analysis_results']):
                result = attrs['last_analysis_results']['Trustwave']['result']
                if (result):
                    print(mycolors.foreground.cyan + "\n".ljust(26) + "Trustwave: ".ljust(15) + mycolors.reset + result, end='')
                else:
                    print(mycolors.foreground.cyan + "\n".ljust(26) + "Trustwave: ".ljust(15) + mycolors.reset + ok, end='')
            if ('URLhaus' in attrs['last_analysis_results']):
                result = attrs['last_analysis_results']['URLhaus']['result']
                if (result):
                    print(mycolors.foreground.cyan + "\n".ljust(26) + "URLhaus: ".ljust(15) + mycolors.reset + result, end='')
                else:
                    print(mycolors.foreground.cyan + "\n".ljust(26) + "URLhaus: ".ljust(15) + mycolors.reset + ok, end='')
            if ('VX Vault' in attrs['last_analysis_results']):
                result = attrs['last_analysis_results']['VX Vault']['result']
                if (result):
                    print(mycolors.foreground.cyan + "\n".ljust(26) + "VX Vault: ".ljust(15) + mycolors.reset + result, end='')
                else:
                    print(mycolors.foreground.cyan + "\n".ljust(26) + "VX Vault: ".ljust(15) + mycolors.reset + ok, end='')
            if ('Webroot' in attrs['last_analysis_results']):
                result = attrs['last_analysis_results']['Webroot']['result']
                if (result):
                    print(mycolors.foreground.cyan + "\n".ljust(26) + "Webroot: ".ljust(15) + mycolors.reset + result, end='')
                else:
                    print(mycolors.foreground.cyan + "\n".ljust(26) + "Webroot: ".ljust(15) + mycolors.reset + ok, end='')

    def vtdomainwork(self, mydomain):
        if not mydomain or not validators.domain(mydomain):
            if cv.bkg == 0:
                print(mycolors.foreground.red + "\nYou didn't provide a valid domain.\n")
            else:
                print(mycolors.foreground.yellow + "\nYou didn't provide a valid domain.\n")
            return False

        url = VirusTotalExtractor.urldomainvt3

        try:
            finalurl = ''.join([url, "/", mydomain])
            requestsession = requests.Session()
            requestsession.headers.update({'x-apikey': self.VTAPI})
            requestsession.headers.update({'content-type': 'application/json'})
            response = requestsession.get(finalurl)
            vttext = json.loads(response.text)

            if (response.status_code == 404):
                if (cv.bkg == 1):
                    print(mycolors.foreground.yellow + "\nDOMAIN NOT FOUND!")
                if (cv.bkg == 0):
                    print(mycolors.foreground.red + "\nDOMAIN NOT FOUND!")
            else:
                attrs = vttext.get('data', {}).get('attributes', {})
                if (cv.bkg == 1):
                    if ('creation_date' in attrs):
                        create_date = attrs['creation_date']
                        print(mycolors.foreground.yellow + "\nCreation Date: ".ljust(26) + mycolors.reset + str(datetime.fromtimestamp(create_date)), end='')
                    if ('last_update_date' in attrs):
                        last_update_date = attrs['last_update_date']
                        print(mycolors.foreground.yellow + "\nLast Update Date: ".ljust(26) + mycolors.reset + str(datetime.fromtimestamp(last_update_date)), end='')
                    if ('registrar' in attrs):
                        registrar = attrs['registrar']
                        print(mycolors.foreground.yellow + "\nRegistrar: ".ljust(26) + mycolors.reset + registrar, end='')
                    if ('reputation' in attrs):
                        reputation = attrs['reputation']
                        print(mycolors.foreground.yellow + "\nReputation: ".ljust(26) + mycolors.reset + str(reputation), end='')
                    if ('whois' in attrs):
                        whois = attrs['whois']
                        print(mycolors.foreground.yellow + "\nWhois: ".ljust(26) + mycolors.reset + (mycolors.reset + "\n".ljust(26)).join(textwrap.wrap(" ".join(whois.split()), width=80)), end=' ')
                    if ('whois_date' in attrs):
                        whois_date = attrs['whois_date']
                        print(mycolors.foreground.yellow + "\nWhois Date: ".ljust(26) + mycolors.reset + str(datetime.fromtimestamp(whois_date)), end='')
                    if ('jarm' in attrs):
                        jarm = attrs['jarm']
                        print(mycolors.foreground.lightred + "\n\nJarm: ".ljust(27) + mycolors.reset + str(jarm), end='')
                    if ('last_analysis_stats' in attrs):
                        if ('harmless' in attrs['last_analysis_stats']):
                            harmless = attrs['last_analysis_stats']['harmless']
                            print(mycolors.foreground.lightred + "\nHarmless: ".ljust(26) + mycolors.reset + str(harmless), end='')
                    if ('last_analysis_stats' in attrs):
                        if ('malicious' in attrs['last_analysis_stats']):
                            malicious = attrs['last_analysis_stats']['malicious']
                            print(mycolors.foreground.lightred + "\nMalicious: ".ljust(26) + mycolors.reset + str(malicious), end='')
                    if ('last_analysis_stats' in attrs):
                        if ('undetected' in attrs['last_analysis_stats']):
                            undetected = attrs['last_analysis_stats']['undetected']
                            print(mycolors.foreground.lightred + "\nUndetected: ".ljust(26) + mycolors.reset + str(undetected), end='')
                    if ('last_analysis_stats' in attrs):
                        if ('suspicious' in attrs['last_analysis_stats']):
                            suspicious = attrs['last_analysis_stats']['suspicious']
                            print(mycolors.foreground.lightred + "\nSuspicious: ".ljust(26) + mycolors.reset + str(suspicious), end='')

                    self.vt_url_ip_domain_report_dark(vttext)

                if (cv.bkg == 0):
                    if ('creation_date' in attrs):
                        create_date = attrs['creation_date']
                        print(mycolors.foreground.green + "\nCreation Date: ".ljust(26) + mycolors.reset + str(datetime.fromtimestamp(create_date)), end='')
                    if ('last_update_date' in attrs):
                        last_update_date = attrs['last_update_date']
                        print(mycolors.foreground.green + "\nLast Update Date: ".ljust(26) + mycolors.reset + str(datetime.fromtimestamp(last_update_date)), end='')
                    if ('registrar' in attrs):
                        registrar = attrs['registrar']
                        print(mycolors.foreground.green + "\nRegistrar: ".ljust(26) + mycolors.reset + registrar, end='')
                    if ('reputation' in attrs):
                        reputation = attrs['reputation']
                        print(mycolors.foreground.green + "\nReputation: ".ljust(26) + mycolors.reset + str(reputation), end='')
                    if ('whois' in attrs):
                        whois = attrs['whois']
                        print(mycolors.foreground.green + "\nWhois: ".ljust(26) + mycolors.reset + (mycolors.reset + "\n".ljust(26)).join(textwrap.wrap(" ".join(whois.split()), width=80)), end=' ')
                    if ('whois_date' in attrs):
                        whois_date = attrs['whois_date']
                        print(mycolors.foreground.green + "\nWhois Date: ".ljust(26) + mycolors.reset + str(datetime.fromtimestamp(whois_date)), end='')
                    if ('jarm' in attrs):
                        jarm = attrs['jarm']
                        print(mycolors.foreground.red + "\n\nJarm: ".ljust(27) + mycolors.reset + str(jarm), end='')
                    if ('last_analysis_stats' in attrs):
                        if ('harmless' in attrs['last_analysis_stats']):
                            harmless = attrs['last_analysis_stats']['harmless']
                            print(mycolors.foreground.red + "\nHarmless: ".ljust(26) + mycolors.reset + str(harmless), end='')
                    if ('last_analysis_stats' in attrs):
                        if ('malicious' in attrs['last_analysis_stats']):
                            malicious = attrs['last_analysis_stats']['malicious']
                            print(mycolors.foreground.red + "\nMalicious: ".ljust(26) + mycolors.reset + str(malicious), end='')
                    if ('last_analysis_stats' in attrs):
                        if ('undetected' in attrs['last_analysis_stats']):
                            undetected = attrs['last_analysis_stats']['undetected']
                            print(mycolors.foreground.red + "\nUndetected: ".ljust(26) + mycolors.reset + str(undetected), end='')
                    if ('last_analysis_stats' in attrs):
                        if ('suspicious' in attrs['last_analysis_stats']):
                            suspicious = attrs['last_analysis_stats']['suspicious']
                            print(mycolors.foreground.red + "\nSuspicious: ".ljust(26) + mycolors.reset + str(suspicious), end='')

                    self.vt_url_ip_domain_report_light(vttext)
        except ValueError:
            if (cv.bkg == 1):
                print((mycolors.foreground.lightred + "Error while connecting to Virus Total!\n"))
            else:
                print((mycolors.foreground.red + "Error while connecting to Virus Total!\n"))
            print(mycolors.reset)
            exit(3)

    def vtipwork(self, myip):
        if not myip:
            return False

        url = VirusTotalExtractor.urlipvt3

        try:
            finalurl = ''.join([url, "/", myip])
            requestsession = requests.Session()
            requestsession.headers.update({'x-apikey': self.VTAPI})
            requestsession.headers.update({'content-type': 'application/json'})
            response = requestsession.get(finalurl)
            vttext = json.loads(response.text)

            if (response.status_code == 404):
                if (cv.bkg == 1):
                    print(mycolors.foreground.yellow + "\nIP ADDRESS NOT FOUND!")
                if (cv.bkg == 0):
                    print(mycolors.foreground.red + "\nIP ADDRESS NOT FOUND!")
            else:
                attrs = vttext.get('data', {}).get('attributes', {})

                if (cv.bkg == 1):
                    if ('as_owner' in attrs):
                        as_owner = attrs['as_owner']
                        print(mycolors.foreground.yellow + "\nAS Owner: ".ljust(26) + mycolors.reset + as_owner, end='')
                    if ('asn' in attrs):
                        asn = attrs['asn']
                        print(mycolors.foreground.yellow + "\nASN: ".ljust(26) + mycolors.reset + str(asn), end='')
                    if ('whois_date' in attrs):
                        whois_date = attrs['whois_date']
                        print(mycolors.foreground.yellow + "\nWhois Date: ".ljust(26) + mycolors.reset + str(datetime.fromtimestamp(whois_date)), end='')
                    if ('whois' in attrs):
                        whois = attrs['whois']
                        print(mycolors.foreground.yellow + "\nWhois: ".ljust(26) + mycolors.reset + (mycolors.reset + "\n".ljust(26)).join(textwrap.wrap(" ".join(whois.split()), width=80)), end=' ')
                    if ('country' in attrs):
                        country = attrs['country']
                        print(mycolors.foreground.lightcyan + "\n\nCountry: ".ljust(27) + mycolors.reset + country, end='')
                    if ('jarm' in attrs):
                        jarm = attrs['jarm']
                        print(mycolors.foreground.lightcyan + "\nJARM: ".ljust(26) + mycolors.reset + str(jarm), end='')
                    if ('network' in attrs):
                        network = attrs['network']
                        print(mycolors.foreground.lightcyan + "\nNetwork: ".ljust(26) + mycolors.reset + str(network), end='')
                    if ('regional_internet_registry' in attrs):
                        rir = attrs['regional_internet_registry']
                        print(mycolors.foreground.lightcyan + "\nR.I.R: ".ljust(26) + mycolors.reset + str(rir), end='')
                    if ('reputation' in attrs):
                        reputation = attrs['reputation']
                        print(mycolors.foreground.lightred + "\n\nReputation: ".ljust(27) + mycolors.reset + str(reputation), end='')
                    if ('last_analysis_stats' in attrs):
                        if ('harmless' in attrs['last_analysis_stats']):
                            harmless = attrs['last_analysis_stats']['harmless']
                            print(mycolors.foreground.lightred + "\nHarmless: ".ljust(26) + mycolors.reset + str(harmless), end='')
                    if ('last_analysis_stats' in attrs):
                        if ('malicious' in attrs['last_analysis_stats']):
                            malicious = attrs['last_analysis_stats']['malicious']
                            print(mycolors.foreground.lightred + "\nMalicious: ".ljust(26) + mycolors.reset + str(malicious), end='')
                    if ('last_analysis_stats' in attrs):
                        if ('undetected' in attrs['last_analysis_stats']):
                            undetected = attrs['last_analysis_stats']['undetected']
                            print(mycolors.foreground.lightred + "\nUndetected: ".ljust(26) + mycolors.reset + str(undetected), end='')
                    if ('last_analysis_stats' in attrs):
                        if ('suspicious' in attrs['last_analysis_stats']):
                            suspicious = attrs['last_analysis_stats']['suspicious']
                            print(mycolors.foreground.lightred + "\nSuspicious: ".ljust(26) + mycolors.reset + str(suspicious), end='')
                    print(mycolors.foreground.lightred + "\nCity: ".ljust(26) + mycolors.reset + str(geocoder.ip(myip).city), end='')

                    self.vt_url_ip_domain_report_dark(vttext)

                if (cv.bkg == 0):
                    if ('as_owner' in attrs):
                        as_owner = attrs['as_owner']
                        print(mycolors.foreground.yellow + "\nAS Owner: ".ljust(26) + mycolors.reset + as_owner, end='')
                    if ('asn' in attrs):
                        asn = attrs['asn']
                        print(mycolors.foreground.yellow + "\nASN: ".ljust(26) + mycolors.reset + str(asn), end='')
                    if ('whois_date' in attrs):
                        whois_date = attrs['whois_date']
                        print(mycolors.foreground.yellow + "\nWhois Date: ".ljust(26) + mycolors.reset + str(datetime.fromtimestamp(whois_date)), end='')
                    if ('whois' in attrs):
                        whois = attrs['whois']
                        print(mycolors.foreground.yellow + "\nWhois: ".ljust(26) + mycolors.reset + (mycolors.reset + "\n".ljust(26)).join(textwrap.wrap(" ".join(whois.split()), width=80)), end=' ')
                    if ('country' in attrs):
                        country = attrs['country']
                        print(mycolors.foreground.green + "\n\nCountry: ".ljust(27) + mycolors.reset + country, end='')
                    if ('jarm' in attrs):
                        jarm = attrs['jarm']
                        print(mycolors.foreground.green + "\nJARM: ".ljust(26) + mycolors.reset + str(jarm), end='')
                    if ('network' in attrs):
                        network = attrs['network']
                        print(mycolors.foreground.green + "\nNetwork: ".ljust(26) + mycolors.reset + str(network), end='')
                    if ('regional_internet_registry' in attrs):
                        rir = attrs['regional_internet_registry']
                        print(mycolors.foreground.green + "\nR.I.R: ".ljust(26) + mycolors.reset + str(rir), end='')
                    if ('reputation' in attrs):
                        reputation = attrs['reputation']
                        print(mycolors.foreground.red + "\n\nReputation: ".ljust(27) + mycolors.reset + str(reputation), end='')
                    if ('last_analysis_stats' in attrs):
                        if ('harmless' in attrs['last_analysis_stats']):
                            harmless = attrs['last_analysis_stats']['harmless']
                            print(mycolors.foreground.red + "\nHarmless: ".ljust(26) + mycolors.reset + str(harmless), end='')
                    if ('last_analysis_stats' in attrs):
                        if ('malicious' in attrs['last_analysis_stats']):
                            malicious = attrs['last_analysis_stats']['malicious']
                            print(mycolors.foreground.red + "\nMalicious: ".ljust(26) + mycolors.reset + str(malicious), end='')
                    if ('last_analysis_stats' in attrs):
                        if ('undetected' in attrs['last_analysis_stats']):
                            undetected = attrs['last_analysis_stats']['undetected']
                            print(mycolors.foreground.red + "\nUndetected: ".ljust(26) + mycolors.reset + str(undetected), end='')
                    if ('last_analysis_stats' in attrs):
                        if ('suspicious' in attrs['last_analysis_stats']):
                            suspicious = attrs['last_analysis_stats']['suspicious']
                    print(mycolors.foreground.red + "\nCity: ".ljust(26) + mycolors.reset + str(geocoder.ip(myip).city), end='')

                    self.vt_url_ip_domain_report_light(vttext)

                print("\n")

        except ValueError:
            if (cv.bkg == 1):
                print((mycolors.foreground.lightred + "Error while connecting to Virus Total!\n"))
            else:
                print((mycolors.foreground.red + "Error while connecting to Virus Total!\n"))
            print(mycolors.reset)
            exit(3)

    def vturlwork(self, myurl):
        if not myurl or not validators.url(myurl):
            if cv.bkg == 0:
                print(mycolors.foreground.red + "\nYou didn't provide a valid URL.\n")
            else:
                print(mycolors.foreground.yellow + "\nYou didn't provide a valid URL.\n")
            return False

        url = VirusTotalExtractor.urlurlvt3

        try:
            urlid = base64.urlsafe_b64encode(myurl.encode()).decode().strip("=")
            finalurl = ''.join([url, "/", urlid])
            requestsession = requests.Session()
            requestsession.headers.update({'x-apikey': self.VTAPI})
            requestsession.headers.update({'content-type': 'application/json'})
            response = requestsession.get(finalurl)
            vttext = json.loads(response.text)
            attrs = vttext.get('data', {}).get('attributes', {})

            if (response.status_code == 404):
                if (cv.bkg == 1):
                    print(mycolors.foreground.yellow + "\nURL NOT FOUND!")
                if (cv.bkg == 0):
                    print(mycolors.foreground.red + "\nURL NOT FOUND!")
            else:
                if (cv.bkg == 1):
                    if ('last_final_url' in attrs):
                        last_final_url = attrs['last_final_url']
                        print(mycolors.foreground.lightred + "\nLast Final URL: ".ljust(26) + mycolors.reset + str(last_final_url), end='')
                    if ('last_analysis_stats' in attrs):
                        if ('harmless' in attrs['last_analysis_stats']):
                            harmless = attrs['last_analysis_stats']['harmless']
                            print(mycolors.foreground.lightred + "\nHarmless: ".ljust(26) + mycolors.reset + str(harmless), end='')
                    if ('last_analysis_stats' in attrs):
                        if ('malicious' in attrs['last_analysis_stats']):
                            malicious = attrs['last_analysis_stats']['malicious']
                            print(mycolors.foreground.lightred + "\nMalicious: ".ljust(26) + mycolors.reset + str(malicious), end='')
                    if ('last_analysis_stats' in attrs):
                        if ('undetected' in attrs['last_analysis_stats']):
                            undetected = attrs['last_analysis_stats']['undetected']
                            print(mycolors.foreground.lightred + "\nUndetected: ".ljust(26) + mycolors.reset + str(undetected), end='')
                    if ('last_analysis_stats' in attrs):
                        if ('suspicious' in attrs['last_analysis_stats']):
                            suspicious = attrs['last_analysis_stats']['suspicious']
                            print(mycolors.foreground.lightred + "\nSuspicious: ".ljust(26) + mycolors.reset + str(suspicious), end='')
                    if ('last_http_response_content_sha256' in attrs):
                        last_http_sha256 = attrs['last_http_response_content_sha256']
                        print(mycolors.foreground.yellow + "\n\nLast SHA256 Content: ".ljust(27) + mycolors.reset + last_http_sha256, end='')
                    if ('last_http_response_code' in attrs):
                        last_http_response = attrs['last_http_response_code']
                        print(mycolors.foreground.yellow + "\nLast HTTP Response Code: ".ljust(26) + mycolors.reset + str(last_http_response), end='')
                    if ('last_analysis_date' in attrs):
                        last_analysis_date = attrs['last_analysis_date']
                        print(mycolors.foreground.yellow + "\nLast Analysis Date: ".ljust(26) + mycolors.reset + str(datetime.fromtimestamp(last_analysis_date)), end='')
                    if ('times_submitted' in attrs):
                        times_submitted = attrs['times_submitted']
                        print(mycolors.foreground.yellow + "\nTimes Submitted: ".ljust(26) + mycolors.reset + str(times_submitted), end='')
                    if ('reputation' in attrs):
                        reputation = attrs['reputation']
                        print(mycolors.foreground.yellow + "\nReputation: ".ljust(26) + mycolors.reset + str(reputation), end='')
                    if ('threat_names' in attrs):
                        print(mycolors.foreground.lightcyan + "\n\nThreat Names: ", end='')
                        for name in attrs['threat_names']:
                            print(mycolors.reset + "\n".ljust(26) + str(name), end='')
                    if ('redirection_chain' in attrs):
                        print(mycolors.foreground.lightcyan + "\n\nRedirection Chain: ", end='')
                        for chain in attrs['redirection_chain']:
                            print(mycolors.reset + "\n".ljust(26) + str(chain), end='')

                    self.vt_url_ip_domain_report_dark(vttext)

                if (cv.bkg == 0):
                    if ('last_final_url' in attrs):
                        last_final_url = attrs['last_final_url']
                        print(mycolors.foreground.red + "\nLast Final URL: ".ljust(26) + mycolors.reset + str(last_final_url), end='')
                    if ('last_analysis_stats' in attrs):
                        if ('harmless' in attrs['last_analysis_stats']):
                            harmless = attrs['last_analysis_stats']['harmless']
                            print(mycolors.foreground.red + "\nHarmless: ".ljust(26) + mycolors.reset + str(harmless), end='')
                    if ('last_analysis_stats' in attrs):
                        if ('malicious' in attrs['last_analysis_stats']):
                            malicious = attrs['last_analysis_stats']['malicious']
                            print(mycolors.foreground.red + "\nMalicious: ".ljust(26) + mycolors.reset + str(malicious), end='')
                    if ('last_analysis_stats' in attrs):
                        if ('undetected' in attrs['last_analysis_stats']):
                            undetected = attrs['last_analysis_stats']['undetected']
                            print(mycolors.foreground.red + "\nUndetected: ".ljust(26) + mycolors.reset + str(undetected), end='')
                    if ('last_analysis_stats' in attrs):
                        if ('suspicious' in attrs['last_analysis_stats']):
                            suspicious = attrs['last_analysis_stats']['suspicious']
                            print(mycolors.foreground.red + "\nSuspicious: ".ljust(26) + mycolors.reset + str(suspicious), end='')
                    if ('last_http_response_content_sha256' in attrs):
                        last_http_sha256 = attrs['last_http_response_content_sha256']
                        print(mycolors.foreground.purple + "\n\nLast SHA256 Content: ".ljust(27) + mycolors.reset + last_http_sha256, end='')
                    if ('last_http_response_code' in attrs):
                        last_http_response = attrs['last_http_response_code']
                        print(mycolors.foreground.purple + "\nLast HTTP Response Code: ".ljust(26) + mycolors.reset + str(last_http_response), end='')
                    if ('last_analysis_date' in attrs):
                        last_analysis_date = attrs['last_analysis_date']
                        print(mycolors.foreground.purple + "\nLast Analysis Date: ".ljust(26) + mycolors.reset + str(datetime.fromtimestamp(last_analysis_date)), end='')
                    if ('times_submitted' in attrs):
                        times_submitted = attrs['times_submitted']
                        print(mycolors.foreground.purple + "\nTimes Submitted: ".ljust(26) + mycolors.reset + str(times_submitted), end='')
                    if ('reputation' in attrs):
                        reputation = attrs['reputation']
                        print(mycolors.foreground.purple + "\nReputation: ".ljust(26) + mycolors.reset + str(reputation), end='')
                    if ('threat_names' in attrs):
                        print(mycolors.foreground.green + "\n\nThreat Names: ", end='')
                        for name in attrs['threat_names']:
                            print(mycolors.reset + "\n".ljust(26) + str(name), end='')
                    if ('redirection_chain' in attrs):
                        print(mycolors.foreground.green + "\n\nRedirection Chain: ", end='')
                        for chain in attrs['redirection_chain']:
                            print(mycolors.reset + "\n".ljust(26) + str(chain), end='')

                    self.vt_url_ip_domain_report_light(vttext)

                print("\n")
        except ValueError:
            if (cv.bkg == 1):
                print((mycolors.foreground.lightred + "Error while connecting to Virus Total!\n"))
            else:
                print((mycolors.foreground.red + "Error while connecting to Virus Total!\n"))
            print(mycolors.reset)
            exit(3)

    def vtuploadfile(self, file_item, url=None):
        if not file_item or not os.path.isfile(file_item):
            if cv.bkg == 0:
                print(mycolors.foreground.red + "\nYou didn't provide a valid file.\n")
            else:
                print(mycolors.foreground.yellow + "\nYou didn't provide a valid file.\n")
            return False

        if not url:
            url = VirusTotalExtractor.urlfilevt3

        try:
            finalurl = url
            requestsession = requests.Session()
            requestsession.headers.update({'x-apikey': self.VTAPI})
            files = {'file': (file_item, open(file_item, 'rb'))}
            response = requestsession.post(finalurl, files=files)
            vttext = json.loads(response.text)

            if (response.status_code == 400):
                if (cv.bkg == 1):
                    print(mycolors.foreground.yellow + "\tThere was an issue while uploading the file.")
                if (cv.bkg == 0):
                    print(mycolors.foreground.blue + "\tThere was an issue while uploading the file.")
            else:
                if (cv.bkg == 1):
                    print(mycolors.foreground.lightcyan + "\n\tFile Submitted!" + mycolors.reset)
                    print(mycolors.foreground.lightcyan + "\n\tid: " + mycolors.reset + vttext['data']['id'])
                    print(mycolors.foreground.yellow + "\n\tWait for 120 seconds (at least) before requesting the report using -v 1 or -v 8 options!" + mycolors.reset)
                if (cv.bkg == 0):
                    print(mycolors.foreground.green + "\n\tFile Submitted!" + mycolors.reset)
                    print(mycolors.foreground.green + "\n\tid: " + mycolors.reset + vttext['data']['id'])
                    print(mycolors.foreground.purple + "\n\tWait for 120 seconds (at least) before requesting the report using -v 1 or -v 8 options!" + mycolors.reset)
        except ValueError:
            if (cv.bkg == 1):
                print((mycolors.foreground.lightred + "Error while connecting to Virus Total!\n"))
            else:
                print((mycolors.foreground.red + "Error while connecting to Virus Total!\n"))
            print(mycolors.reset)
            exit(3)

    def vtreportwork(self, myhash, prolog):
        url = VirusTotalExtractor.urlfilevt3

        try:
            finalurl = ''.join([url, "/", myhash])
            requestsession = requests.Session()
            requestsession.headers.update({'x-apikey': self.VTAPI})
            requestsession.headers.update({'content-type': 'application/json'})
            response = requestsession.get(finalurl)
            vttext = json.loads(response.text)
            attrs = vttext.get('data', {}).get('attributes', {})

            if (response.status_code == 404):
                if (cv.bkg == 1):
                    print(mycolors.foreground.yellow + "\nSAMPLE NOT FOUND!")
                if (cv.bkg == 0):
                    print(mycolors.foreground.red + "\nSAMPLE NOT FOUND!")
            else:
                if (cv.bkg == 1):
                    if (prolog == 1):
                        if ('md5' in attrs):
                            md5hash = attrs['md5']
                            print(mycolors.foreground.lightcyan + "\nMD5 hash: ".ljust(22) + mycolors.reset + md5hash, end='')
                        if ('sha1' in attrs):
                            sha1hash = attrs['sha1']
                            print(mycolors.foreground.lightcyan + "\nSHA1 hash: ".ljust(22) + mycolors.reset + sha1hash, end='')
                        if ('sha256' in attrs):
                            sha256hash = attrs['sha256']
                            print(mycolors.foreground.lightcyan + "\nSHA256 hash: ".ljust(22) + mycolors.reset + sha256hash, end='')
                        if ('last_analysis_stats' in attrs):
                            malicious = attrs['last_analysis_stats']['malicious']
                            undetected = attrs['last_analysis_stats']['undetected']
                            print(mycolors.foreground.lightred + "\n\nMalicious: ".ljust(23) + mycolors.reset + str(malicious), end='')
                            print(mycolors.foreground.lightred + "\nUndetected: ".ljust(22) + mycolors.reset + str(undetected), end='\n')

                    print(mycolors.foreground.lightred + "\nAV Report:", end='')
                    if ('last_analysis_results' in attrs):
                        ok = "CLEAN"
                        if ('Avast' in attrs['last_analysis_results']):
                            result = attrs['last_analysis_results']['Avast']['result']
                            if (result):
                                print(mycolors.foreground.lightcyan + "\n".ljust(22) + "Avast: ".ljust(15) + mycolors.reset + result, end='')
                            else:
                                print(mycolors.foreground.lightcyan + "\n".ljust(22) + "Avast: ".ljust(15) + mycolors.reset + ok, end='')
                    if ('last_analysis_results' in attrs):
                        if ('Avira' in attrs['last_analysis_results']):
                            result = attrs['last_analysis_results']['Avira']['result']
                            if (result):
                                print(mycolors.foreground.lightcyan + "\n".ljust(22) + "Avira: ".ljust(15) + mycolors.reset + result, end='')
                            else:
                                print(mycolors.foreground.lightcyan + "\n".ljust(22) + "Avira: ".ljust(15) + mycolors.reset + ok, end='')
                    if ('last_analysis_results' in attrs):
                        if ('BitDefender' in attrs['last_analysis_results']):
                            result = attrs['last_analysis_results']['BitDefender']['result']
                            if (result):
                                print(mycolors.foreground.lightcyan + "\n".ljust(22) + "BitDefender: ".ljust(15) + mycolors.reset + result, end='')
                            else:
                                print(mycolors.foreground.lightcyan + "\n".ljust(22) + "BitDefender: ".ljust(15) + mycolors.reset + ok, end='')
                    if ('last_analysis_results' in attrs):
                        if ('DrWeb' in attrs['last_analysis_results']):
                            result = attrs['last_analysis_results']['DrWeb']['result']
                            if (result):
                                print(mycolors.foreground.lightcyan + "\n".ljust(22) + "DrWeb: ".ljust(15) + mycolors.reset + result, end='')
                            else:
                                print(mycolors.foreground.lightcyan + "\n".ljust(22) + "DrWeb: ".ljust(15) + mycolors.reset + ok, end='')
                    if ('last_analysis_results' in attrs):
                        if ('Emsisoft' in attrs['last_analysis_results']):
                            result = attrs['last_analysis_results']['Emsisoft']['result']
                            if (result):
                                print(mycolors.foreground.lightcyan + "\n".ljust(22) + "Emsisoft: ".ljust(15) + mycolors.reset + result, end='')
                            else:
                                print(mycolors.foreground.lightcyan + "\n".ljust(22) + "Emsisoft: ".ljust(15) + mycolors.reset + ok, end='')
                    if ('last_analysis_results' in attrs):
                        if ('ESET-NOD32' in attrs['last_analysis_results']):
                            result = attrs['last_analysis_results']['ESET-NOD32']['result']
                            if (result):
                                print(mycolors.foreground.lightcyan + "\n".ljust(22) + "ESET-NOD32: ".ljust(15) + mycolors.reset + result, end='')
                            else:
                                print(mycolors.foreground.lightcyan + "\n".ljust(22) + "ESET-NOD32: ".ljust(15) + mycolors.reset + ok, end='')
                    if ('last_analysis_results' in attrs):
                        if ('F-Secure' in attrs['last_analysis_results']):
                            result = attrs['last_analysis_results']['F-Secure']['result']
                            if (result):
                                print(mycolors.foreground.lightcyan + "\n".ljust(22) + "F-Secure: ".ljust(15) + mycolors.reset + result, end='')
                            else:
                                print(mycolors.foreground.lightcyan + "\n".ljust(22) + "F-Secure: ".ljust(15) + mycolors.reset + ok, end='')
                    if ('last_analysis_results' in attrs):
                        if ('FireEye' in attrs['last_analysis_results']):
                            result = attrs['last_analysis_results']['FireEye']['result']
                            if (result):
                                print(mycolors.foreground.lightcyan + "\n".ljust(22) + "FireEye: ".ljust(15) + mycolors.reset + result, end='')
                            else:
                                print(mycolors.foreground.lightcyan + "\n".ljust(22) + "FireEye: ".ljust(15) + mycolors.reset + ok, end='')
                    if ('last_analysis_results' in attrs):
                        if ('Fortinet' in attrs['last_analysis_results']):
                            result = attrs['last_analysis_results']['Fortinet']['result']
                            if (result):
                                print(mycolors.foreground.lightcyan + "\n".ljust(22) + "Fortinet: ".ljust(15) + mycolors.reset + result, end='')
                            else:
                                print(mycolors.foreground.lightcyan + "\n".ljust(22) + "Fortinet: ".ljust(15) + mycolors.reset + ok, end='')
                    if ('last_analysis_results' in attrs):
                        if ('Kaspersky' in attrs['last_analysis_results']):
                            result = attrs['last_analysis_results']['Kaspersky']['result']
                            if (result):
                                print(mycolors.foreground.lightcyan + "\n".ljust(22) + "Kaspersky: ".ljust(15) + mycolors.reset + result, end='')
                            else:
                                print(mycolors.foreground.lightcyan + "\n".ljust(22) + "Kaspersky: ".ljust(15) + mycolors.reset + ok, end='')
                    if ('last_analysis_results' in attrs):
                        if ('McAfee' in attrs['last_analysis_results']):
                            result = attrs['last_analysis_results']['McAfee']['result']
                            if (result):
                                print(mycolors.foreground.lightcyan + "\n".ljust(22) + "McAfee: ".ljust(15) + mycolors.reset + result, end='')
                            else:
                                print(mycolors.foreground.lightcyan + "\n".ljust(22) + "McAfee: ".ljust(15) + mycolors.reset + ok, end='')
                    if ('last_analysis_results' in attrs):
                        if ('Microsoft' in attrs['last_analysis_results']):
                            result = attrs['last_analysis_results']['Microsoft']['result']
                            if (result):
                                print(mycolors.foreground.lightcyan + "\n".ljust(22) + "Microsoft: ".ljust(15) + mycolors.reset + result, end='')
                            else:
                                print(mycolors.foreground.lightcyan + "\n".ljust(22) + "Microsoft: ".ljust(15) + mycolors.reset + ok, end='')
                    if ('last_analysis_results' in attrs):
                        if ('Panda' in attrs['last_analysis_results']):
                            result = attrs['last_analysis_results']['Panda']['result']
                            if (result):
                                print(mycolors.foreground.lightcyan + "\n".ljust(22) + "Panda: ".ljust(15) + mycolors.reset + result, end='')
                            else:
                                print(mycolors.foreground.lightcyan + "\n".ljust(22) + "Panda: ".ljust(15) + mycolors.reset + ok, end='')
                    if ('last_analysis_results' in attrs):
                        if ('Sophos' in attrs['last_analysis_results']):
                            result = attrs['last_analysis_results']['Sophos']['result']
                            if (result):
                                print(mycolors.foreground.lightcyan + "\n".ljust(22) + "Sophos: ".ljust(15) + mycolors.reset + result, end='')
                            else:
                                print(mycolors.foreground.lightcyan + "\n".ljust(22) + "Sophos: ".ljust(15) + mycolors.reset + ok, end='')
                    if ('last_analysis_results' in attrs):
                        if ('Symantec' in attrs['last_analysis_results']):
                            result = attrs['last_analysis_results']['Symantec']['result']
                            if (result):
                                print(mycolors.foreground.lightcyan + "\n".ljust(22) + "Symantec: ".ljust(15) + mycolors.reset + result, end='')
                            else:
                                print(mycolors.foreground.lightcyan + "\n".ljust(22) + "Symantec: ".ljust(15) + mycolors.reset + ok, end='')
                    if ('last_analysis_results' in attrs):
                        if ('TrendMicro' in attrs['last_analysis_results']):
                            result = attrs['last_analysis_results']['TrendMicro']['result']
                            if (result):
                                print(mycolors.foreground.lightcyan + "\n".ljust(22) + "TrendMicro: ".ljust(15) + mycolors.reset + result, end='')
                            else:
                                print(mycolors.foreground.lightcyan + "\n".ljust(22) + "TrendMicro: ".ljust(15) + mycolors.reset + ok, end='')
                    if ('last_analysis_results' in attrs):
                        if ('ZoneAlarm' in attrs['last_analysis_results']):
                            result = attrs['last_analysis_results']['ZoneAlarm']['result']
                            if (result):
                                print(mycolors.foreground.lightcyan + "\n".ljust(22) + "ZoneAlarm: ".ljust(15) + mycolors.reset + result, end='')
                            else:
                                print(mycolors.foreground.lightcyan + "\n".ljust(22) + "ZoneAlarm: ".ljust(15) + mycolors.reset + ok, end='')

                if (cv.bkg == 0):
                    if (prolog == 1):
                        if ('md5' in attrs):
                            md5hash = attrs['md5']
                            print(mycolors.foreground.cyan + "\nMD5 hash: ".ljust(22) + mycolors.reset + md5hash, end='')
                        if ('sha1' in attrs):
                            sha1hash = attrs['sha1']
                            print(mycolors.foreground.cyan + "\nSHA1 hash: ".ljust(22) + mycolors.reset + sha1hash, end='')
                        if ('sha256' in attrs):
                            sha256hash = attrs['sha256']
                            print(mycolors.foreground.cyan + "\nSHA256 hash: ".ljust(22) + mycolors.reset + sha256hash, end='')
                        if ('last_analysis_stats' in attrs):
                            malicious = attrs['last_analysis_stats']['malicious']
                            undetected = attrs['last_analysis_stats']['undetected']
                            print(mycolors.foreground.red + "\n\nMalicious: ".ljust(23) + mycolors.reset + str(malicious), end='')
                            print(mycolors.foreground.red + "\nUndetected: ".ljust(22) + mycolors.reset + str(undetected), end='\n')

                    print(mycolors.foreground.red + "\nAV Report:", end='')
                    ok = "CLEAN"
                    if ('last_analysis_results' in attrs):
                        if ('Avast' in attrs['last_analysis_results']):
                            result = attrs['last_analysis_results']['Avast']['result']
                            if (result):
                                print(mycolors.foreground.cyan + "\n".ljust(22) + "Avast: ".ljust(15) + mycolors.reset + result, end='')
                            else:
                                print(mycolors.foreground.cyan + "\n".ljust(22) + "Avast: ".ljust(15) + mycolors.reset + ok, end='')
                    if ('last_analysis_results' in attrs):
                        if ('Avira' in attrs['last_analysis_results']):
                            result = attrs['last_analysis_results']['Avira']['result']
                            if (result):
                                print(mycolors.foreground.cyan + "\n".ljust(22) + "Avira: ".ljust(15) + mycolors.reset + result, end='')
                            else:
                                print(mycolors.foreground.cyan + "\n".ljust(22) + "Avira: ".ljust(15) + mycolors.reset + ok, end='')
                    if ('last_analysis_results' in attrs):
                        if ('BitDefender' in attrs['last_analysis_results']):
                            result = attrs['last_analysis_results']['BitDefender']['result']
                            if (result):
                                print(mycolors.foreground.cyan + "\n".ljust(22) + "BitDefender: ".ljust(15) + mycolors.reset + result, end='')
                            else:
                                print(mycolors.foreground.cyan + "\n".ljust(22) + "BitDefender: ".ljust(15) + mycolors.reset + ok, end='')
                    if ('last_analysis_results' in attrs):
                        if ('DrWeb' in attrs['last_analysis_results']):
                            result = attrs['last_analysis_results']['DrWeb']['result']
                            if (result):
                                print(mycolors.foreground.cyan + "\n".ljust(22) + "DrWeb: ".ljust(15) + mycolors.reset + result, end='')
                            else:
                                print(mycolors.foreground.cyan + "\n".ljust(22) + "DrWeb: ".ljust(15) + mycolors.reset + ok, end='')
                    if ('last_analysis_results' in attrs):
                        if ('Emsisoft' in attrs['last_analysis_results']):
                            result = attrs['last_analysis_results']['Emsisoft']['result']
                            if (result):
                                print(mycolors.foreground.cyan + "\n".ljust(22) + "Emsisoft: ".ljust(15) + mycolors.reset + result, end='')
                            else:
                                print(mycolors.foreground.cyan + "\n".ljust(22) + "Emsisoft: ".ljust(15) + mycolors.reset + ok, end='')
                    if ('last_analysis_results' in attrs):
                        if ('ESET-NOD32' in attrs['last_analysis_results']):
                            result = attrs['last_analysis_results']['ESET-NOD32']['result']
                            if (result):
                                print(mycolors.foreground.cyan + "\n".ljust(22) + "ESET-NOD32: ".ljust(15) + mycolors.reset + result, end='')
                            else:
                                print(mycolors.foreground.cyan + "\n".ljust(22) + "ESET-NOD32: ".ljust(15) + mycolors.reset + ok, end='')
                    if ('last_analysis_results' in attrs):
                        if ('F-Secure' in attrs['last_analysis_results']):
                            result = attrs['last_analysis_results']['F-Secure']['result']
                            if (result):
                                print(mycolors.foreground.cyan + "\n".ljust(22) + "F-Secure: ".ljust(15) + mycolors.reset + result, end='')
                            else:
                                print(mycolors.foreground.cyan + "\n".ljust(22) + "F-Secure: ".ljust(15) + mycolors.reset + ok, end='')
                    if ('last_analysis_results' in attrs):
                        if ('FireEye' in attrs['last_analysis_results']):
                            result = attrs['last_analysis_results']['FireEye']['result']
                            if (result):
                                print(mycolors.foreground.cyan + "\n".ljust(22) + "FireEye: ".ljust(15) + mycolors.reset + result, end='')
                            else:
                                print(mycolors.foreground.cyan + "\n".ljust(22) + "FireEye: ".ljust(15) + mycolors.reset + ok, end='')
                    if ('last_analysis_results' in attrs):
                        if ('Fortinet' in attrs['last_analysis_results']):
                            result = attrs['last_analysis_results']['Fortinet']['result']
                            if (result):
                                print(mycolors.foreground.cyan + "\n".ljust(22) + "Fortinet: ".ljust(15) + mycolors.reset + result, end='')
                            else:
                                print(mycolors.foreground.cyan + "\n".ljust(22) + "Fortinet: ".ljust(15) + mycolors.reset + ok, end='')
                    if ('last_analysis_results' in attrs):
                        if ('Kaspersky' in attrs['last_analysis_results']):
                            result = attrs['last_analysis_results']['Kaspersky']['result']
                            if (result):
                                print(mycolors.foreground.cyan + "\n".ljust(22) + "Kaspersky: ".ljust(15) + mycolors.reset + result, end='')
                            else:
                                print(mycolors.foreground.cyan + "\n".ljust(22) + "Kaspersky: ".ljust(15) + mycolors.reset + ok, end='')
                    if ('last_analysis_results' in attrs):
                        if ('McAfee' in attrs['last_analysis_results']):
                            result = attrs['last_analysis_results']['McAfee']['result']
                            if (result):
                                print(mycolors.foreground.cyan + "\n".ljust(22) + "McAfee: ".ljust(15) + mycolors.reset + result, end='')
                            else:
                                print(mycolors.foreground.cyan + "\n".ljust(22) + "McAfee: ".ljust(15) + mycolors.reset + ok, end='')
                    if ('last_analysis_results' in attrs):
                        if ('Microsoft' in attrs['last_analysis_results']):
                            result = attrs['last_analysis_results']['Microsoft']['result']
                            if (result):
                                print(mycolors.foreground.cyan + "\n".ljust(22) + "Microsoft: ".ljust(15) + mycolors.reset + result, end='')
                            else:
                                print(mycolors.foreground.cyan + "\n".ljust(22) + "Microsoft: ".ljust(15) + mycolors.reset + ok, end='')
                    if ('last_analysis_results' in attrs):
                        if ('Panda' in attrs['last_analysis_results']):
                            result = attrs['last_analysis_results']['Panda']['result']
                            if (result):
                                print(mycolors.foreground.cyan + "\n".ljust(22) + "Panda: ".ljust(15) + mycolors.reset + result, end='')
                            else:
                                print(mycolors.foreground.cyan + "\n".ljust(22) + "Panda: ".ljust(15) + mycolors.reset + ok, end='')
                    if ('last_analysis_results' in attrs):
                        if ('Sophos' in attrs['last_analysis_results']):
                            result = attrs['last_analysis_results']['Sophos']['result']
                            if (result):
                                print(mycolors.foreground.cyan + "\n".ljust(22) + "Sophos: ".ljust(15) + mycolors.reset + result, end='')
                            else:
                                print(mycolors.foreground.cyan + "\n".ljust(22) + "Sophos: ".ljust(15) + mycolors.reset + ok, end='')
                    if ('last_analysis_results' in attrs):
                        if ('Symantec' in attrs['last_analysis_results']):
                            result = attrs['last_analysis_results']['Symantec']['result']
                            if (result):
                                print(mycolors.foreground.cyan + "\n".ljust(22) + "Symantec: ".ljust(15) + mycolors.reset + result, end='')
                            else:
                                print(mycolors.foreground.cyan + "\n".ljust(22) + "Symantec: ".ljust(15) + mycolors.reset + ok, end='')
                    if ('last_analysis_results' in attrs):
                        if ('TrendMicro' in attrs['last_analysis_results']):
                            result = attrs['last_analysis_results']['TrendMicro']['result']
                            if (result):
                                print(mycolors.foreground.cyan + "\n".ljust(22) + "TrendMicro: ".ljust(15) + mycolors.reset + result, end='')
                            else:
                                print(mycolors.foreground.cyan + "\n".ljust(22) + "TrendMicro: ".ljust(15) + mycolors.reset + ok, end='')
                    if ('last_analysis_results' in attrs):
                        if ('ZoneAlarm' in attrs['last_analysis_results']):
                            result = attrs['last_analysis_results']['ZoneAlarm']['result']
                            if (result):
                                print(mycolors.foreground.cyan + "\n".ljust(22) + "ZoneAlarm: ".ljust(15) + mycolors.reset + result, end='')
                            else:
                                print(mycolors.foreground.cyan + "\n".ljust(22) + "ZoneAlarm: ".ljust(15) + mycolors.reset + ok, end='')

                print("\n")

        except ValueError:
            if (cv.bkg == 1):
                print((mycolors.foreground.lightred + "Error while connecting to Virus Total!\n"))
            else:
                print((mycolors.foreground.red + "Error while connecting to Virus Total!\n"))
            print(mycolors.reset)
            exit(3)

    def vthashwork(self, myhash, showreport):
        if len(myhash) not in [32, 40, 64]:
            if cv.bkg == 0:
                print(mycolors.foreground.red + "\nYou didn't provide a valid hash.\n")
            else:
                print(mycolors.foreground.yellow + "\nYou didn't provide a valid hash.\n")
            return False

        url = VirusTotalExtractor.urlfilevt3

        try:
            finalurl = ''.join([url, "/", myhash])
            requestsession = requests.Session()
            requestsession.headers.update({'x-apikey': self.VTAPI})
            requestsession.headers.update({'content-type': 'application/json'})
            response = requestsession.get(finalurl)
            vttext = json.loads(response.text)
            attrs = vttext.get('data', {}).get('attributes', {})

            if (response.status_code == 404):
                if (cv.bkg == 1):
                    print(mycolors.foreground.yellow + "\nSAMPLE NOT FOUND!")
                if (cv.bkg == 0):
                    print(mycolors.foreground.red + "\nSAMPLE NOT FOUND!")
            else:
                if (cv.bkg == 1):
                    if ('md5' in attrs):
                        md5hash = attrs['md5']
                        print(mycolors.foreground.lightcyan + "\nMD5 hash: ".ljust(22) + mycolors.reset + md5hash, end='')
                    if ('sha1' in attrs):
                        sha1hash = attrs['sha1']
                        print(mycolors.foreground.lightcyan + "\nSHA1 hash: ".ljust(22) + mycolors.reset + sha1hash, end='')
                    if ('sha256' in attrs):
                        sha256hash = attrs['sha256']
                        print(mycolors.foreground.lightcyan + "\nSHA256 hash: ".ljust(22) + mycolors.reset + sha256hash, end='')
                    if ('last_analysis_stats' in attrs):
                        malicious = attrs['last_analysis_stats']['malicious']
                        undetected = attrs['last_analysis_stats']['undetected']
                        print(mycolors.foreground.lightred + "\n\nMalicious: ".ljust(23) + mycolors.reset + str(malicious), end='')
                        print(mycolors.foreground.lightred + "\nUndetected: ".ljust(22) + mycolors.reset + str(undetected), end='\n')
                    if ('type_description' in attrs):
                        type_description = attrs['type_description']
                        print(mycolors.foreground.yellow + "\nType Description: ".ljust(22) + mycolors.reset + type_description, end='')
                    if ('size' in attrs):
                        size = attrs['size']
                        print(mycolors.foreground.yellow + "\nSize: ".ljust(22) + mycolors.reset + str(size), end='')
                    if ('last_analysis_date' in attrs):
                        last_analysis_date = attrs['last_analysis_date']
                        print(mycolors.foreground.yellow + "\nLast Analysis Date: ".ljust(22) + mycolors.reset + str(datetime.fromtimestamp(last_analysis_date)), end='')
                    if ('type_tag' in attrs):
                        type_tag = attrs['type_tag']
                        print(mycolors.foreground.yellow + "\nType Tag: ".ljust(22) + mycolors.reset + type_tag, end='')
                    if ('times_submitted' in attrs):
                        times_submitted = attrs['times_submitted']
                        print(mycolors.foreground.yellow + "\nTimes Submitted: ".ljust(22) + mycolors.reset + str(times_submitted), end='')
                    if ('popular_threat_classification' in attrs):
                        print(mycolors.foreground.lightred + "\n\nThreat Label: ".ljust(23), end='')
                        if ('suggested_threat_label' in attrs['popular_threat_classification']):
                            threat_label = attrs['popular_threat_classification']['suggested_threat_label']
                        else:
                            threat_label = 'NO GIVEN NAME'
                        print(mycolors.reset + str(threat_label), end='')
                        if ('popular_threat_category' in attrs['popular_threat_classification']):
                            print(mycolors.foreground.lightred + "\nClassification: ", end='')
                            for popular in attrs['popular_threat_classification']['popular_threat_category']:
                                count = popular['count']
                                value = popular['value']
                                print(mycolors.reset + "\n".ljust(22) + "popular count: ".ljust(15) + str(count), end='')
                                print(mycolors.reset + "\n".ljust(22) + "label: ".ljust(15) + str(value), end='\n')
                    if ('trid' in attrs):
                        print(mycolors.foreground.lightcyan + "\nTrid: ", end='')
                        for trid in attrs['trid']:
                            file_type = trid['file_type']
                            probability = trid['probability']
                            print(mycolors.reset + "\n".ljust(22) + "file_type: ".ljust(15) + str(file_type), end='')
                            print(mycolors.reset + "\n".ljust(22) + "probability: ".ljust(15) + str(probability), end='\n')
                    if ('names' in attrs):
                        print(mycolors.foreground.lightcyan + "\nNames: ", end='')
                        for name in attrs['names']:
                            print(mycolors.reset + ("\n".ljust(22) + (mycolors.reset + "\n".ljust(22)).join(textwrap.wrap(" ".join(name.split()), width=80))), end=' ')
                    if ('pe_info' in attrs):
                        print(mycolors.foreground.lightred + "\n\nPE Info: ", end='')
                        if ('imphash' in attrs['pe_info']):
                            imphash = attrs['pe_info']['imphash']
                            print(mycolors.foreground.yellow + "\n".ljust(22) + "Imphash: ".ljust(15) + mycolors.reset + str(imphash), end='')
                        if ('import_list' in attrs['pe_info']):
                            print(mycolors.foreground.yellow + "\n".ljust(22) + "Libraries: ".ljust(15), end='')
                            for lib in attrs['pe_info']['import_list']:
                                print(mycolors.reset + "\n".ljust(37) + str(lib['library_name']), end='')
                        if ('sections' in attrs['pe_info']):
                            print(mycolors.foreground.yellow + "\n".ljust(22) + "Sections: ", end='')
                            for section in attrs['pe_info']['sections']:
                                if ('name' in section):
                                    section_name = section['name']
                                    print(mycolors.reset + "\n\n".ljust(38) + "section_name: ".ljust(14) + str(section_name), end=' ')
                                if ('virtual_size' in section):
                                    virtual_size = section['virtual_size']
                                    print(mycolors.reset + "\n".ljust(37) + "virtual_size: ".ljust(14) + str(virtual_size), end=' ')
                                if ('entropy' in section):
                                    entropy = section['entropy']
                                    print(mycolors.reset + "\n".ljust(37) + "entropy: ".ljust(14) + str(entropy), end=' ')
                                if ('flags' in section):
                                    flags = section['flags']
                                    print(mycolors.reset + "\n".ljust(37) + "flags: ".ljust(14) + str(flags), end=' ')
                    if ('androguard' in attrs):
                        print(mycolors.foreground.lightcyan + "\n\nAndroguard: ", end='')
                        if ('Activities' in attrs['androguard']):
                            print(mycolors.foreground.lightred + "\n".ljust(22) + "Activities: ".ljust(23), end='')
                            for activity in attrs['androguard']['Activities']:
                                print(mycolors.reset + "\n".ljust(37) + activity, end='')
                        if ('main_activity' in attrs['androguard']):
                            print(mycolors.foreground.lightred + "\n\n".ljust(23) + "MainActivity: ".ljust(15), end='')
                            mainactivity = attrs['androguard']['main_activity']
                            print(mycolors.reset + mainactivity, end='')
                        if ('Package' in attrs['androguard']):
                            print(mycolors.foreground.lightred + "\n".ljust(22) + "Package: ".ljust(15), end='')
                            mainactivity = attrs['androguard']['Package']
                            print(mycolors.reset + mainactivity, end='\n')
                        if ('Providers' in attrs['androguard']):
                            print(mycolors.foreground.lightred + "\n".ljust(22) + "Providers: ".ljust(23), end='')
                            for provider in attrs['androguard']['Providers']:
                                print(mycolors.reset + "\n".ljust(37) + provider, end='')
                        if ('Receivers' in attrs['androguard']):
                            print(mycolors.foreground.lightred + "\n".ljust(22) + "Receivers: ".ljust(23), end='')
                            for receiver in attrs['androguard']['Receivers']:
                                print(mycolors.reset + "\n".ljust(37) + receiver, end='')
                        if ('Libraries' in attrs['androguard']):
                            print(mycolors.foreground.lightred + "\n".ljust(22) + "Libraries: ".ljust(23), end='')
                            for library in attrs['androguard']['Libraries']:
                                print(mycolors.reset + "\n".ljust(37) + library, end='')
                        if ('Services' in attrs['androguard']):
                            print(mycolors.foreground.lightred + "\n".ljust(22) + "Services: ".ljust(23), end='')
                            for service in attrs['androguard']['Services']:
                                print(mycolors.reset + "\n".ljust(37) + service, end='')
                        if ('StringsInformation' in attrs['androguard']):
                            print(mycolors.foreground.lightred + "\n".ljust(22) + "StringsInfo: ".ljust(23), end='')
                            for string in attrs['androguard']['StringsInformation']:
                                print(mycolors.reset + "\n".ljust(37) + string, end='')
                        if ('certificate' in attrs['androguard']):
                            print(mycolors.foreground.lightred + "\n".ljust(22) + "Certificate: ", end='')
                            if ('Issuer' in attrs['androguard']['certificate']):
                                print(mycolors.foreground.lightcyan + "\n".ljust(37) + "Issuer: ".ljust(15), end=' ')
                                if ('DN' in attrs['androguard']['certificate']['Issuer']):
                                    dn = attrs['androguard']['certificate']['Issuer']['DN']
                                    print(mycolors.reset + "DN: " + dn, end='')
                            if ('Subject' in attrs['androguard']['certificate']):
                                print(mycolors.foreground.lightcyan + "\n".ljust(37) + "Subject: ".ljust(15), end=' ')
                                if ('DN' in attrs['androguard']['certificate']['Subject']):
                                    dn = attrs['androguard']['certificate']['Subject']['DN']
                                    print(mycolors.reset + "DN: " + dn, end='')
                            if ('serialnumber' in attrs['androguard']['certificate']):
                                print(mycolors.foreground.lightcyan + "\n".ljust(37) + "SerialNumber: ".ljust(15), end=' ')
                                serialnumber = attrs['androguard']['certificate']['serialnumber']
                                print(mycolors.reset + serialnumber, end='')
                            if ('validfrom' in attrs['androguard']['certificate']):
                                print(mycolors.foreground.lightcyan + "\n".ljust(37) + "ValidFrom: ".ljust(15), end=' ')
                                validfrom = attrs['androguard']['certificate']['validfrom']
                                print(mycolors.reset + validfrom, end='')
                            if ('validto' in attrs['androguard']['certificate']):
                                print(mycolors.foreground.lightcyan + "\n".ljust(37) + "ValidTo: ".ljust(15), end=' ')
                                validto = attrs['androguard']['certificate']['validto']
                                print(mycolors.reset + validto, end='')
                            if ('thumbprint' in attrs['androguard']['certificate']):
                                print(mycolors.foreground.lightcyan + "\n".ljust(37) + "Thumbprint: ".ljust(15), end=' ')
                                thumbprint = attrs['androguard']['certificate']['thumbprint']
                                print(mycolors.reset + thumbprint, end='')
                        if ('intent_filters' in attrs['androguard']):
                            print(mycolors.foreground.lightred + "\n".ljust(22) + "IntentFilters: ", end='')
                            if ('Activities' in attrs['androguard']['intent_filters']):
                                print(mycolors.foreground.lightcyan + "\n".ljust(37) + "Activities: ".ljust(15), end=' ')
                                for key, value in (attrs['androguard']['intent_filters']['Activities']).items():
                                    print(mycolors.reset + "\n\n".ljust(54) + mycolors.foreground.yellow + "name: ".ljust(11) + mycolors.reset + key, end='')
                                    if ('action' in value):
                                        for action_item in value['action']:
                                            print(mycolors.reset + "\n".ljust(53) + mycolors.foreground.lightcyan + "action: ".ljust(11) + mycolors.reset + action_item, end='')
                                    if ('category' in value):
                                        for category in value['category']:
                                            print(mycolors.reset + "\n".ljust(53) + mycolors.foreground.lightcyan + "category: ".ljust(11) + mycolors.reset + category, end='')
                            if ('Receivers' in attrs['androguard']['intent_filters']):
                                print(mycolors.foreground.lightcyan + "\n".ljust(37) + "Receivers: ".ljust(15), end=' ')
                                for key, value in (attrs['androguard']['intent_filters']['Receivers']).items():
                                    print(mycolors.reset + "\n\n".ljust(54) + mycolors.foreground.yellow + "name: ".ljust(11) + mycolors.reset + key, end='')
                                    if ('action' in value):
                                        for action_item in value['action']:
                                            print(mycolors.reset + "\n".ljust(53) + mycolors.foreground.lightcyan + "action: ".ljust(11) + mycolors.reset + action_item, end='')
                                    if ('category' in value):
                                        for category in value['category']:
                                            print(mycolors.reset + "\n".ljust(53) + mycolors.foreground.lightcyan + "category: ".ljust(11) + mycolors.reset + category, end='')
                            if ('Services' in attrs['androguard']['intent_filters']):
                                print(mycolors.foreground.lightcyan + "\n".ljust(37) + "Services: ".ljust(15), end=' ')
                                for key, value in (attrs['androguard']['intent_filters']['Services']).items():
                                    print(mycolors.reset + "\n\n".ljust(54) + mycolors.foreground.yellow + "name: ".ljust(11) + mycolors.reset + key, end='')
                                    if ('action' in value):
                                        for action_item in value['action']:
                                            print(mycolors.reset + "\n".ljust(53) + mycolors.foreground.lightcyan + "action: ".ljust(11) + mycolors.reset + action_item, end='')
                                    if ('category' in value):
                                        for category in value['category']:
                                            print(mycolors.reset + "\n".ljust(53) + mycolors.foreground.lightcyan + "category: ".ljust(11) + mycolors.reset + category, end='')
                        if ('permission_details' in attrs['androguard']):
                            print(mycolors.foreground.lightred + "\n".ljust(22) + "Permissions: ", end='')
                            for key, value in (attrs['androguard']['permission_details']).items():
                                print(mycolors.reset + "\n\n".ljust(54) + mycolors.foreground.yellow + "name: ".ljust(11) + mycolors.reset + key, end='')
                                if ('full_description' in value):
                                    print(mycolors.reset + ("\n".ljust(53) + mycolors.foreground.lightcyan + "details: ".ljust(11) + mycolors.reset + (mycolors.reset + "\n".ljust(64)).join(textwrap.wrap(" ".join(value['full_description'].split()), width=80))), end=' ')
                                if ('permission_type' in value):
                                    print(mycolors.reset + "\n".ljust(53) + mycolors.foreground.lightcyan + "type: ".ljust(11) + mycolors.reset + value['permission_type'], end='')
                                if ('short_description' in value):
                                    print(mycolors.reset + ("\n".ljust(53) + mycolors.foreground.lightcyan + "info: ".ljust(11) + mycolors.reset + ("\n" + mycolors.reset + "".ljust(63)).join(textwrap.wrap(value['short_description'], width=80))), end=' ')

                    print("\n")

                    if (showreport == 1):
                        self.vtreportwork(myhash, 0)

                if (cv.bkg == 0):
                    if ('md5' in attrs):
                        md5hash = attrs['md5']
                        print(mycolors.foreground.cyan + "\nMD5 hash: ".ljust(22) + mycolors.reset + md5hash, end='')
                    if ('sha1' in attrs):
                        sha1hash = attrs['sha1']
                        print(mycolors.foreground.cyan + "\nSHA1 hash: ".ljust(22) + mycolors.reset + sha1hash, end='')
                    if ('sha256' in attrs):
                        sha256hash = attrs['sha256']
                        print(mycolors.foreground.cyan + "\nSHA256 hash: ".ljust(22) + mycolors.reset + sha256hash, end='')
                    if ('last_analysis_stats' in attrs):
                        malicious = attrs['last_analysis_stats']['malicious']
                        undetected = attrs['last_analysis_stats']['undetected']
                        print(mycolors.foreground.red + "\n\nMalicious: ".ljust(23) + mycolors.reset + str(malicious), end='')
                        print(mycolors.foreground.red + "\nUndetected: ".ljust(22) + mycolors.reset + str(undetected), end='\n')
                    if ('type_description' in attrs):
                        type_description = attrs['type_description']
                        print(mycolors.foreground.purple + "\nType Description: ".ljust(22) + mycolors.reset + type_description, end='')
                    if ('size' in attrs):
                        size = attrs['size']
                        print(mycolors.foreground.purple + "\nSize: ".ljust(22) + mycolors.reset + str(size), end='')
                    if ('last_analysis_date' in attrs):
                        last_analysis_date = attrs['last_analysis_date']
                        print(mycolors.foreground.purple + "\nLast Analysis Date: ".ljust(22) + mycolors.reset + str(datetime.fromtimestamp(last_analysis_date)), end='')
                    if ('type_tag' in attrs):
                        type_tag = attrs['type_tag']
                        print(mycolors.foreground.cyan + "\nType Tag: ".ljust(22) + mycolors.reset + type_tag, end='')
                    if ('times_submitted' in attrs):
                        times_submitted = attrs['times_submitted']
                        print(mycolors.foreground.cyan + "\nTimes Submitted: ".ljust(22) + mycolors.reset + str(times_submitted), end='')
                    if ('popular_threat_classification' in attrs):
                        print(mycolors.foreground.red + "\n\nThreat Label: ".ljust(23), end='')
                        if ('suggested_threat_label' in attrs['popular_threat_classification']):
                            threat_label = attrs['popular_threat_classification']['suggested_threat_label']
                        else:
                            threat_label = 'NO GIVEN NAME'
                        print(mycolors.reset + str(threat_label), end='')
                        if ('popular_threat_category' in attrs['popular_threat_classification']):
                            print(mycolors.foreground.red + "\nClassification: ", end='')
                            for popular in attrs['popular_threat_classification']['popular_threat_category']:
                                count = popular['count']
                                value = popular['value']
                                print(mycolors.reset + "\n".ljust(22) + "popular count: ".ljust(15) + str(count), end='')
                                print(mycolors.reset + "\n".ljust(22) + "label: ".ljust(15) + str(value), end='\n')
                    if ('trid' in attrs):
                        print(mycolors.foreground.cyan + "\nTrid: ", end='')
                        for trid in attrs['trid']:
                            file_type = trid['file_type']
                            probability = trid['probability']
                            print(mycolors.reset + "\n".ljust(22) + "file_type: ".ljust(15) + str(file_type), end='')
                            print(mycolors.reset + "\n".ljust(22) + "probability: ".ljust(15) + str(probability), end='\n')
                    if ('names' in attrs):
                        print(mycolors.foreground.cyan + "\nNames: ", end='')
                        for name in attrs['names']:
                            print(mycolors.reset + ("\n".ljust(22) + (mycolors.reset + "\n".ljust(22)).join(textwrap.wrap(" ".join(name.split()), width=80))), end=' ')
                    if ('pe_info' in attrs):
                        print(mycolors.foreground.red + "\n\nPE Info: ", end='')
                        if ('imphash' in attrs['pe_info']):
                            imphash = attrs['pe_info']['imphash']
                            print(mycolors.foreground.blue + "\n".ljust(22) + "Imphash: ".ljust(15) + mycolors.reset + str(imphash), end='')
                        if ('import_list' in attrs['pe_info']):
                            print(mycolors.foreground.blue + "\n".ljust(22) + "Libraries: ".ljust(15), end='')
                            for lib in attrs['pe_info']['import_list']:
                                print(mycolors.reset + "\n".ljust(37) + str(lib['library_name']), end='')
                        if ('sections' in attrs['pe_info']):
                            print(mycolors.foreground.blue + "\n".ljust(22) + "Sections: ", end='')
                            for section in attrs['pe_info']['sections']:
                                if ('name' in section):
                                    section_name = section['name']
                                    print(mycolors.reset + "\n\n".ljust(38) + "section_name: ".ljust(14) + str(section_name), end=' ')
                                if ('virtual_size' in section):
                                    virtual_size = section['virtual_size']
                                    print(mycolors.reset + "\n".ljust(37) + "virtual_size: ".ljust(14) + str(virtual_size), end=' ')
                                if ('entropy' in section):
                                    entropy = section['entropy']
                                    print(mycolors.reset + "\n".ljust(37) + "entropy: ".ljust(14) + str(entropy), end=' ')
                                if ('flags' in section):
                                    flags = section['flags']
                                    print(mycolors.reset + "\n".ljust(37) + "flags: ".ljust(14) + str(flags), end=' ')
                    if ('androguard' in attrs):
                        print(mycolors.foreground.cyan + "\n\nAndroguard: ", end='')
                        if ('Activities' in attrs['androguard']):
                            print(mycolors.foreground.red + "\n".ljust(22) + "Activities: ".ljust(23), end='')
                            for activity in attrs['androguard']['Activities']:
                                print(mycolors.reset + "\n".ljust(37) + activity, end='')
                        if ('main_activity' in attrs['androguard']):
                            print(mycolors.foreground.red + "\n\n".ljust(23) + "MainActivity: ".ljust(15), end='')
                            mainactivity = attrs['androguard']['main_activity']
                            print(mycolors.reset + mainactivity, end='')
                        if ('Package' in attrs['androguard']):
                            print(mycolors.foreground.red + "\n".ljust(22) + "Package: ".ljust(15), end='')
                            mainactivity = attrs['androguard']['Package']
                            print(mycolors.reset + mainactivity, end='\n')
                        if ('Providers' in attrs['androguard']):
                            print(mycolors.foreground.red + "\n".ljust(22) + "Providers: ".ljust(23), end='')
                            for provider in attrs['androguard']['Providers']:
                                print(mycolors.reset + "\n".ljust(37) + provider, end='')
                        if ('Receivers' in attrs['androguard']):
                            print(mycolors.foreground.red + "\n".ljust(22) + "Receivers: ".ljust(23), end='')
                            for receiver in attrs['androguard']['Receivers']:
                                print(mycolors.reset + "\n".ljust(37) + receiver, end='')
                        if ('Libraries' in attrs['androguard']):
                            print(mycolors.foreground.red + "\n".ljust(22) + "Libraries: ".ljust(23), end='')
                            for library in attrs['androguard']['Libraries']:
                                print(mycolors.reset + "\n".ljust(37) + library, end='')
                        if ('Services' in attrs['androguard']):
                            print(mycolors.foreground.red + "\n".ljust(22) + "Services: ".ljust(23), end='')
                            for service in attrs['androguard']['Services']:
                                print(mycolors.reset + "\n".ljust(37) + service, end='')
                        if ('StringsInformation' in attrs['androguard']):
                            print(mycolors.foreground.red + "\n".ljust(22) + "StringsInfo: ".ljust(23), end='')
                            for string in attrs['androguard']['StringsInformation']:
                                print(mycolors.reset + "\n".ljust(37) + string, end='')
                        if ('certificate' in attrs['androguard']):
                            print(mycolors.foreground.red + "\n".ljust(22) + "Certificate: ", end='')
                            if ('Issuer' in attrs['androguard']['certificate']):
                                print(mycolors.foreground.blue + "\n".ljust(37) + "Issuer: ".ljust(15), end=' ')
                                if ('DN' in attrs['androguard']['certificate']['Issuer']):
                                    dn = attrs['androguard']['certificate']['Issuer']['DN']
                                    print(mycolors.reset + "DN: " + dn, end='')
                            if ('Subject' in attrs['androguard']['certificate']):
                                print(mycolors.foreground.blue + "\n".ljust(37) + "Subject: ".ljust(15), end=' ')
                                if ('DN' in attrs['androguard']['certificate']['Subject']):
                                    dn = attrs['androguard']['certificate']['Subject']['DN']
                                    print(mycolors.reset + "DN: " + dn, end='')
                            if ('serialnumber' in attrs['androguard']['certificate']):
                                print(mycolors.foreground.blue + "\n".ljust(37) + "SerialNumber: ".ljust(15), end=' ')
                                serialnumber = attrs['androguard']['certificate']['serialnumber']
                                print(mycolors.reset + serialnumber, end='')
                            if ('validfrom' in attrs['androguard']['certificate']):
                                print(mycolors.foreground.blue + "\n".ljust(37) + "ValidFrom: ".ljust(15), end=' ')
                                validfrom = attrs['androguard']['certificate']['validfrom']
                                print(mycolors.reset + validfrom, end='')
                            if ('validto' in attrs['androguard']['certificate']):
                                print(mycolors.foreground.blue + "\n".ljust(37) + "ValidTo: ".ljust(15), end=' ')
                                validto = attrs['androguard']['certificate']['validto']
                                print(mycolors.reset + validto, end='')
                            if ('thumbprint' in attrs['androguard']['certificate']):
                                print(mycolors.foreground.blue + "\n".ljust(37) + "Thumbprint: ".ljust(15), end=' ')
                                thumbprint = attrs['androguard']['certificate']['thumbprint']
                                print(mycolors.reset + thumbprint, end='')
                        if ('intent_filters' in attrs['androguard']):
                            print(mycolors.foreground.red + "\n".ljust(22) + "IntentFilters: ", end='')
                            if ('Activities' in attrs['androguard']['intent_filters']):
                                print(mycolors.foreground.blue + "\n".ljust(37) + "Activities: ".ljust(15), end=' ')
                                for key, value in (attrs['androguard']['intent_filters']['Activities']).items():
                                    print(mycolors.reset + "\n\n".ljust(54) + mycolors.foreground.purple + "name: ".ljust(11) + mycolors.reset + key, end='')
                                    if ('action' in value):
                                        for action_item in value['action']:
                                            print(mycolors.reset + "\n".ljust(53) + mycolors.foreground.cyan + "action: ".ljust(11) + mycolors.reset + action_item, end='')
                                    if ('category' in value):
                                        for category in value['category']:
                                            print(mycolors.reset + "\n".ljust(53) + mycolors.foreground.cyan + "category: ".ljust(11) + mycolors.reset + category, end='')
                            if ('Receivers' in attrs['androguard']['intent_filters']):
                                print(mycolors.foreground.blue + "\n".ljust(37) + "Receivers: ".ljust(15), end=' ')
                                for key, value in (attrs['androguard']['intent_filters']['Receivers']).items():
                                    print(mycolors.reset + "\n\n".ljust(54) + mycolors.foreground.purple + "name: ".ljust(11) + mycolors.reset + key, end='')
                                    if ('action' in value):
                                        for action_item in value['action']:
                                            print(mycolors.reset + "\n".ljust(53) + mycolors.foreground.cyan + "action: ".ljust(11) + mycolors.reset + action_item, end='')
                                    if ('category' in value):
                                        for category in value['category']:
                                            print(mycolors.reset + "\n".ljust(53) + mycolors.foreground.cyan + "category: ".ljust(11) + mycolors.reset + category, end='')
                            if ('Services' in attrs['androguard']['intent_filters']):
                                print(mycolors.foreground.blue + "\n".ljust(37) + "Services: ".ljust(15), end=' ')
                                for key, value in (attrs['androguard']['intent_filters']['Services']).items():
                                    print(mycolors.reset + "\n\n".ljust(54) + mycolors.foreground.purple + "name: ".ljust(11) + mycolors.reset + key, end='')
                                    if ('action' in value):
                                        for action_item in value['action']:
                                            print(mycolors.reset + "\n".ljust(53) + mycolors.foreground.cyan + "action: ".ljust(11) + mycolors.reset + action_item, end='')
                                    if ('category' in value):
                                        for category in value['category']:
                                            print(mycolors.reset + "\n".ljust(53) + mycolors.foreground.cyan + "category: ".ljust(11) + mycolors.reset + category, end='')
                        if ('permission_details' in attrs['androguard']):
                            print(mycolors.foreground.red + "\n".ljust(22) + "Permissions: ", end='')
                            for key, value in (attrs['androguard']['permission_details']).items():
                                print(mycolors.reset + "\n\n".ljust(54) + mycolors.foreground.purple + "name: ".ljust(11) + mycolors.reset + key, end='')
                                if ('full_description' in value):
                                    print(mycolors.reset + ("\n".ljust(53) + mycolors.foreground.cyan + "details: ".ljust(11) + mycolors.reset + (mycolors.reset + "\n".ljust(64)).join(textwrap.wrap(" ".join(value['full_description'].split()), width=80))), end=' ')
                                if ('permission_type' in value):
                                    print(mycolors.reset + "\n".ljust(53) + mycolors.foreground.cyan + "type: ".ljust(11) + mycolors.reset + value['permission_type'], end='')
                                if ('short_description' in value):
                                    print(mycolors.reset + ("\n".ljust(53) + mycolors.foreground.cyan + "info: ".ljust(11) + mycolors.reset + ("\n" + mycolors.reset + "".ljust(63)).join(textwrap.wrap(value['short_description'], width=80))), end=' ')

                    print("\n")

                    if (showreport == 1):
                        self.vtreportwork(myhash, 0)
        except ValueError:
            if (cv.bkg == 1):
                print((mycolors.foreground.lightred + "Error while connecting to Virus Total!\n"))
            else:
                print((mycolors.foreground.red + "Error while connecting to Virus Total!\n"))
            print(mycolors.reset)
            exit(3)

    def vtlargefile(self, file_item):
        url = VirusTotalExtractor.urlfilevt3

        try:
            finalurl = ''.join([url, "/upload_url"])
            requestsession = requests.Session()
            requestsession.headers.update({'x-apikey': self.VTAPI})
            requestsession.headers.update({'content-type': 'application/json'})
            response = requestsession.get(finalurl)
            vttext = json.loads(response.text)

            if (response.status_code == 404):
                if (cv.bkg == 1):
                    print(mycolors.foreground.yellow + "\tThere was an issue while getting a URL for uploading the file.")
                if (cv.bkg == 0):
                    print(mycolors.foreground.blue + "\tThere was an issue while getting a URL for uploading the file.")
            else:
                if (cv.bkg == 1):
                    print(mycolors.foreground.yellow + "\n\tUploading file...")
                    self.vtuploadfile(file_item, url=vttext['data'])
                if (cv.bkg == 0):
                    print(mycolors.foreground.blue + "\n\tUploading file...")
                    self.vtuploadfile(file_item, url=vttext['data'])

        except ValueError:
            if (cv.bkg == 1):
                print((mycolors.foreground.lightred + "Error while connecting to Virus Total!\n"))
            else:
                print((mycolors.foreground.red + "Error while connecting to Virus Total!\n"))
            print(mycolors.reset)
            exit(3)

    def vtbatchwork(self, myhash):
        url = VirusTotalExtractor.urlfilevt3

        type_description = 'NOT FOUND'
        threat_label = 'NOT FOUND'
        malicious = 'NOT FOUND'

        try:

            finalurl = ''.join([url, "/", myhash])
            requestsession = requests.Session()
            requestsession.headers.update({'x-apikey': self.VTAPI})
            requestsession.headers.update({'content-type': 'application/json'})
            response = requestsession.get(finalurl)
            vttext = json.loads(response.text)
            attrs = vttext.get('data', {}).get('attributes', {})

            if (response.status_code == 404):
                return (type_description, threat_label, malicious)
            else:
                if ('type_description' in attrs):
                    type_description = attrs['type_description']
                else:
                    type_description = 'NO DESCRIPTION'
                if ('popular_threat_classification' in attrs):
                    if ('suggested_threat_label' in attrs['popular_threat_classification']):
                        threat_label = attrs['popular_threat_classification']['suggested_threat_label']
                else:
                    threat_label = 'NO GIVEN NAME'
                if ('last_analysis_stats' in attrs):
                    if ('malicious' in attrs['last_analysis_stats']):
                        malicious = attrs['last_analysis_stats']['malicious']
                else:
                    malicious = 'NOT FOUND'

                return (type_description, threat_label, malicious)

        except ValueError:
            if (cv.bkg == 1):
                print((mycolors.foreground.lightred + "Error while connecting to Virus Total!\n"))
            else:
                print((mycolors.foreground.red + "Error while connecting to Virus Total!\n"))
            print(mycolors.reset)
            exit(3)

    def vtbatchcheck(self, filename, apitype):
        type_description = ''
        threat_label = ''
        malicious = ''
        apitype_var = apitype

        try:
            print("\nSample".center(10) + "Hash".center(68) + "Description".center(30) + "Threat Label".center(26) + "AV Detection".center(24))
            print('-' * 152, end="\n\n")

            fh = open(filename, 'r')
            filelines = fh.readlines()

            hashnumber = 0
            for hashitem in filelines:
                hashnumber = hashnumber + 1
                (type_description, threat_label, malicious) = self.vtbatchwork(hashitem)
                if (type_description == "NOT FOUND"):
                    if (cv.bkg == 1):
                        print(mycolors.foreground.lightcyan + "hash_" + str(hashnumber) + "\t   " + mycolors.reset + (hashitem.strip()).ljust(79) + mycolors.foreground.yellow + (type_description).ljust(28) + mycolors.foreground.lightcyan + (threat_label).ljust(26) + mycolors.foreground.lightred + str(malicious))
                    if (cv.bkg == 0):
                        print(mycolors.foreground.purple + "hash_" + str(hashnumber) + "\t   " + mycolors.reset + (hashitem.strip()).ljust(79) + mycolors.foreground.cyan + (type_description).ljust(28) + mycolors.foreground.blue + (threat_label).ljust(26) + mycolors.foreground.red + str(malicious))
                    if (apitype_var == 1):
                        if ((hashnumber % 4) == 0):
                            time.sleep(61)
                else:
                    if (cv.bkg == 1):
                        print(mycolors.foreground.lightcyan + "hash_" + str(hashnumber) + "\t   " + mycolors.reset + (hashitem.strip()).ljust(68) + mycolors.foreground.yellow + (type_description).ljust(30) + mycolors.foreground.lightcyan + (threat_label).ljust(34) + mycolors.foreground.lightred + str(malicious))
                    if (cv.bkg == 0):
                        print(mycolors.foreground.purple + "hash_" + str(hashnumber) + "\t   " + mycolors.reset + (hashitem.strip()).ljust(68) + mycolors.foreground.cyan + (type_description).ljust(30) + mycolors.foreground.blue + (threat_label).ljust(34) + mycolors.foreground.red + str(malicious))
                    if (apitype_var == 1):
                        if ((hashnumber % 4) == 0):
                            time.sleep(61)
            fh.close()
        except OSError:
            if (cv.bkg == 1):
                print((mycolors.foreground.lightred + "The provided file doesn't exist!\n"))
            else:
                print((mycolors.foreground.red + "The provided file doesn't exist!\n"))
            print(mycolors.reset)
            exit(3)

    def vtbehavior(self, myhash):
        url = VirusTotalExtractor.urlfilevt3

        try:
            finalurl = ''.join([url, "/", myhash, "/behaviour_summary"])
            requestsession = requests.Session()
            requestsession.headers.update({'x-apikey': self.VTAPI})
            requestsession.headers.update({'content-type': 'application/json'})
            response = requestsession.get(finalurl)
            vttext = json.loads(response.text)

            if (response.status_code == 404):
                if (cv.bkg == 1):
                    print(mycolors.foreground.yellow + "\tReport not found for the provided hash!")
                if (cv.bkg == 0):
                    print(mycolors.foreground.blue + "\tReport not found for the provided hash!")
            else:
                if (cv.bkg == 1):
                    finalhash = myhash
                    print(mycolors.foreground.lightred + "\nProvided Hash: ".ljust(24) + mycolors.reset + finalhash)
                    if ('verdicts' in vttext['data']):
                        print(mycolors.foreground.yellow + "Verdicts: ".ljust(22) + mycolors.reset, end=' ')
                        for verdict in vttext['data']['verdicts']:
                            print(mycolors.reset + (verdict), end=' | ')
                    if ('verdict_confidence' in vttext['data']):
                        print(mycolors.foreground.yellow + "\nVerdict Confidence: ".ljust(24) + mycolors.reset + str(vttext['data']['verdict_confidence']) + mycolors.reset, end=' ')
                    if ('verdict_labels' in vttext['data']):
                        print(mycolors.foreground.yellow + "\nVerdict Labels: ".ljust(23) + mycolors.reset, end=' ')
                        for label in vttext['data']['verdict_labels']:
                            print(mycolors.reset + (label), end=' ')
                    if ('processes_injected' in vttext['data']):
                        print(mycolors.foreground.lightred + "\n\nProcesses Injected: ", end='')
                        for injected in vttext['data']['processes_injected']:
                            print(mycolors.reset + ("\n".ljust(24) + ("\n" + "".ljust(24)).join(textwrap.wrap(injected, width=120))), end=' ')
                    if ('calls_highlighted' in vttext['data']):
                        print(mycolors.foreground.lightred + "\n\nCalls Highlighted: ", end='')
                        for calls in vttext['data']['calls_highlighted']:
                            print(mycolors.reset + ("\n".ljust(24) + ("\n" + "".ljust(24)).join(textwrap.wrap(calls, width=120))), end=' ')
                    if ('processes_tree' in vttext['data']):
                        print(mycolors.foreground.lightcyan + "\n\nProcesses Tree: ", end='')
                        for process in vttext['data']['processes_tree']:
                            print("\n")
                            print(mycolors.reset + " ".ljust(23) + "process_id: ".ljust(15) + process['process_id'], end='')
                            print(mycolors.reset + ("\n".ljust(24) + "process_name: ".ljust(15) + mycolors.reset + (mycolors.reset + "\n".ljust(39)).join(textwrap.wrap(" ".join(process['name'].split()), width=80))), end=' ')
                            if ('children' in process):
                                print(mycolors.reset + "\n".ljust(24) + "children: ".ljust(15), end='')
                                for child in process['children']:
                                    print(mycolors.reset + "\n".ljust(28) + "process_id: ".ljust(15) + child['process_id'], end='')
                                    print(mycolors.reset + ("\n".ljust(28) + "process_name: ".ljust(15) + mycolors.reset + (mycolors.reset + "\n".ljust(43)).join(textwrap.wrap(" ".join(child['name'].split()), width=80))), end=' ')
                    if ('processes_terminated' in vttext['data']):
                        print(mycolors.foreground.lightcyan + "\n\nProcesses Terminated: ", end='\n')
                        for process_term in vttext['data']['processes_terminated']:
                            print(mycolors.reset + "".ljust(23) + process_term, end='\n')
                    if ('processes_killed' in vttext['data']):
                        print(mycolors.foreground.lightcyan + "\n\nProcesses Killed: ", end='\n')
                        for process_kill in vttext['data']['processes_killed']:
                            print(mycolors.reset + "".ljust(23) + process_kill, end='\n')
                    if ('services_created' in vttext['data']):
                        print(mycolors.foreground.lightred + "\n\nServices Created: ", end='\n')
                        for services_created in vttext['data']['services_created']:
                            print(mycolors.reset + "".ljust(23) + services_created, end='\n')
                    if ('services_deleted' in vttext['data']):
                        print(mycolors.foreground.lightred + "\n\nServices Deleted: ", end='\n')
                        for services_deleted in vttext['data']['services_deleted']:
                            print(mycolors.reset + "".ljust(23) + services_deleted, end='\n')
                    if ('services_started' in vttext['data']):
                        print(mycolors.foreground.lightred + "\n\nServices Started: ", end='\n')
                        for services_started in vttext['data']['services_started']:
                            print(mycolors.reset + "".ljust(23) + services_started, end='\n')
                    if ('services_stopped' in vttext['data']):
                        print(mycolors.foreground.lightred + "\n\nServices Stopped: ", end='\n')
                        for services_stopped in vttext['data']['services_stopped']:
                            print(mycolors.reset + "".ljust(23) + services_stopped, end='\n')
                    if ('dns_lookups' in vttext['data']):
                        print(mycolors.foreground.yellow + "\nDNS Lookups: ", end='')
                        for lookup in vttext['data']['dns_lookups']:
                            if ('resolved_ips' in lookup):
                                print(mycolors.reset + "\n".ljust(24) + "resolved_ips: ", end='')
                                for ip in (lookup['resolved_ips']):
                                    print(ip, end=' | ')
                            if ('hostname' in lookup):
                                print(mycolors.reset + "\n".ljust(24) + "hostname: ".ljust(14) + lookup['hostname'], end='\n')
                    if ('ja3_digests' in vttext['data']):
                        print(mycolors.foreground.yellow + "\n\nJA3 Digests: ", end='\n')
                        for ja3 in vttext['data']['ja3_digests']:
                            print(mycolors.reset + "".ljust(23) + ja3, end='\n')
                    if ('modules_loaded' in vttext['data']):
                        print(mycolors.foreground.yellow + "\nModules Loaded: ", end='')
                        for module in vttext['data']['modules_loaded']:
                            print(mycolors.reset + ("\n".ljust(24) + ("\n" + "".ljust(24)).join(textwrap.wrap(module, width=120))), end=' ')
                    if ('registry_keys_opened' in vttext['data']):
                        print(mycolors.foreground.yellow + "\n\nRegistry Keys Opened: ", end='')
                        for key in vttext['data']['registry_keys_opened']:
                            print(mycolors.reset + ("\n".ljust(24) + ("\n" + "".ljust(24)).join(textwrap.wrap(key, width=120))), end=' ')
                    if ('files_opened' in vttext['data']):
                        print(mycolors.foreground.lightcyan + "\n\nFiles Opened: ", end='')
                        for filename in vttext['data']['files_opened']:
                            print(mycolors.reset + ("\n".ljust(24) + ("\n" + "".ljust(24)).join(textwrap.wrap(filename, width=120))), end=' ')
                    if ('files_written' in vttext['data']):
                        print(mycolors.foreground.lightcyan + "\n\nFiles Written: ", end='')
                        for filewritten in vttext['data']['files_written']:
                            print(mycolors.reset + ("\n".ljust(24) + ("\n" + "".ljust(24)).join(textwrap.wrap(filewritten, width=120))), end=' ')
                    if ('files_deleted' in vttext['data']):
                        print(mycolors.foreground.lightcyan + "\n\nFiles Deleted: ", end='')
                        for filedeleted in vttext['data']['files_deleted']:
                            print(mycolors.reset + ("\n".ljust(24) + ("\n" + "".ljust(24)).join(textwrap.wrap(filedeleted, width=120))), end=' ')
                    if ('command_executions' in vttext['data']):
                        print(mycolors.foreground.yellow + "\n\nCommand Executions: ", end='')
                        for command in vttext['data']['command_executions']:
                            print(mycolors.reset + ("\n".ljust(24) + ("\n" + "".ljust(24)).join(textwrap.wrap(command, width=120))), end=' ')
                    if ('mutexes_created' in vttext['data']):
                        print(mycolors.foreground.yellow + "\n\nMutex Created: ", end='')
                        for mutex in vttext['data']['mutexes_created']:
                            print(mycolors.reset + ("\n".ljust(24) + ("\n" + "".ljust(24)).join(textwrap.wrap(mutex, width=120))), end=' ')
                    if ('windows_hidden' in vttext['data']):
                        print(mycolors.foreground.yellow + "\n\nWindows Hidden: ", end='\n')
                        for windows_hidden in vttext['data']['windows_hidden']:
                            print(mycolors.reset + "".ljust(23) + windows_hidden, end='\n')

                if (cv.bkg == 0):
                    finalhash = myhash
                    print(mycolors.foreground.red + "\nProvided Hash: ".ljust(24) + mycolors.reset + finalhash)
                    if ('verdicts' in vttext['data']):
                        print(mycolors.foreground.purple + "Verdicts: ".ljust(22) + mycolors.reset, end=' ')
                        for verdict in vttext['data']['verdicts']:
                            print(mycolors.reset + (verdict), end=' | ')
                    if ('verdict_confidence' in vttext['data']):
                        print(mycolors.foreground.purple + "\nVerdict Confidence: ".ljust(24) + mycolors.reset + str(vttext['data']['verdict_confidence']) + mycolors.reset, end=' ')
                    if ('verdict_labels' in vttext['data']):
                        print(mycolors.foreground.purple + "\nVerdict Labels: ".ljust(23) + mycolors.reset, end=' ')
                        for label in vttext['data']['verdict_labels']:
                            print(mycolors.reset + (label), end=' ')
                    if ('processes_injected' in vttext['data']):
                        print(mycolors.foreground.red + "\n\nProcesses Injected: ", end='')
                        for injected in vttext['data']['processes_injected']:
                            print(mycolors.reset + ("\n".ljust(24) + ("\n" + "".ljust(24)).join(textwrap.wrap(injected, width=120))), end=' ')
                    if ('calls_highlighted' in vttext['data']):
                        print(mycolors.foreground.red + "\n\nCalls Highlighted: ", end='')
                        for calls in vttext['data']['calls_highlighted']:
                            print(mycolors.reset + ("\n".ljust(24) + ("\n" + "".ljust(24)).join(textwrap.wrap(calls, width=120))), end=' ')
                    if ('processes_tree' in vttext['data']):
                        print(mycolors.foreground.blue + "\n\nProcesses Tree: ", end='')
                        for process in vttext['data']['processes_tree']:
                            print("\n")
                            print(mycolors.reset + " ".ljust(23) + "process_id: ".ljust(15) + process['process_id'], end='')
                            print(mycolors.reset + ("\n".ljust(24) + "process_name: ".ljust(15) + mycolors.reset + (mycolors.reset + "\n".ljust(39)).join(textwrap.wrap(" ".join(process['name'].split()), width=80))), end=' ')
                            if ('children' in process):
                                print(mycolors.reset + "\n".ljust(24) + "children: ".ljust(15), end='')
                                for child in process['children']:
                                    print(mycolors.reset + "\n".ljust(28) + "process_id: ".ljust(15) + child['process_id'], end='')
                                    print(mycolors.reset + ("\n".ljust(28) + "process_name: ".ljust(15) + mycolors.reset + (mycolors.reset + "\n".ljust(43)).join(textwrap.wrap(" ".join(child['name'].split()), width=80))), end=' ')
                    if ('processes_terminated' in vttext['data']):
                        print(mycolors.foreground.blue + "\n\nProcesses Terminated: ", end='\n')
                        for process_term in vttext['data']['processes_terminated']:
                            print(mycolors.reset + "".ljust(23) + process_term, end='\n')
                    if ('processes_killed' in vttext['data']):
                        print(mycolors.foreground.blue + "\n\nProcesses Killed: ", end='\n')
                        for process_kill in vttext['data']['processes_killed']:
                            print(mycolors.reset + "".ljust(23) + process_kill, end='\n')
                    if ('services_created' in vttext['data']):
                        print(mycolors.foreground.blue + "\n\nServices Created: ", end='\n')
                        for services_created in vttext['data']['services_created']:
                            print(mycolors.reset + "".ljust(23) + services_created, end='\n')
                    if ('services_deleted' in vttext['data']):
                        print(mycolors.foreground.blue + "\n\nServices Deleted: ", end='\n')
                        for services_deleted in vttext['data']['services_deleted']:
                            print(mycolors.reset + "".ljust(23) + services_deleted, end='\n')
                    if ('services_started' in vttext['data']):
                        print(mycolors.foreground.blue + "\n\nServices Started: ", end='\n')
                        for services_started in vttext['data']['services_started']:
                            print(mycolors.reset + "".ljust(23) + services_started, end='\n')
                    if ('services_stopped' in vttext['data']):
                        print(mycolors.foreground.blue + "\n\nServices Stopped: ", end='\n')
                        for services_stopped in vttext['data']['services_stopped']:
                            print(mycolors.reset + "".ljust(23) + services_stopped, end='\n')
                    if ('dns_lookups' in vttext['data']):
                        print(mycolors.foreground.blue + "\nDNS Lookups: ", end='')
                        for lookup in vttext['data']['dns_lookups']:
                            if ('resolved_ips' in lookup):
                                print(mycolors.reset + "\n".ljust(24) + "resolved_ips: ", end='')
                                for ip in (lookup['resolved_ips']):
                                    print(ip, end=' | ')
                            if ('hostname' in lookup):
                                print(mycolors.reset + "\n".ljust(24) + "hostname: ".ljust(14) + lookup['hostname'], end='\n')
                    if ('ja3_digests' in vttext['data']):
                        print(mycolors.foreground.blue + "\n\nJA3 Digests: ", end='\n')
                        for ja3 in vttext['data']['ja3_digests']:
                            print(mycolors.reset + "".ljust(23) + ja3, end='\n')
                    if ('modules_loaded' in vttext['data']):
                        print(mycolors.foreground.blue + "\nModules Loaded: ", end='')
                        for module in vttext['data']['modules_loaded']:
                            print(mycolors.reset + ("\n".ljust(24) + ("\n" + "".ljust(24)).join(textwrap.wrap(module, width=120))), end=' ')
                    if ('registry_keys_opened' in vttext['data']):
                        print(mycolors.foreground.blue + "\n\nRegistry Keys Opened: ", end='')
                        for key in vttext['data']['registry_keys_opened']:
                            print(mycolors.reset + ("\n".ljust(24) + ("\n" + "".ljust(24)).join(textwrap.wrap(key, width=120))), end=' ')
                    if ('files_opened' in vttext['data']):
                        print(mycolors.foreground.blue + "\n\nFiles Opened: ", end='')
                        for filename in vttext['data']['files_opened']:
                            print(mycolors.reset + ("\n".ljust(24) + ("\n" + "".ljust(24)).join(textwrap.wrap(filename, width=120))), end=' ')
                    if ('files_written' in vttext['data']):
                        print(mycolors.foreground.blue + "\n\nFiles Written: ", end='')
                        for filewritten in vttext['data']['files_written']:
                            print(mycolors.reset + ("\n".ljust(24) + ("\n" + "".ljust(24)).join(textwrap.wrap(filewritten, width=120))), end=' ')
                    if ('files_deleted' in vttext['data']):
                        print(mycolors.foreground.blue + "\n\nFiles Deleted: ", end='')
                        for filedeleted in vttext['data']['files_deleted']:
                            print(mycolors.reset + ("\n".ljust(24) + ("\n" + "".ljust(24)).join(textwrap.wrap(filedeleted, width=120))), end=' ')
                    if ('command_executions' in vttext['data']):
                        print(mycolors.foreground.purple + "\n\nCommand Executions: ", end='')
                        for command in vttext['data']['command_executions']:
                            print(mycolors.reset + ("\n".ljust(24) + ("\n" + "".ljust(24)).join(textwrap.wrap(command, width=120))), end=' ')
                    if ('mutexes_created' in vttext['data']):
                        print(mycolors.foreground.purple + "\n\nMutex Created: ", end='')
                        for mutex in vttext['data']['mutexes_created']:
                            print(mycolors.reset + ("\n".ljust(24) + ("\n" + "".ljust(24)).join(textwrap.wrap(mutex, width=120))), end=' ')
                    if ('windows_hidden' in vttext['data']):
                        print(mycolors.foreground.purple + "\n\nWindows Hidden: ", end='\n')
                        for windows_hidden in vttext['data']['windows_hidden']:
                            print(mycolors.reset + "".ljust(23) + windows_hidden, end='\n')

        except ValueError:
            if (cv.bkg == 1):
                print((mycolors.foreground.lightred + "Error while connecting to Virus Total!\n"))
            else:
                print((mycolors.foreground.red + "Error while connecting to Virus Total!\n"))
            print(mycolors.reset)
            exit(3)

    def vtdirchecking(self, repo2, apitype):
        F = []
        H = []
        type_description = ''
        threat_label = ''
        malicious = ''
        apitype_var = apitype

        directory = repo2
        if not os.path.isabs(directory):
            directory = os.path.abspath('.') + "/" + directory
        os.chdir(directory)

        try:
            for filen in os.listdir(directory):
                try:
                    filename = str(filen)
                    if os.path.isdir(filename):
                        continue
                    F.append(filename)
                    H.append(sha256hash(filename))

                except (AttributeError, NameError):
                    if (cv.bkg == 1):
                        print(mycolors.foreground.lightred + "\nAn error has occured while reading the %s file." % filename)
                    else:
                        print(mycolors.foreground.red + "\nAn error has occured while reading the %s file." % filename)
                    print(mycolors.reset)

            file_hash_dict = dict(list(zip(F, H)))

            print("\nSample".center(10) + "Filename".center(72) + "Description".center(26) + "Threat Label".center(28) + "AV Detection".center(26))
            print('-' * 154, end="\n\n")

            hashnumber = 0

            for key, value in file_hash_dict.items():
                hashnumber = hashnumber + 1
                (type_description, threat_label, malicious) = self.vtbatchwork(value)
                if (cv.bkg == 1):
                    print(mycolors.foreground.lightcyan + "file_" + str(hashnumber) + "\t   " + mycolors.reset + (key.strip()).ljust(71) + mycolors.foreground.yellow + (type_description).ljust(30) + mycolors.foreground.lightcyan + (threat_label).ljust(34) + mycolors.foreground.lightred + str(malicious))
                if (cv.bkg == 0):
                    print(mycolors.foreground.blue + "file_" + str(hashnumber) + "\t   " + mycolors.reset + (key.strip()).ljust(71) + mycolors.foreground.cyan + (type_description).ljust(30) + mycolors.foreground.blue + (threat_label).ljust(34) + mycolors.foreground.red + str(malicious))
                if (apitype_var == 1):
                    if ((hashnumber % 4) == 0):
                        time.sleep(61)
        except OSError:
            if (cv.bkg == 1):
                print((mycolors.foreground.lightred + "The provided file doesn't exist!\n"))
            else:
                print((mycolors.foreground.red + "The provided file doesn't exist!\n"))
            print(mycolors.reset)
            exit(3)
