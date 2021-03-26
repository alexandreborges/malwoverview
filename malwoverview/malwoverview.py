#!/usr/bin/env python3

# Copyright (C)  2018-2021 Alexandre Borges <alexandreborges@blackstormsecurity.com>
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

#CONTRIBUTORS

# Alexandre Borges (project owner)
# Corey Forman (https://github.com/digitalsleuth)
# Christian Clauss (https://github.com/cclauss)

# Malwoverview.py: version 4.3.2

import os
import sys
import re
import pefile
import peutils
import magic
import argparse
import requests
import hashlib
import json
import time
import validators
import geocoder
import threading
import socket
import urllib3
import subprocess
import types
import textwrap
import base64
import configparser
import platform
from operator import itemgetter
from polyswarm_api.api import PolyswarmAPI
from urllib.parse import urlparse
from colorama import init, Fore, Back, Style
from datetime import datetime
from urllib.parse import urlencode, quote_plus
from urllib.parse import quote
from requests.exceptions import RetryError
from pathlib import Path
from valhallaAPI.valhalla import ValhallaAPI

# On Windows systems, it is necessary to install python-magic-bin: pip install python-magic-bin

__author__ = "Alexandre Borges"
__copyright__ = "Copyright 2018-2021, Alexandre Borges"
__license__ = "GNU General Public License v3.0"
__version__ = "4.3.2"
__email__ = "alexandreborges at blackstormsecurity.com"

haurl = 'https://www.hybrid-analysis.com/api/v2'
url = 'https://www.virustotal.com/vtapi/v2/file/report'
param = 'params'
user_agent = 'Falcon Sandbox'
urlvt = 'https://www.virustotal.com/vtapi/v2/url/scan'
ipvt = 'https://www.virustotal.com/vtapi/v2/ip-address/report'
urlvtreport = 'https://www.virustotal.com/vtapi/v2/url/report' 
urlvtdomain = 'https://www.virustotal.com/vtapi/v2/domain/report'
urlfilevtcheck = 'https://www.virustotal.com/vtapi/v2/file/scan'
urlmalshare = 'https://malshare.com/api.php?api_key='
urlbazaar = 'https://mb-api.abuse.ch/api/v1/'
urlthreatfox = 'https://threatfox-api.abuse.ch/api/v1/'
hauss = 'https://urlhaus.abuse.ch/api/'
hausq = 'https://urlhaus-api.abuse.ch/v1/url/'
hausb = 'https://urlhaus-api.abuse.ch/v1/urls/recent/'
hausp = 'https://urlhaus-api.abuse.ch/v1/payloads/recent/'
hausph = 'https://urlhaus-api.abuse.ch/v1/payload/'
hausd = 'https://urlhaus-api.abuse.ch/v1/download/'
haust = 'https://urlhaus-api.abuse.ch/v1/tag/'
haussig = 'https://urlhaus-api.abuse.ch/v1/signature/'
urlalien = 'http://otx.alienvault.com/api/v1'
malpediaurl = 'https://malpedia.caad.fkie.fraunhofer.de/api'
threatcrowdurl = 'https://www.threatcrowd.org/searchApi/v2/'

F = []
H = []
final=''
ffpname2 = ''
repo2 = ''

class mycolors:

    reset='\033[0m'
    reverse='\033[07m'
    bold='\033[01m'
    class foreground:
        orange='\033[33m'
        blue='\033[34m'
        purple='\033[35m'
        lightgreen='\033[92m'
        lightblue='\033[94m'
        pink='\033[95m'
        lightcyan='\033[96m'
        red='\033[31m'
        green='\033[32m'
        cyan='\033[36m'
        lightgrey='\033[37m'
        darkgrey='\033[90m'
        lightred='\033[91m'
        yellow='\033[93m'
    class background:
        black='\033[40m'
        blue='\033[44m'
        cyan='\033[46m'
        lightgrey='\033[47m'
        purple='\033[45m'
        green='\033[42m'
        orange='\033[43m'
        red='\033[41m'

def ftype(filename):
    type = magic.from_file(filename)
    return type

def packed(pe):
    try:

        n = 0

        for sect in pe.sections:
            if sect.SizeOfRawData == 0:
                n = n + 1
            if (sect.get_entropy() < 1 and sect.get_entropy() > 0) or sect.get_entropy() > 7:
                n = n + 2
        if n > 2:
            return True
        if (n > 0 and n < 3):
            return "probably packed"
        else:
            return False

    except:
        return None


def sha256hash(fname):

    BSIZE = 65536
    hnd = open(fname, 'rb')
    hash256 = hashlib.sha256()
    while True:
        info = hnd.read(BSIZE)
        if not info:
            break
        hash256.update(info)
    return hash256.hexdigest()


def md5hash(fname):

    BSIZE = 65536
    hnd = open(fname, 'rb')
    hashmd5 = hashlib.md5()
    while True:
        info = hnd.read(BSIZE)
        if not info:
            break
        hashmd5.update(info)
    return hashmd5.hexdigest()


def listexports(fname):

    E = []
    mype2=pefile.PE(fname,fast_load=True)
    if mype2.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXPORT']].VirtualAddress != 0:
        mype2.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXPORT']])
        for exptab in mype2.DIRECTORY_ENTRY_EXPORT.symbols:
            x = hex(mype2.OPTIONAL_HEADER.ImageBase + exptab.address), exptab.name
            E.append(x)
    return E


def listimports(fname):

    I = []
    mype2=pefile.PE(fname,fast_load=True)
    if mype2.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT']].VirtualAddress != 0:
        mype2.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT']])
        if mype2.DIRECTORY_ENTRY_IMPORT is not None:
            for entry in mype2.DIRECTORY_ENTRY_IMPORT:
                for imptab in entry.imports:
                    if imptab.name is None:
                        imptab.name = "None"
                    if imptab.address is None :
                        imptab.address = int(0) 
                    x = hex(int(imptab.address)), imptab.name
                    I.append(x)
    return I


def listsections(fname):

    pe=pefile.PE(fname)

    if(windows == 1):
        print("Sections: ", end='')
        print("\t\tEntropy\n")
        for sect in pe.sections:
            print("%17s" % (sect.Name).decode('utf-8'), end='')
            print(("\t%5.2f" % sect.get_entropy()))
    else:
        print("Sections: ", end='')
        print("\t\tEntropy\n")
        for sect in pe.sections:
            print("%17s" % (sect.Name).decode('utf-8'), end='')
            print(("\t\t%5.2f" % sect.get_entropy()))

def listdlls(fname):

    pe=pefile.PE(fname)

    if(bkg == 1):
        print(mycolors.reset + "\nImported DLLs: ", end='\n')
        print((25*'-').ljust(25),end='\n\n')
        for x in pe.DIRECTORY_ENTRY_IMPORT:
            print("\t " + mycolors.foreground.lightgreen + x.dll.decode('utf-8') + mycolors.reset)
    else:
        print(mycolors.reset + "\nImported DLLs: ", end='\n')
        print((25*'-').ljust(25),end='\n\n')
        for x in pe.DIRECTORY_ENTRY_IMPORT:
            print("\t " + mycolors.foreground.purple + x.dll.decode('utf-8') + mycolors.reset)


def impext(targetfile):

    print(mycolors.reset)

    print(("\nImported Functions".ljust(40)))
    print((110*'-').ljust(110))
    IR = []
    IR = sorted(listimports(targetfile))
    dic={ }
    dic = dict(IR)
    d = iter(list(dic.items()))
    IX = []
    for key,value in sorted(d):
        IX.append(str(value))
    Y = iter(IX)

    for i in Y:
        if i is None:
            break

        while (i == 'None'):
            i = next(Y, None)

        if i is None:
                break
        if (bkg == 1):
            print((mycolors.foreground.lightcyan + "%-40s" % (i)[2:-1]), end=' ')
        else:
            print((mycolors.foreground.cyan + "%-40s" % (i)[2:-1]), end=' ')
        w = next(Y, None)
        if w is None:
            break
        if (w == 'None'):
            w = next(Y, None)
        if w is None:
            break
        if (bkg == 1):
            print((mycolors.foreground.lightgreen + "%-40s" % (w)[2:-1]), end=' ')
        else:
            print((mycolors.foreground.green + "%-40s" % (w)[2:-1]), end=' ')
        t = next(Y, None)
        if t is None:
            break
        if (t == 'None'):
            t = next(Y, None)
        if t is None:
            break
        if (bkg == 1):
            print((mycolors.foreground.yellow + "%-40s" % (t)[2:-1]))
        else:
            print((mycolors.foreground.purple + "%-40s" % (t)[2:-1]))
    
    print(mycolors.reset)

    print(("\n\nExported Functions".ljust(40)))
    print((110*'-').ljust(110))
    ER = []
    ER = sorted(listexports(targetfile))
    dic2={ }
    dic2 = dict(ER)
    d2 = iter(list(dic2.items()))
    EX = []
    for key, value in sorted(d2):
        EX.append(str(value))
    Y2 = iter(EX)
    for i in Y2:
        if i is None:
            break
        while (i == 'None'):
            i = next(Y2, None)
        if i is None:
            break
        if (bkg == 1):
            print((mycolors.foreground.yellow + "%-40s" % (i)[2:-1]), end=' ')
        else:
            print((mycolors.foreground.purple + "%-40s" % (i)[2:-1]), end=' ')
        w = next(Y2, None)
        if w is None:
            break
        if (w == 'None'):
            w = next(Y2, None)
        if w is None:
            break
        if (bkg == 1):
            print((mycolors.foreground.lightgreen + "%-40s" % (w)[2:-1]), end=' ')
        else:
            print((mycolors.foreground.green + "%-40s" % (w)[2:-1]), end=' ')

        t = next(Y2, None)
        if t is None:
            break
        if (t == 'None'):
            t = next(Y2, None)
        if t is None:
            break
        if (bkg == 1):
            print((mycolors.foreground.lightblue + "%-40s" % (t)[2:-1]))
        else:
            print((mycolors.foreground.cyan + "%-40s" % (t)[2:-1]))

    print(mycolors.reset)


def vtcheck(filehash, url, param):

    pos = ''
    total = ''
    vttext = ''
    response = ''

    try:

        resource = filehash
        params = {'apikey': VTAPI , 'resource': resource}
        response = requests.get(url, params=params)
        vttext = json.loads(response.text)
        rc = (vttext['response_code'])
        if (rc == 0):
            final = ' Not Found'
            return final
        while (rc != 1):
            time.sleep(20)
            response = requests.get(url, params=params)
            vttext = json.loads(response.text)
            rc = (vttext['response_code'])

        pos = str(vttext['positives'])
        total = str(vttext['total'])
        final = (pos + "/" + total)
        rc = str(vttext['response_code'])

        return final

    except ValueError:
        final = '     '
        return final


def vturlcheck(myurl, param):

    pos = ''
    total = ''
    vttext = ''
    response = ''
    resource = ''

    try:

        resource = myurl
        params = {'apikey': VTAPI , 'url': resource, 'allinfo': True}
        response = requests.post(urlvt, params=params)
        vttext = json.loads(response.text)
        rc = (vttext['response_code'])
        if (rc == 0):
            final = 'Error during URL checking'
            if (bkg == 1):
                print(mycolors.foreground.lightred + final)
            else:
                print(mycolors.foreground.red + final)
            exit(1)
        if (rc == 1):
            print(mycolors.reset + "\nURL SUMMARY REPORT")
            print("-"*20,"\n")

        if (bkg == 0):
            print(mycolors.foreground.blue + "Status: ".ljust(17),vttext['verbose_msg'])
            print(mycolors.foreground.blue + "Scan date: ".ljust(17),vttext['scan_date'])
            print(mycolors.foreground.blue + "Scan ID: ".ljust(17),vttext['scan_id'])
            print(mycolors.foreground.purple + "URL: ".ljust(17),vttext['url'])
            print(mycolors.foreground.cyan + "Permanent Link: ".ljust(17),vttext['permalink'])
            print(mycolors.foreground.red + "Result VT: ".ljust(17), end=' ')

        else:
            print(mycolors.foreground.lightgreen + "Status: ".ljust(17),vttext['verbose_msg'])
            print(mycolors.foreground.lightgreen + "Scan date: ".ljust(17),vttext['scan_date'])
            print(mycolors.foreground.lightgreen + "Scan ID: ".ljust(17),vttext['scan_id'])
            print(mycolors.foreground.yellow + "URL: ".ljust(17),vttext['url'])
            print(mycolors.foreground.lightcyan + "Permanent Link: ".ljust(17),vttext['permalink'])
            print(mycolors.foreground.lightred + "Result VT: ".ljust(17), end=' ')

        time.sleep(10)

        try:

            resource=vttext['url']
            params = {'apikey': VTAPI , 'resource': resource}
            response = requests.get(urlvtreport, params=params)
            vttext = json.loads(response.text)
            rc = (vttext['response_code'])
            if (rc == 0):
                final = 'Error gathering the Report.'
                if (bkg == 1):
                    print(mycolors.foreground.lightred + final)
                else:
                    print(mycolors.foreground.red + final)
                exit(1)
            pos = str(vttext['positives'])
            total = str(vttext['total'])
            final = (pos + "/" + total)
            print(final + "\n")

            if (bkg == 1):
                print(Fore.WHITE + "URL DETAILED REPORT")
                print("-"*20,"\n")

                if('AlienVault' in vttext['scans']):
                    print(mycolors.foreground.lightcyan + "AlienVault: ".ljust(17),mycolors.foreground.yellow + vttext['scans']['AlienVault']['result'])
                if('Avira' in vttext['scans']):
                    print(mycolors.foreground.lightcyan + "Avira: ".ljust(17),mycolors.foreground.yellow + vttext['scans']['Avira']['result'])
                if('BitDefender' in vttext['scans']):
                    print(mycolors.foreground.lightcyan + "BitDefender: ".ljust(17),mycolors.foreground.yellow + vttext['scans']['BitDefender']['result'])
                if('Certego' in vttext['scans']):
                    print(mycolors.foreground.lightcyan + "Certego: ".ljust(17),mycolors.foreground.yellow + vttext['scans']['Certego']['result'])
                if('Comodo Valkyrie Verdict' in vttext['scans']):
                    print(mycolors.foreground.lightcyan + "Comodo: ".ljust(17),mycolors.foreground.yellow + vttext['scans']['Comodo Valkyrie Verdict']['result'])
                if('CRDF' in vttext['scans']):
                    print(mycolors.foreground.lightcyan + "CRDF: ".ljust(17),mycolors.foreground.yellow + vttext['scans']['CRDF']['result'])
                if('CyRadar' in vttext['scans']):
                    print(mycolors.foreground.lightcyan + "CyRadar: ".ljust(17),mycolors.foreground.yellow + vttext['scans']['CyRadar']['result'])
                if('Emsisoft' in vttext['scans']):
                    print(mycolors.foreground.lightcyan + "Emsisoft: ".ljust(17),mycolors.foreground.yellow + vttext['scans']['Emsisoft']['result'])
                if('ESET' in vttext['scans']):
                    print(mycolors.foreground.lightcyan + "ESET: ".ljust(17),mycolors.foreground.yellow + vttext['scans']['ESET']['result'])
                if('Forcepoint ThreatSeeker' in vttext['scans']):
                    print(mycolors.foreground.lightcyan + "Forcepoint: ".ljust(17),mycolors.foreground.yellow + vttext['scans']['Forcepoint ThreatSeeker']['result'])
                if('Fortinet' in vttext['scans']):
                    print(mycolors.foreground.lightcyan + "Fortinet: ".ljust(17),mycolors.foreground.yellow + vttext['scans']['Fortinet']['result'])
                if('G-Data' in vttext['scans']):
                    print(mycolors.foreground.lightcyan + "G-Data: ".ljust(17),mycolors.foreground.yellow + vttext['scans']['G-Data']['result'])
                if('Google Safebrowsing' in vttext['scans']):
                    print(mycolors.foreground.lightcyan + "Google: ".ljust(17),mycolors.foreground.yellow + vttext['scans']['Google Safebrowsing']['result'])
                if('Kaspersky' in vttext['scans']):
                    print(mycolors.foreground.lightcyan + "Kaspersky: ".ljust(17),mycolors.foreground.yellow + vttext['scans']['Kaspersky']['result'])
                if('malwares.com URL checker' in vttext['scans']):
                    print(mycolors.foreground.lightcyan + "Malwares.com: ".ljust(17),mycolors.foreground.yellow + vttext['scans']['malwares.com URL checker']['result'])
                if('Malc0de Database' in vttext['scans']):
                    print(mycolors.foreground.lightcyan + "Malc0de: ".ljust(17),mycolors.foreground.yellow + vttext['scans']['Malc0de Database']['result'])
                if('MalwarePatrol' in vttext['scans']):
                    print(mycolors.foreground.lightcyan + "MalwarePatrol: ".ljust(17),mycolors.foreground.yellow + vttext['scans']['MalwarePatrol']['result'])
                if('OpenPhish' in vttext['scans']):
                    print(mycolors.foreground.lightcyan + "OpenPhish: ".ljust(17),mycolors.foreground.yellow + vttext['scans']['OpenPhish']['result'])
                if('PhishLabs' in vttext['scans']):
                    print(mycolors.foreground.lightcyan + "PhishLabs: ".ljust(17),mycolors.foreground.yellow + vttext['scans']['PhishLabs']['result'])
                if('Phishtank' in vttext['scans']):
                    print(mycolors.foreground.lightcyan + "Phishtank: ".ljust(17),mycolors.foreground.yellow + vttext['scans']['Phishtank']['result'])
                if('Spamhaus' in vttext['scans']):
                    print(mycolors.foreground.lightcyan + "Spamhaus: ".ljust(17),mycolors.foreground.yellow + vttext['scans']['Spamhaus']['result'])
                if('Sophos' in vttext['scans']):
                    print(mycolors.foreground.lightcyan + "Sophos: ".ljust(17),mycolors.foreground.yellow + vttext['scans']['Sophos']['result'])
                if('Trustwave' in vttext['scans']):
                    print(mycolors.foreground.lightcyan + "Trustwave: ".ljust(17),mycolors.foreground.yellow + vttext['scans']['Trustwave']['result'])
                if('VX Vault' in vttext['scans']):
                    print(mycolors.foreground.lightcyan + "VX Vault: ".ljust(17),mycolors.foreground.yellow + vttext['scans']['VX Vault']['result'])
                if('ZeroCERT' in vttext['scans']):
                    print(mycolors.foreground.lightcyan + "ZeroCERT: ".ljust(17),mycolors.foreground.yellow + vttext['scans']['ZeroCERT']['result'])
                print(mycolors.reset + "\n")
                exit(0)

            else:
                print(Fore.BLACK + "URL DETAILED REPORT")
                print("-"*20,"\n")
                if('AlienVault' in vttext['scans']):
                    print(mycolors.foreground.cyan + "AlienVault: ".ljust(17),mycolors.foreground.red + vttext['scans']['AlienVault']['result'])
                if('Avira' in vttext['scans']):
                    print(mycolors.foreground.cyan + "Avira: ".ljust(17),mycolors.foreground.red + vttext['scans']['Avira']['result'])
                if('BitDefender' in vttext['scans']):
                    print(mycolors.foreground.cyan + "BitDefender: ".ljust(17),mycolors.foreground.red + vttext['scans']['BitDefender']['result'])
                if('Certgo' in vttext['scans']):
                    print(mycolors.foreground.cyan + "Certego: ".ljust(17),mycolors.foreground.red + vttext['scans']['Certego']['result'])
                if('Comodo Valkyrie Verdict' in vttext['scans']):
                    print(mycolors.foreground.cyan + "Comodo: ".ljust(17),mycolors.foreground.red + vttext['scans']['Comodo Valkyrie Verdict']['result'])
                if('CRDF' in vttext['scans']):
                    print(mycolors.foreground.cyan + "CRDF: ".ljust(17),mycolors.foreground.red + vttext['scans']['CRDF']['result'])
                if('CyRadar' in vttext['scans']):
                    print(mycolors.foreground.cyan + "CyRadar: ".ljust(17),mycolors.foreground.red + vttext['scans']['CyRadar']['result'])
                if('Emsisoft' in vttext['scans']):
                    print(mycolors.foreground.cyan + "Emsisoft: ".ljust(17),mycolors.foreground.red + vttext['scans']['Emsisoft']['result'])
                if('ESET' in vttext['scans']):
                    print(mycolors.foreground.cyan + "ESET: ".ljust(17),mycolors.foreground.red + vttext['scans']['ESET']['result'])
                if('Forcepoint ThreatSeeker' in vttext['scans']):
                    print(mycolors.foreground.cyan + "Forcepoint: ".ljust(17),mycolors.foreground.red + vttext['scans']['Forcepoint ThreatSeeker']['result'])
                if('Fortinet' in vttext['scans']):
                    print(mycolors.foreground.cyan + "Fortinet: ".ljust(17),mycolors.foreground.red + vttext['scans']['Fortinet']['result'])
                if('G-Data' in vttext['scans']):
                    print(mycolors.foreground.cyan + "G-Data: ".ljust(17),mycolors.foreground.red + vttext['scans']['G-Data']['result'])
                if('Google Safebrowsing' in vttext['scans']):
                    print(mycolors.foreground.cyan + "Google: ".ljust(17),mycolors.foreground.red + vttext['scans']['Google Safebrowsing']['result'])
                if('Kaspersky' in vttext['scans']):
                    print(mycolors.foreground.cyan + "Kaspersky: ".ljust(17),mycolors.foreground.red + vttext['scans']['Kaspersky']['result'])
                if('malwares.com URL checker' in vttext['scans']):
                    print(mycolors.foreground.cyan + "Malwares.com: ".ljust(17),mycolors.foreground.red + vttext['scans']['malwares.com URL checker']['result'])
                if('Malc0de Database' in vttext['scans']):
                    print(mycolors.foreground.cyan + "Malc0de: ".ljust(17),mycolors.foreground.red + vttext['scans']['Malc0de Database']['result'])
                if('MalwarePatrol' in vttext['scans']):
                    print(mycolors.foreground.cyan + "MalwarePatrol: ".ljust(17),mycolors.foreground.red + vttext['scans']['MalwarePatrol']['result'])
                if('OpenPhish' in vttext['scans']):
                    print(mycolors.foreground.cyan + "OpenPhish: ".ljust(17),mycolors.foreground.red + vttext['scans']['OpenPhish']['result'])
                if('PhishLabs' in vttext['scans']):
                    print(mycolors.foreground.cyan + "PhishLabs: ".ljust(17),mycolors.foreground.red + vttext['scans']['PhishLabs']['result'])
                if('Phishtank' in vttext['scans']):
                    print(mycolors.foreground.cyan + "Phishtank: ".ljust(17),mycolors.foreground.red + vttext['scans']['Phishtank']['result'])
                if('Spamhaus' in vttext['scans']):
                    print(mycolors.foreground.cyan + "Spamhaus: ".ljust(17),mycolors.foreground.red + vttext['scans']['Spamhaus']['result'])
                if('Sophos' in vttext['scans']):
                    print(mycolors.foreground.cyan + "Sophos: ".ljust(17),mycolors.foreground.red + vttext['scans']['Sophos']['result'])
                if('Truswave' in vttext['scans']):
                    print(mycolors.foreground.cyan + "Trustwave: ".ljust(17),mycolors.foreground.red + vttext['scans']['Trustwave']['result'])
                if('VX Vault' in vttext['scans']):
                    print(mycolors.foreground.cyan + "VX Vault: ".ljust(17),mycolors.foreground.red + vttext['scans']['VX Vault']['result'])
                if('ZeroCERT' in vttext['scans']):
                    print(mycolors.foreground.cyan + "ZeroCERT: ".ljust(17),mycolors.foreground.red + vttext['scans']['ZeroCERT']['result'])
                print(mycolors.reset + "\n")
                exit(0)

        except ValueError:
            if (bkg == 1):
                print(mycolors.foreground.lightred + "Error while connecting to Virus Total!\n")
            else:
                print(mycolors.foreground.red + "Error while connecting to Virus Total!\n")
            print(mycolors.reset)
            exit(2)

    except ValueError:
        if (bkg == 1):
            print(mycolors.foreground.lightred + "Error while connecting to Virus Total!\n")
        else:
            print(mycolors.foreground.red + "Error while connecting to Virus Total!\n")
        print(mycolors.reset)
        exit(3)


def vtdomaincheck(mydomain, param):

    pos = ''
    total = ''
    vttext = ''
    response = ''
    resource = ''
    rc = ''
    vxtext = ''

    try:

        resource = mydomain
        params = {'apikey': VTAPI , 'domain': resource}
        response = requests.get(urlvtdomain, params=params)
        vttext = json.loads(response.text)

        rc = (vttext['response_code'])
        if (rc == 0):
            final = 'Domain not found.'
            if (bkg == 1):
                print(mycolors.foreground.lightred + final)
            else:
                print(mycolors.foreground.red + final)
            print(mycolors.reset)
            exit(1)

        if (rc == 1):

            print(mycolors.reset)
            print("\nDOMAIN SUMMARY REPORT")
            print("-"*20,"\n")

            if (bkg == 0):
                print(mycolors.foreground.green + "Undetected Referrer Samples:  ".ljust(17))
            else:
                print(mycolors.foreground.lightcyan + "Undetected Referrer Samples: ".ljust(17))

            if 'undetected_referrer_samples' in vttext:
                if (bool(vttext['undetected_referrer_samples'])):
                    try:
                        for i in range(0, len(vttext['undetected_referrer_samples'])):
                            if (vttext['undetected_referrer_samples'][i].get('date')):
                                print("".ljust(28), end=' ')
                                print(("date: %s" % vttext['undetected_referrer_samples'][i]['date']))
                            if (vttext['undetected_referrer_samples'][i].get('positives')):
                                print("".ljust(28), end=' ')
                                print(("positives: %s" % vttext['undetected_referrer_samples'][i]['positives']))
                            if (vttext['undetected_referrer_samples'][i].get('total')):
                                print("".ljust(28), end=' ')
                                print(("total: %s" % vttext['undetected_referrer_samples'][i]['total']))
                            if (vttext['undetected_referrer_samples'][i].get('sha256')):
                                print("".ljust(28), end=' ')
                                print(("sha256: %s" % vttext['undetected_referrer_samples'][i]['sha256']), end=' ')
                            print("\n")
                    except KeyError as e:
                        pass


            if (bkg == 0):
                print(mycolors.foreground.blue + "Detected Referrer Samples:  ".ljust(17))
            else:
                print(mycolors.foreground.yellow + "Detected Referrer Samples: ".ljust(17))

            if 'detected_referrer_samples' in vttext:
                if (bool(vttext['detected_referrer_samples'])):
                    try:
                        for i in range(len(vttext['detected_referrer_samples'])):
                            if (vttext['detected_referrer_samples'][i].get('date')):
                                print("".ljust(28), end=' ')
                                print(("date: %s" % vttext['detected_referrer_samples'][i]['date']))
                            if (vttext['detected_referrer_samples'][i].get('positives')):
                                print("".ljust(28), end=' ')
                                print(("positives: %s" % vttext['detected_referrer_samples'][i]['positives']))
                            if (vttext['detected_referrer_samples'][i].get('total')):
                                print("".ljust(28), end=' ')
                                print(("total: %s" % vttext['detected_referrer_samples'][i]['total']))
                            if (vttext['detected_referrer_samples'][i].get('sha256')):
                                print("".ljust(28), end=' ')
                                print(("sha256: %s" % vttext['detected_referrer_samples'][i]['sha256']), end=' ')
                            print("\n")
                    except KeyError as e:
                        pass

            if (bkg == 0):
                print(mycolors.foreground.red + "\nWhois Timestamp:  ".ljust(17))
            else:
                print(mycolors.foreground.yellow + "\nWhois Timestamp: ".ljust(17))

            if 'whois_timestamp' in vttext:
                if (bool(vttext['whois_timestamp'])):
                    try:
                        print("".ljust(28), end=' ') 
                        ts = vttext['whois_timestamp']
                        print((datetime.utcfromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')))
                    except KeyError as e:
                        pass

            if (bkg == 0):
                print(mycolors.foreground.purple + "\nUndetected Downld. Samples:  ".ljust(17))
            else:
                print(mycolors.foreground.lightgreen + "\nUndetected Downld. Samples: ".ljust(17))

            if 'undetected_downloaded_samples' in vttext:
                if (bool(vttext['undetected_downloaded_samples'])):
                    try:
                        for i in range(len(vttext['undetected_downloaded_samples'])):
                            if (vttext['undetected_downloaded_samples'][i].get('date')):
                                print("".ljust(28), end=' ')
                                print(("date: %s" % vttext['undetected_downloaded_samples'][i]['date']))
                            if (vttext['undetected_downloaded_samples'][i].get('positives')):
                                print("".ljust(28), end=' ')
                                print(("positives: %s" % vttext['undetected_downloaded_samples'][i]['positives']))
                            if (vttext['undetected_downloaded_samples'][i].get('total')):
                                print("".ljust(28), end=' ')
                                print(("total: %s" % vttext['undetected_downloaded_samples'][i]['total']))
                            if (vttext['undetected_downloaded_samples'][i].get('sha256')):
                                print("".ljust(28), end=' ')
                                print(("sha256: %s" % vttext['undetected_downloaded_samples'][i]['sha256']), end=' ')
                            print("\n")
                    except KeyError as e:
                        pass

            if (bkg == 0):
                print(mycolors.foreground.purple + "\nDetected Downloaded Samples:  ".ljust(17))
            else:
                print(mycolors.foreground.orange + "\nDetected Downloaded Samples: ".ljust(17))

            if 'detected_downloaded_samples' in vttext:
                if (bool(vttext['detected_downloaded_samples'])):
                    try:
                        for i in range(len(vttext['detected_downloaded_samples'])):
                            if (vttext['detected_downloaded_samples'][i].get('date')):
                                print("".ljust(28), end=' ')
                                print(("date: %s" % vttext['detected_downloaded_samples'][i]['date']))
                            if (vttext['detected_downloaded_samples'][i].get('positives')):
                                print("".ljust(28), end=' ')
                                print(("positives: %s" % vttext['detected_downloaded_samples'][i]['positives']))
                            if (vttext['detected_downloaded_samples'][i].get('total')):
                                print("".ljust(28), end=' ')
                                print(("total: %s" % vttext['detected_downloaded_samples'][i]['total']))
                            if (vttext['detected_downloaded_samples'][i].get('sha256')):
                                print("".ljust(28), end=' ')
                                print(("sha256: %s" % vttext['detected_downloaded_samples'][i]['sha256']), end=' ')
                            print("\n")
                    except KeyError as e:
                        pass

            if (bkg == 0):
                print(mycolors.foreground.red + "Resolutions:  ".ljust(17))
            else:
                print(mycolors.foreground.lightred + "Resolutions: ".ljust(17))

            if 'resolutions' in vttext:
                if (bool(vttext['resolutions'])):
                    try:
                        for i in range(len(vttext['resolutions'])):
                            if (vttext['resolutions'][i].get('last_resolved')):
                                print("".ljust(28), end=' ')
                                print(("last resolved: %s" % vttext['resolutions'][i]['last_resolved']))
                            if (vttext['resolutions'][i].get('ip_address')):
                                print("".ljust(28), end=' ')
                                print(("ip address:    %-18s" % vttext['resolutions'][i]['ip_address']), end=' ')
                                print("\t(City:%s)" % (geocoder.ip(vttext['resolutions'][i]['ip_address'])).city)
                            print("\n")
                    except KeyError as e:
                        pass

            if (bkg == 0):
                print(mycolors.foreground.green + "\nSubdomains:  ".ljust(17))
            else:
                print(mycolors.foreground.lightgreen + "\nSubdomains: ".ljust(17))

            if 'subdomains' in vttext:
                if (bool(vttext['subdomains'])):
                    try:
                        for i in range(len(vttext['subdomains'])):
                            print("".ljust(28), end=' ') 
                            print((vttext['subdomains'][i]))
                    except KeyError as e:
                        pass

            if (bkg == 0):
                print(mycolors.foreground.cyan + "\nCategories:  ".ljust(17))
            else:
                print(mycolors.foreground.lightcyan + "\nCategories: ".ljust(17))

            if 'categories' in vttext:
                if (bool(vttext['categories'])):
                    try:
                        for i in range(len(vttext['categories'])):
                            print("".ljust(28), end=' ')
                            print((vttext['categories'][i]))
                    except KeyError as e:
                        pass

            if (bkg == 0):
                print(mycolors.foreground.cyan + "\nDomain Siblings: ".ljust(17))
            else:
                print(mycolors.foreground.lightcyan + "\nDomain Siblings: ".ljust(17))

            if 'domain_sublings' in vttext:
                if (bool(vttext['domain_sublings'])):
                    try:
                        for i in range(len(vttext['domain_siblings'])):
                            print("".ljust(28), end=' ')
                            print((vttext['domain_siblings'][i]), end=' ')
                        print("\n")
                    except KeyError as e:
                        pass

            if (bkg == 0):
                print(mycolors.foreground.red + "\nDetected URLs: ".ljust(17))
            else:
                print(mycolors.foreground.yellow + "\nDetected URLs: ".ljust(17))

            if 'detected_urls' in vttext:
                if (bool(vttext['detected_urls'])):
                    try:
                        for i in range(len(vttext['detected_urls'])):
                            if (vttext['detected_urls'][i].get('url')):
                                print("".ljust(28), end=' ')
                                print(("url: %s" % vttext['detected_urls'][i]['url']))
                            if (vttext['detected_urls'][i].get('positives')):
                                print("".ljust(28), end=' ')
                                print(("positives: %s" % vttext['detected_urls'][i]['positives']))
                            if (vttext['detected_urls'][i].get('total')):
                                print("".ljust(28), end=' ')
                                print(("total: %s" % vttext['detected_urls'][i]['total']))
                            if (vttext['detected_urls'][i].get('scan_date')):
                                print("".ljust(28), end=' ')
                                print(("scan_date: %s" % vttext['detected_urls'][i]['scan_date']), end=' ')
                            print("\n")
                    except KeyError as e:
                        pass

            if (bkg == 0):
                print(mycolors.foreground.green + "\nUndetected URLs: ".ljust(17))
            else:
                print(mycolors.foreground.lightgreen + "\nUndetected URLs: ".ljust(17))

            if 'undetected_urls' in vttext:
                if (bool(vttext['undetected_urls'])):
                    try:
                        for i in range(len(vttext['undetected_urls'])):
                            if (bkg == 0):
                                print((mycolors.foreground.green + "".ljust(28)), end=' ')
                                print(("data %s\n" % i))
                            else:
                                print((mycolors.foreground.lightgreen + "".ljust(28)), end=' ')
                                print(("data %s\n" % i))
                            for y in range(len(vttext['undetected_urls'][i])):
                                if (bkg == 0):
                                    print((mycolors.foreground.cyan + "".ljust(28)), end=' ')
                                    if (y == 0):
                                        print(("url:       "), end=' ')
                                    if (y == 1):
                                        print(("sha256:    "), end=' ')
                                    if (y == 2):
                                        print(("positives: "), end=' ')
                                    if (y == 3):
                                        print(("total:     "), end=' ')
                                    if (y == 4):
                                        print(("date:      "), end=' ')
                                    print(("%s" % (vttext['undetected_urls'][i][y])))
                                else:
                                    print((mycolors.foreground.lightgreen + "".ljust(28)), end=' ')
                                    if (y == 0):
                                        print(("url:       "), end=' ')
                                    if (y == 1):
                                        print(("sha256:    "), end=' ')
                                    if (y == 2):
                                        print(("positives: "), end=' ')
                                    if (y == 3):
                                        print(("total:     "), end=' ')
                                    if (y == 4):
                                        print(("date:      "), end=' ')
                                    print(("%s" % (vttext['undetected_urls'][i][y])))
                            print("\n")
                    except KeyError as e:
                        pass

    except ValueError:
        if(bkg == 1):
            print((mycolors.foreground.lightred + "Error while connecting to Virus Total!\n"))
        else:
            print((mycolors.foreground.red + "Error while connecting to Virus Total!\n"))
        print(mycolors.reset)
        exit(3)


def ipvtcheck(ipaddress, urlvtip):

    pos = ''
    total = ''
    vttext = ''
    response = ''
    resource = ''
    rc = ''
    vxtext = ''

    try:

        resource = ipaddress
        params = {'apikey': VTAPI , 'ip': resource}
        response = requests.get(urlvtip, params=params)
        vttext = json.loads(response.text)

        rc = (vttext['response_code'])
        if (rc == 0):
            final = 'Domain not found.'
            if (bkg == 1):
                print(mycolors.foreground.lightred + final)
            else:
                print(mycolors.foreground.red + final)
            print(mycolors.reset)
            exit(1)

        if (rc == 1):

            print(mycolors.reset)
            print("\nIP ADDRESS SUMMARY REPORT")
            print("-"*25,"\n")

            if 'country' in vttext:
                if (bkg == 0):
                    print(mycolors.foreground.red + "Country:\t" + mycolors.reset + vttext['country'] + mycolors.reset, end='\n')
                else:
                    print(mycolors.foreground.orange + "Country:\t" + mycolors.reset + vttext['country'] + mycolors.reset, end='\n')
            else:
                if (bkg == 0):
                    print(mycolors.foreground.red + "Country:\t" + mycolors.reset + "Not specified" + mycolors.reset, end='\n')
                else:
                    print(mycolors.foreground.red + "Country:\t" + mycolors.reset + "Not specified" + mycolors.reset, end='\n')

            if 'asn' in vttext:
                if (bkg == 0):
                    print(mycolors.foreground.red + "ASN:\t\t", end='')
                    print(mycolors.reset + str(vttext['asn']) + mycolors.reset, end='\n\n')
                else:
                    print(mycolors.foreground.orange + "ASN:\t\t", end='')
                    print(mycolors.reset + str(vttext['asn']) + mycolors.reset, end='\n\n')
            else:
                if (bkg == 0):
                    print(mycolors.foreground.red + "ASN:\t\t" + mycolors.reset + "Not specified" + mycolors.reset, end='\n\n')
                else:
                    print(mycolors.foreground.orange + "ASN:\t\t" + mycolors.reset + "Not specified" + mycolors.reset, end='\n\n')

            print(mycolors.reset + "\nResolutions")
            print("-" * 11)

            if 'resolutions' in vttext:
                if (vttext['resolutions']):
                    for i in vttext['resolutions']:
                        if (bkg == 0):
                            print(mycolors.foreground.green + "\nLast Resolved:\t" + mycolors.reset + i['last_resolved'] + mycolors.reset)
                            print(mycolors.foreground.green + "Hostname:\t" + mycolors.reset + i['hostname'] + mycolors.reset)
                        else:
                            print(mycolors.foreground.lightgreen + "\nLast Resolved:\t" + mycolors.reset + i['last_resolved'] + mycolors.reset)
                            print(mycolors.foreground.lightgreen + "Hostname:\t" + mycolors.reset + i['hostname'] + mycolors.reset)

            print(mycolors.reset + "\n\nDetected URLs")
            print("-" * 13)

            if 'detected_urls' in vttext:
                for j in vttext['detected_urls']:
                    if (bkg == 0):
                        print(mycolors.foreground.cyan + "\nURL:\t\t", end='')
                        print(mycolors.reset + ("\n".ljust(17)).join(textwrap.wrap(j['url'], width=100)), end='\n')
                        print(mycolors.foreground.cyan+ "Scan Date:\t", end='')
                        print(mycolors.reset + j['scan_date'] + mycolors.reset)
                        print(mycolors.foreground.cyan + "Positives:\t", end='')
                        print(mycolors.reset + str(j['positives']) + mycolors.reset)
                        print(mycolors.foreground.cyan + "Total:\t\t", end='')
                        print(mycolors.reset + str(j['total']) + mycolors.reset)
                    else:
                        print(mycolors.foreground.lightred + "\nURL:\t\t", end='')
                        print(mycolors.reset + ("\n".ljust(17)).join(textwrap.wrap(j['url'], width=100)), end='\n')
                        print(mycolors.foreground.lightred + "Scan Date:\t", end='')
                        print(mycolors.reset + j['scan_date'] + mycolors.reset)
                        print(mycolors.foreground.lightred + "Positives:\t", end='')
                        print(mycolors.reset + str(j['positives']) + mycolors.reset)
                        print(mycolors.foreground.lightred + "Total:\t\t", end='')
                        print(mycolors.reset + str(j['total']) + mycolors.reset)
                        
            print(mycolors.reset + "\n\nDetected Downloaded Samples")
            print("-" * 27)

            if 'detected_downloaded_samples' in vttext:
                for k in vttext['detected_downloaded_samples']:
                    if (bkg == 0):
                        print(mycolors.foreground.red + "\nSHA256:\t\t" + mycolors.reset, end='')
                        print(mycolors.reset + k['sha256'] + mycolors.reset)
                        print(mycolors.foreground.red + "Date:\t\t" + mycolors.reset, end='')
                        print(mycolors.reset + k['date'] + mycolors.reset)
                        print(mycolors.foreground.red + "Positives:\t" + mycolors.reset, end='')
                        print(mycolors.reset + str(k['positives']) + mycolors.reset)
                        print(mycolors.foreground.red + "Total:\t\t" + mycolors.reset, end='')
                        print(mycolors.reset + str(k['total']) + mycolors.reset)
                    else:
                        print(mycolors.foreground.yellow + "\nSHA256:\t\t" + mycolors.reset, end='')
                        print(mycolors.reset + k['sha256'] + mycolors.reset)
                        print(mycolors.foreground.yellow + "Date:\t\t" + mycolors.reset, end='')
                        print(mycolors.reset + k['date'] + mycolors.reset)
                        print(mycolors.foreground.yellow + "Positives:\t" + mycolors.reset, end='')
                        print(mycolors.reset + str(k['positives']) + mycolors.reset)
                        print(mycolors.foreground.yellow + "Total:\t\t" + mycolors.reset, end='')
                        print(mycolors.reset + str(k['total']) + mycolors.reset)

            print(mycolors.reset + "\n\nUndetected Downloaded Samples")
            print("-" * 27)

            if 'undetected_downloaded_samples' in vttext:
                for m in vttext['undetected_downloaded_samples']:
                    if (bkg == 0):
                        print(mycolors.foreground.purple + "\nSHA256:\t\t" + mycolors.reset, end='')
                        print(mycolors.reset + m['sha256'] + mycolors.reset)
                        print(mycolors.foreground.purple + "Date:\t\t" + mycolors.reset, end='')
                        print(mycolors.reset + m['date'] + mycolors.reset)
                        print(mycolors.foreground.purple + "Positives:\t" + mycolors.reset, end='')
                        print(mycolors.reset + str(m['positives']) + mycolors.reset)
                        print(mycolors.foreground.purple + "Total:\t\t" + mycolors.reset, end='')
                        print(mycolors.reset + str(m['total']) + mycolors.reset)
                    else:
                        print(mycolors.foreground.lightcyan + "\nSHA256:\t\t" + mycolors.reset, end='')
                        print(mycolors.reset + m['sha256'] + mycolors.reset)
                        print(mycolors.foreground.lightcyan + "Date:\t\t" + mycolors.reset, end='')
                        print(mycolors.reset + m['date'] + mycolors.reset)
                        print(mycolors.foreground.lightcyan + "Positives:\t" + mycolors.reset, end='')
                        print(mycolors.reset + str(m['positives']) + mycolors.reset)
                        print(mycolors.foreground.lightcyan + "Total:\t\t" + mycolors.reset, end='')
                        print(mycolors.reset + str(m['total']) + mycolors.reset)


    except ValueError:
        if(bkg == 1):
            print((mycolors.foreground.lightred + "Error while connecting to Virus Total!\n"))
        else:
            print((mycolors.foreground.red + "Error while connecting to Virus Total!\n"))
        print(mycolors.reset)
        exit(3)


def vtfilecheck(filename, urlfilevtcheck, param):

    pos = ''
    total = ''
    vttext = ''
    response = ''
    resource = ''
    dname = ''
    fname = '' 
    try:

        resource = {'file': (filename, open(filename,'rb'))}
        mysha256hash = sha256hash(filename)
        params = {'apikey': VTAPI}
        response = requests.post(urlfilevtcheck, files = resource, params=params)
        vttext = json.loads(response.text)
        rc = (vttext['response_code'])
        if (rc == 0):
            final = 'Error during file checking on Virus Total'
            if(bkg == 1):
                print(mycolors.foreground.lightred + final)
            else:
                print(mycolors.foreground.red + final)
            exit(1)
        if (rc == 1):
            print(mycolors.reset)
            print("\nFILE SUMMARY VT REPORT")
            print("-"*25,"\n")

            if (bkg == 0):
                print(mycolors.foreground.green + "Filename: ".ljust(17),os.path.basename(filename))
                print(mycolors.foreground.blue + "Status: ".ljust(17),vttext['verbose_msg'])
                print(mycolors.foreground.blue + "Resource: ".ljust(17),vttext['resource'])
                print(mycolors.foreground.blue + "Scan ID: ".ljust(17),vttext['scan_id'])
                print(mycolors.foreground.purple + "SHA256: ".ljust(17),vttext['sha256'])
                print(mycolors.foreground.cyan + "Permanent Link: ".ljust(17),vttext['permalink'])
                print(mycolors.foreground.red + "Result VT: ".ljust(17), end=' ')

            else:
                print(mycolors.foreground.yellow + "Filename: ".ljust(17),os.path.basename(filename))
                print(mycolors.foreground.lightgreen + "Status: ".ljust(17),vttext['verbose_msg'])
                print(mycolors.foreground.lightgreen + "Resource: ".ljust(17),vttext['resource'])
                print(mycolors.foreground.lightgreen + "Scan ID: ".ljust(17),vttext['scan_id'])
                print(mycolors.foreground.yellow + "SHA256: ".ljust(17),vttext['sha256'])
                print(mycolors.foreground.lightcyan + "Permanent Link: ".ljust(17),vttext['permalink'])
                print(mycolors.foreground.lightred + "Result VT: ".ljust(17), end=' ')

            time.sleep(90)

            try:

                finalstatus = vtcheck(vttext['scan_id'], url, param)
                print(finalstatus)
                print ("\n")
                print(mycolors.reset)
                print("VIRUS TOTAL DETAILED REPORT")
                print("-"*28,"\n")
                time.sleep(5)
                vtshow(vttext['scan_id'], url, param)
                print(mycolors.reset + "\n")
                exit(0)


            except ValueError:
                if(bkg == 1):
                    print(mycolors.foreground.lightred + "Error while connecting to Virus Total!\n")
                else:
                    print(mycolors.foreground.red + "Error while connecting to Virus Total!\n")
                print(mycolors.reset)
                exit(2)

    except ValueError:
        if(bkg == 1):
            print((mycolors.foreground.lightred + "Error while connecting to Virus Total!\n"))
        else:
            print((mycolors.foreground.red + "Error while connecting to Virus Total!\n"))
        print(mycolors.reset)
        exit(3)


def vtshow(filehash, url, param): 

    vttext = ''
    response = ''

    try:
        resource=filehash
        params = {'apikey': VTAPI , 'resource': resource}
        response = requests.get(url, params=params)
        vttext = json.loads(response.text)

        rc = (vttext['response_code'])
        if (rc == 0):
            final = 'Not Found'
            return final 

        if (bkg == 0):
            print(mycolors.foreground.cyan + "Scan date: ".ljust(13),vttext['scan_date'] + "\n")
        else:
            print(mycolors.foreground.yellow + "Scan date: ".ljust(13),vttext['scan_date'] + "\n")

        if (bkg == 1):
            print(mycolors.foreground.lightred)
        else:
            print(mycolors.foreground.red)

        if ('Avast' in vttext['scans']):
            print("Avast:".ljust(13),vttext['scans']['Avast']['result'])

        if ('Avira' in vttext['scans']):
            print("Avira:".ljust(13),vttext['scans']['Avira']['result'])

        if ('BitDefender' in vttext['scans']):
            print("BitDefender:".ljust(13),vttext['scans']['BitDefender']['result'])

        if ('ESET-NOD32' in vttext['scans']):
            print("ESET-NOD32:".ljust(13),vttext['scans']['ESET-NOD32']['result'])

        if ('F-Secure' in vttext['scans']):
            print("F-Secure:".ljust(13),vttext['scans']['F-Secure']['result'])

        if ('FireEye' in vttext['scans']):
            print("FireEye:".ljust(13),vttext['scans']['FireEye']['result'])

        if ('Fortinet' in vttext['scans']):
            print("Fortinet:".ljust(13),vttext['scans']['Fortinet']['result'])

        if ("Kaspersky" in vttext['scans']):
            print("Kaspersky:".ljust(13),vttext['scans']['Kaspersky']['result'])

        if ("MalwareBytes" in vttext['scans']):
            print("MalwareBytes:".ljust(13),vttext['scans']['MalwareBytes']['result'])

        if ("McAfee" in vttext['scans']):
            print("McAfee:".ljust(13),vttext['scans']['McAfee']['result'])

        if ("Microsoft" in vttext['scans']):
            print("Microsoft:".ljust(13),vttext['scans']['Microsoft']['result'])

        if ("Panda" in vttext['scans']):
            print("Panda:".ljust(13),vttext['scans']['Panda']['result'])

        if ("Sophos" in vttext['scans']):
            print("Sophos:".ljust(13),vttext['scans']['Sophos']['result'])

        if ("Symantec" in vttext['scans']):
            print("Symantec:".ljust(13),vttext['scans']['Symantec']['result'])

        if ("TrendMicro" in vttext['scans']):
            print("TrendMicro:".ljust(13),vttext['scans']['TrendMicro']['result'])

        if ("Zone-Alarm" in vttext['scans']):
            print("Zone-Alarm:".ljust(13),vttext['scans']['Zone-Alarm']['result'])

    except ValueError:
        if(bkg == 1):
            print((mycolors.foreground.lightred + "Error while connecting to Virus Total!\n"))
        else:
            print((mycolors.foreground.red + "Error while connecting to Virus Total!\n"))
        print(mycolors.reset)


def hashow(filehash):

    hatext = ''
    haresponse = ''
    final = ''

    try:

        resource = filehash
        requestsession = requests.Session( )
        requestsession.headers.update({'user-agent': user_agent})
        requestsession.headers.update({'api-key': HAAPI})
        requestsession.headers.update({'content-type': 'application/json'})

        if (xx == 0):
            finalurl = '/'.join([haurl,'report', resource + ':100', 'summary'])
        elif (xx == 1):
            finalurl = '/'.join([haurl,'report', resource + ':110', 'summary'])
        elif (xx == 2):
            finalurl = '/'.join([haurl,'report', resource + ':120', 'summary'])
        elif (xx == 3):
            finalurl = '/'.join([haurl,'report', resource + ':200', 'summary'])
        else:
            finalurl = '/'.join([haurl,'report', resource + ':300', 'summary'])

        haresponse = requestsession.get(url=finalurl)
        hatext = json.loads(haresponse.text)

        rc = str(hatext)
        if 'message' in rc:
            final = 'Malware sample was not found in Hybrid-Analysis repository.'
            if (bkg == 1):
                print((mycolors.foreground.lightred + "\n" + final + "\n"))
            else:
                print((mycolors.foreground.red + "\n" + final + "\n"))
            return final

        if 'environment_description' in hatext:
            envdesc = str(hatext['environment_description'])
        else:
            envdesc = ''

        if 'type' in hatext:
            maltype = str(hatext['type'])
        else:
            maltype = ''

        if 'verdict' in hatext:
            verdict = str(hatext['verdict'])
        else:
            verdict = ''

        if 'threat_level' in hatext:
            threatlevel = str(hatext['threat_level'])
        else:
            threatlevel = ''

        if 'threat_score' in hatext:
            threatscore = str(hatext['threat_score'])
        else:
            threatscore = ''

        if 'av_detect' in hatext:
            avdetect = str(hatext['av_detect'])
        else:
            avdetect = ''

        if 'total_signatures' in hatext:
            totalsignatures = str(hatext['total_signatures'])
        else:
            totalsignatures = ''

        if 'submit_name' in hatext:
            submitname = str(hatext['submit_name'])
        else:
            submitname = ''

        if 'analysis_start_time' in hatext:
            analysistime = str(hatext['analysis_start_time'])
        else:
            analysistime = ''

        if 'size' in hatext:
            malsize = str(hatext['size'])
        else:
            malsize = ''

        if 'total_processes' in hatext:
            totalprocesses = str(hatext['total_processes'])
        else:
            totalprocesses = ''

        if 'total_network_connections' in hatext:
            networkconnections =  str(hatext['total_network_connections'])
        else:
            networkconnections = ''

        if 'domains' in hatext:
            domains = (hatext['domains'])
        else:
            domains = ''

        if 'hosts' in hatext:
            hosts = (hatext['hosts'])
        else:
            hosts = ''

        if 'compromised_hosts' in hatext:
            compromised_hosts = (hatext['compromised_hosts'])
        else:
            compromised_hosts = ''

        if 'vx_family' in hatext:
            vxfamily = str(hatext['vx_family'])
        else:
            vxfamily = ''

        if 'type_short' in (hatext):
            typeshort = (hatext['type_short'])
        else:
            typeshort = ''

        if 'tags' in hatext:
            classification = (hatext['tags'])
        else:
            classification = ''

        if 'certificates' in hatext:
            certificates = hatext['certificates']
        else:
            certificates = ''

        if 'mitre_attcks' in hatext:
            mitre = hatext['mitre_attcks']
        else:
            mitre = ''

        print(mycolors.reset)
        print ("\nHybrid-Analysis Summary Report:")
        print((70*'-').ljust(70))
        if (bkg == 1):
            print((mycolors.foreground.lightcyan))
        else:
            print((mycolors.foreground.red))
        print("Environment:".ljust(20),envdesc)
        print("File Type:".ljust(20),maltype)
        print("Verdict:".ljust(20),verdict)
        print("Threat Level:".ljust(20),threatlevel)
        print("Threat Score:".ljust(20),threatscore + '/100') 
        print("AV Detect".ljust(20),avdetect + '%')
        print("Total Signatures:".ljust(20),totalsignatures)
        if (bkg == 1):
            print((mycolors.foreground.yellow))
        else:
            print((mycolors.foreground.cyan))
        print("Submit Name:".ljust(20),submitname)
        print("Analysis Time:".ljust(20),analysistime)
        print("File Size:".ljust(20),malsize)
        print("Total Processes:".ljust(20),totalprocesses)
        print("Network Connections:".ljust(20),networkconnections)

        print("\nDomains:")
        for i in domains:
            print("".ljust(20), i)

        print("\nHosts:")
        for i in hosts:
            print("".ljust(20), i, "\t", "city: " + (geocoder.ip(i).city))

        print("\nCompromised Hosts:")
        for i in compromised_hosts:
            print("".ljust(20), i, "\t", "city: " + (geocoder.ip(i).city))

        if (bkg == 1):
            print((mycolors.foreground.lightred))
        else:
            print((mycolors.foreground.cyan))

        print("Vx Family:".ljust(20),vxfamily)
        print("File Type Short:    ", end=' ')
        for i in typeshort:
            print(i, end=' ')

        print("\nClassification Tags:".ljust(20), end=' ')
        for i in classification:
            print(i, end=' ') 

        if (bkg == 1):
            print((mycolors.foreground.pink))
        else:
            print((mycolors.foreground.purple))

        print("\nCertificates:\n", end=' ')
        for i in certificates:
            print("".ljust(20), end=' ')
            print(("owner: %s" % i['owner']))
            print("".ljust(20), end=' ')
            print(("issuer: %s" % i['issuer']))
            print("".ljust(20), end=' ')
            print(("valid_from: %s" % i['valid_from']))
            print("".ljust(20), end=' ')
            print(("valid_until: %s\n" % i['valid_until']))

        if (bkg == 1):
            print(mycolors.foreground.lightgreen)
        else:
            print(mycolors.foreground.purple)

        print("\nMITRE Attacks:\n")
        for i in mitre:
            print("".ljust(20), end=' ')
            print(("tactic: %s" % i['tactic']))
            print("".ljust(20), end=' ')
            print(("technique: %s" % i['technique']))
            print("".ljust(20), end=' ')
            print(("attck_id: %s" % i['attck_id']))
            print("".ljust(20), end=' ')
            print(("attck_id_wiki: %s\n" % i['attck_id_wiki']))

        rc = (hatext)
        if (rc == 0):
            final = 'Not Found'
        print(mycolors.reset)
        return final


    except ValueError as e:
        print(e)
        if(bkg == 1):
            print((mycolors.foreground.lightred + "Error while connecting to Hybrid-Analysis!\n"))
        else:
            print((mycolors.foreground.red + "Error while connecting to Hybrid-Analysis!\n"))
        print(mycolors.reset)


def polymetasearch(poly, metainfo):

    if (metainfo == 0):
        targetfile = poly 
        mysha256hash=''
        dname = str(os.path.dirname(targetfile))
        if os.path.abspath(dname) == False:
            dname = os.path.abspath('.') + "/" + dname
        fname = os.path.basename(targetfile)
        magictype = ftype(targetfile)

        try:

            if re.match(r'^PE[0-9]{2}|^MS-DOS', magictype):
                fmype = pefile.PE(targetfile)
                mymd5hash = md5hash(targetfile)
                mysha256hash = sha256hash(targetfile)
                GS = generalstatus(targetfile)
                fimph = fmype.get_imphash()
            else:
                if (bkg == 1):
                    print(mycolors.foreground.lightred + "\nYou didn\'t provided a PE file")
                else:
                    print(mycolors.foreground.red + "\nYou didn\'t provided a PE file")
                print(mycolors.reset)
                exit(1)

        except (AttributeError, NameError) as e:
            if (bkg == 1):
                print((mycolors.foreground.lightred + "\nThe file %s doesn't respect some PE format rules. Exiting...\n" % targetfile))
            else:
                print((mycolors.foreground.red + "\nThe file %s doesn't respect some PE format rules. Exiting...\n" % targetfile))
            print(mycolors.reset)
            exit(1)

    print(mycolors.reset)
    print("POLYSWARM.NETWORK RESULTS")
    print('-' * 25, end="\n\n")

    try:

        if (metainfo == 0):
            metaresults = polyswarm.search_by_metadata("pefile.imphash:" + fimph)
            for x in metaresults:
                if (bkg == 1):
                    if(x.sha256):
                        print(mycolors.reset + "\nSHA256: " +  mycolors.foreground.lightred + "%s" % x.sha256, end=' ') 
                    else:
                        print(mycolors.reset + "\nSHA256: " +  mycolors.foreground.lightred + "%s" + "None", end=' ') 
                    if(x.md5):
                        print(mycolors.reset + "MD5: " + mycolors.foreground.lightgreen + "%s" % x.md5, end=' ')
                    else:
                        print(mycolors.reset + "MD5: " + mycolors.foreground.lightgreen + "%s" + "None", end=' ')
                else: 
                    if(x.sha256):
                        print(mycolors.reset + "\nSHA256: " +  mycolors.foreground.red + "%s" % x.sha256, end=' ') 
                    else:
                        print(mycolors.reset + "\nSHA256: " +  mycolors.foreground.red + "%s" + "None", end=' ') 
                    if(x.md5):
                        print(mycolors.reset + "MD5: " + mycolors.foreground.green + "%s" % x.md5, end=' ')
                    else:
                        print(mycolors.reset + "MD5: " + mycolors.foreground.green + "%s" + "None", end=' ')
            print(mycolors.reset + "\n")
            sys.exit(0)

        if (metainfo == 1):
            metaresults = polyswarm.search_by_metadata("strings.ipv4:" + poly)
        if (metainfo == 2):
            metaresults = polyswarm.search_by_metadata("strings.domains:" + poly)
        if (metainfo == 3):
            poly = (r'"' + poly + r'"')
            metaresults = polyswarm.search_by_metadata("strings.urls:" + poly)
        if (metainfo == 4):
            poly = ('scan.latest_scan.\*.metadata.malware_family:' + poly)
            metaresults = polyswarm.search_by_metadata(poly)
        for y in metaresults:
            if (bkg == 1):
                if (y.sha256):
                    print(mycolors.reset + "\nSHA256: " +  mycolors.foreground.lightgreen + "%s" % y.sha256, end=' ') 
                else:
                    print(mycolors.reset + "Result: " + mycolors.foreground.yellow + "Sample not found!", end=' ')
                    exit(0)
                score = next(polyswarm.search(y.sha256))
                print(mycolors.reset + "Polyscore: " +  mycolors.foreground.blue + "%20s" % score.polyscore, end=' ') 
                if (str(y.scan.get('detections',{}).get('malicious'))) != 'None':
                    print(mycolors.reset + "scan: " + mycolors.foreground.yellow + "%s" % y.scan.get('detections', {}).get('malicious'), end=' ') 
                    print("/ " + "%2s malicious" % y.scan.get('detections',{}).get('total'), end=' ')
                else:
                    print(mycolors.reset + "scan: " + mycolors.foreground.pink + "not scanned yet", end=' ')
            else:
                if (y.sha256):
                    print(mycolors.reset + "\nSHA256: " +  mycolors.foreground.green + "%s" % y.sha256, end=' ') 
                else:
                    print(mycolors.reset + "scan: " + mycolors.foreground.purple + "Sample not found!", end=' ')
                    exit(0)
                score = next(polyswarm.search(y.sha256))
                print(mycolors.reset + "Polyscore: " +  mycolors.foreground.blue + "%20s" % score.polyscore, end=' ') 
                if (str(y.scan.get('detections',{}).get('malicious'))) != 'None':
                    print(mycolors.reset + "scan: " + mycolors.foreground.red + "%s" % y.scan.get('detections', {}).get('malicious'), end=' ') 
                    print("/ " + "%2s malicious" % y.scan.get('detections',{}).get('total'), end=' ')
                else:
                    print(mycolors.reset + "Result: " + mycolors.foreground.purple + "not scanned yet", end=' ')

        print(mycolors.reset)
        
    except (RetryError) as e:
            if (bkg == 1):
                print((mycolors.foreground.lightred + "\nAn error has ocurred during Polyswarm processing. Exiting...\n"))
            else:
                print((mycolors.foreground.red + "\nAn error has ocurred during Polyswarm processing. Exiting...\n"))
            print(mycolors.reset)
            exit(1)
    
    except Exception:
            if (bkg == 1):
                print((mycolors.foreground.lightred + "\nAn error has ocurred while connecting to Polyswarm.\n"))
            else:
                print((mycolors.foreground.red + "\nAn error has ocurred while connecting to Polyswarm.\n"))
            print(mycolors.reset)
            exit(1)


def polyfile(poly):

    sha256 = '' 
    filetype = ''
    extended = ''
    firstseen = ''
    score = 0

    try:
    
        myhash = sha256hash(poly)
        instance = polyswarm.submit(poly)
        result = polyswarm.wait_for(instance)
        print(mycolors.reset)
        print("POLYSWARM.NETWORK RESULTS")
        print('-' * 25, end="\n\n")
        for assertion in result.assertions:
            if (bkg == 1):
                print(mycolors.reset + "Engine: " + mycolors.foreground.lightgreen + "%-12s" % assertion.author_name, end='')
                print(mycolors.reset + "\tVerdict:" + mycolors.foreground.lightred + " ", "Malicious" if assertion.verdict else "Clean")
            else:
                print(mycolors.reset + "Engine: " + mycolors.foreground.green + "%-12s" % assertion.author_name, end='')
                print(mycolors.reset + "\tVerdict:" + mycolors.foreground.red + " ", "Malicious" if assertion.verdict else "Clean")

        results = polyswarm.search(myhash)
        print(mycolors.reset)
        for myhashes in results:
            if(myhashes.sha256):
                sha256 = myhashes.sha256
            if(myhashes.mimetype):
                filetype = myhashes.mimetype
            if(myhashes.extended_type):
                extended = myhashes.extended_type
            if(myhashes.first_seen):
                firstseen = myhashes.first_seen
            if(myhashes.polyscore):
                score = myhashes.polyscore

        if (bkg == 1):
            if(sha256):
                print(mycolors.foreground.lightcyan + "\nSHA256: \t%s" % sha256)
            if(filetype):
                print(mycolors.foreground.lightred + "File Type: \t%s" % filetype)
            if(extended):
                print(mycolors.foreground.lightred + "Extended Info: \t%s" % extended)
            if(firstseen):
                print(mycolors.foreground.pink + "First seen: \t%s" % firstseen)
            if (score is not None):
                print(mycolors.foreground.yellow + "\nPolyscore: \t%f" % score)
        else:
            if(sha256):
                print(mycolors.foreground.cyan + "\nSHA256: \t%s" % sha256)
            if(filetype):
                print(mycolors.foreground.purple + "File Type: \t%s" % filetype)
            if(extended):
                print(mycolors.foreground.purple + "Extended Info: \t%s" % extended)
            if(firstseen):
                print(mycolors.foreground.blue + "First seen: \t%s" % firstseen)
            if (score is not None):
                print(mycolors.foreground.red + "\nPolyscore: \t%f" % score)
        print(mycolors.reset)

    except:
            if (bkg == 1):
                print((mycolors.foreground.lightred + "\nAn error has ocurred while connecting to Polyswarm.\n"))
            else:
                print((mycolors.foreground.red + "\nAn error has ocurred while connecting to Polyswarm.\n"))
            print(mycolors.reset)
            exit(1)

def polyhashsearch(poly):


    sha256 = '' 
    filetype = ''
    extended = ''
    firstseen = ''
    score = 0
    DOWN_DIR = '.'

    try:

        results = polyswarm.search(poly)

        print(mycolors.reset)
        print("POLYSWARM.NETWORK RESULTS")
        print('-' * 25, end="\n\n")
        print(mycolors.reset)
    
        for myhashes in results:
            if not myhashes.assertions:
                if(bkg == 1):
                    print(mycolors.foreground.lightred + "This sample has not been scanned on Polyswarm yet!\n" + mycolors.reset)
                    exit(1)
                else:
                    print(mycolors.foreground.red + "This sample has not been scanned on Polyswarmi yet!\n" + mycolors.reset)
                    exit(1)
            if(myhashes.sha256):
                sha256 = myhashes.sha256
            if(myhashes.mimetype):
                filetype = myhashes.mimetype
            if(myhashes.extended_type):
                extended = myhashes.extended_type
            if(myhashes.first_seen):
                firstseen = myhashes.first_seen
            if(myhashes.polyscore):
                score = myhashes.polyscore
            results = myhashes.assertions
            for i in results:
                if (bkg == 1):
                    print(mycolors.foreground.lightgreen + "%s" % i)
                else:
                    print(mycolors.foreground.green + "%s" % i)

        if (bkg == 1):
            if(sha256):
                print(mycolors.foreground.lightcyan + "\nSHA256: \t%s" % sha256)
            if(filetype):
                print(mycolors.foreground.lightred + "File Type: \t%s" % filetype)
            if(extended):
                print(mycolors.foreground.lightred + "Extended Info: \t%s" % extended)
            if(firstseen):
                print(mycolors.foreground.pink + "First seen: \t%s" % firstseen)
            if (score is not None):
                print(mycolors.foreground.yellow + "\nPolyscore: \t%f" % score)
            if (down == 1):
                artifact = polyswarm.download(DOWN_DIR, sha256)
                print(mycolors.reset + "\n\nThe sample has been SAVED!")
        else:
            if(sha256):
                print(mycolors.foreground.cyan + "\nSHA256: \t%s" % sha256)
            if(filetype):
                print(mycolors.foreground.purple + "File Type: \t%s" % filetype)
            if(extended):
                print(mycolors.foreground.purple + "Extended Info: \t%s" % extended)
            if(firstseen):
                print(mycolors.foreground.blue + "First seen: \t%s" % firstseen)
            if (score is not None):
                print(mycolors.foreground.red + "\nPolyscore: \t%f" % score)
            if (down == 1):
                artifact = polyswarm.download(DOWN_DIR, sha256)
                print(mycolors.reset + "\n\nThe sample has been SAVED!")
        print(mycolors.reset)

    except:
            if (bkg == 1):
                print((mycolors.foreground.yellow + "\nThis hash couldn't be found on Polyswarm.\n"))
            else:
                print((mycolors.foreground.red + "\nThis hash couldn't be found Polyswarm.\n"))
            print(mycolors.reset)
            exit(1)


def hafilecheck(filenameha):

    hatext = ''
    haresponse = ''
    resource = ''
    haenv = '100'
    job_id = ''

    try:

        if (xx == 0):
            haenv = '100'
        elif (xx == 1):
            haenv = '110'
        elif (xx == 2):
            haenv = '120'
        elif (xx == 3):
            haenv = '200'
        else:
            haenv = '300'

        resource = {'file': (os.path.basename(filenameha), open(filenameha, 'rb')), 'environment_id': (None, haenv)}

        mysha256hash = sha256hash(filenameha)

        if (bkg == 1):
            print((mycolors.foreground.lightcyan + "\nSubmitted file: %s".ljust(20) % filenameha))
            print(("Submitted hash: %s".ljust(20) % mysha256hash))
            print(("Environment ID: %3s" % haenv))
            print((Fore.WHITE))
        else:
            print((mycolors.foreground.purple + "\nSubmitted file: %s".ljust(20) % filenameha))
            print(("Submitted hash: %s".ljust(20) % mysha256hash))
            print(("Environment ID: %3s" % haenv))
            print((Fore.BLACK))

        requestsession = requests.Session( )
        requestsession.headers.update({'user-agent': user_agent})
        requestsession.headers.update({'api-key': HAAPI})
        requestsession.headers.update({'accept': 'application/json'})

        finalurl = '/'.join([haurl,'submit', 'file'])

        haresponse = requestsession.post(url=finalurl, files=resource)

        hatext = json.loads(haresponse.text)

        rc = str(hatext)

        job_id = str(hatext['job_id'])
        hash_received = str(hatext['sha256'])
        environment_id = str(hatext['environment_id'])

        if (job_id) in rc:
            if (bkg == 1):
                print((mycolors.foreground.yellow + "The suspicious file has been successfully submitted to Hybrid Analysis."))
                print(("\nThe job ID is: ").ljust(31), end=' ')
                print(("%s" % job_id))
                print(("The environment ID is: ").ljust(30), end=' ')
                print(("%s" % environment_id))
                print(("The received sha256 hash is: ").ljust(30), end=' ')
                print(("%s" % hash_received))
                print((mycolors.reset + "\n"))
            else:
                print((mycolors.foreground.green + "The suspicious file has been successfully submitted to Hybrid Analysis."))
                print(("\nThe job ID is: ").ljust(31), end=' ')
                print(("%s" % job_id))
                print(("The environment ID is: ").ljust(30), end=' ')
                print(("%s" % environment_id))
                print(("The received sha256 hash is: ").ljust(30), end=' ')
                print(("%s" % hash_received))
                print((mycolors.reset + "\n"))

        else:
            if (bkg == 1):
                print((mycolors.foreground.lightred + "\nAn error occured while sending the file!"))
                print((mycolors.reset + "\n"))
            else:
                print((mycolors.foreground.red + "\nAn error occured while sending the file!"))
                print((mycolors.reset + "\n"))


    except ValueError as e:
        print(e)
        if (bkg == 1):
            print((mycolors.foreground.lightred + "Error while connecting to Hybrid-Analysis!\n"))
        else:
            print((mycolors.foreground.red + "Error while connecting to Hybrid-Analysis!\n"))
        print((mycolors.reset))


def checkreportha(jobid):

    hatext = ''
    haresponse = ''

    try:

        resource = jobid
        requestsession = requests.Session( )
        requestsession.headers.update({'user-agent': user_agent})
        requestsession.headers.update({'api-key': HAAPI})
        requestsession.headers.update({'content-type': 'application/json'})

        finalurl = '/'.join([haurl,'report', resource , 'state'])

        haresponse = requestsession.get(url=finalurl)
        hatext = json.loads(haresponse.text)

        job_id = jobid

        if ("state" in haresponse.text):
            if (bkg == 1):
                print((mycolors.foreground.yellow + "\nThe report status related to the provided job ID follows below:"))
                print(("\nThe job ID is: ").ljust(31), end=' ')
                print(("%s" % job_id))
                print(("The report status is: ").ljust(30), end=' ')
                print(("%s" % str(hatext['state'])))
                print((mycolors.reset + "\n"))
            else:
                print((mycolors.foreground.purple + "\nThe report status related to the provided job ID follows below:"))
                print(("\nThe job ID is: ").ljust(31), end=' ')
                print(("%s" % job_id))
                print(("The report status is: ").ljust(30), end=' ')
                print(("%s" % str(hatext['state'])))
                print((mycolors.reset + "\n"))
        else:
            if (bkg == 1):
                print((mycolors.foreground.lightred + "\nThere isn't any report associated to this job ID, unfortunately."))
                print((mycolors.reset + "\n"))
            else:
                print((mycolors.foreground.red + "\nThere isn't any report associated to ths job ID, unfortunately"))
                print((mycolors.reset + "\n"))

    except ValueError as e:
        print(e)
        if (bkg == 1):
            print((mycolors.foreground.lightred + "Error while connecting to Hybrid-Analysis!\n"))
        else:
            print((mycolors.foreground.red + "Error while connecting to Hybrid-Analysis!\n"))
        print((mycolors.reset))


def downhash(filehash):

    hatext = ''
    haresponse = ''
    final = ''

    try:

        resource = filehash
        requestsession = requests.Session( )
        requestsession.headers.update({'user-agent': user_agent})
        requestsession.headers.update({'api-key': HAAPI})
        requestsession.headers.update({'accept': 'application/gzip'})

        finalurl = '/'.join([haurl,'overview', resource , 'sample'])

        haresponse = requestsession.get(url=finalurl, allow_redirects=True)

        try:

            hatext = haresponse.text

            rc = str(hatext)
            if 'message' in rc:
                final = 'Malware sample is not available to download.'
                if (bkg == 1):
                    print((mycolors.foreground.lightred + "\n" + final + "\n"))
                else:
                    print((mycolors.foreground.red + "\n" + final + "\n"))
                print((mycolors.reset))
                return final

            open(resource + '.gz', 'wb').write(haresponse.content)
            final = 'SAMPLE SAVED!'

            print((mycolors.reset))
            print((final + "\n"))
            return final

        except ValueError as e:
            print(e)
            if(bkg == 1):
                print((mycolors.foreground.lightred + "Error while downloading Hybrid-Analysis!\n"))
            else:
                print((mycolors.foreground.red + "Error while downloading Hybrid-Analysis!\n"))
            print(mycolors.reset)

    except ValueError as e:
        print(e)
        if(bkg == 1):
            print((mycolors.foreground.lightred + "Error while connecting to Hybrid-Analysis!\n"))
        else:
            print((mycolors.foreground.red + "Error while connecting to Hybrid-Analysis!\n"))
        print(mycolors.reset)


def overextract(fname):

    with open(fname, "rb") as o:
        r = o.read()
    pe = pefile.PE(fname)
    offset = pe.get_overlay_data_start_offset( )
    if offset == None:
       exit(0)
    with open(fname + ".overlay", "wb") as t:
        t.write(r[offset:])
    if (bkg == 1):
        print((mycolors.foreground.lightgreen + "\nOverlay extracted: %s.overlay\n"  % fname))
    else:
        print((mycolors.foreground.red + "\nOverlay extracted: %s.overlay\n"  % fname))
    print(mycolors.reset)


def keysort(item):
    return item[1]


def generalstatus(key):

    vtfinal = ''
    result = ' '
    ovr = ''
    entr = ''
    G = []

    if (vt>=1):
        myfilehash = sha256hash(key)
        vtfinal = vtcheck(myfilehash, url, param)
    G.append(vtfinal)
    mype2 = pefile.PE(key)
    over = mype2.get_overlay_data_start_offset()
    if over == None:
        ovr =  ""
    else:
        ovr =  "OVERLAY"
    G.append(ovr)
    rf = mype2.write()
    entr = mype2.sections[0].entropy_H(rf)
    G.append(entr)
    pack = packed(mype2)
    if pack == False:
        result = "no    "
    elif pack == True:
        result = "PACKED"
    else:
        result = "Likely"
    G.append(result)
    return G


def hashchecking( ):

    print ("\n")
    print(mycolors.reset)
    print("Main Antivirus Reports")
    print("-" * 25 + "\n")

    vtresult = vtshow(hashtemp,url,param)

    if vtresult == 'Not Found':
        if(bkg == 1):
            print(mycolors.foreground.lightred + "Malware sample was not found in Virus Total.")
        else:
            print(mycolors.foreground.red + "Malware sample was not found in Virus Total.")

    print(mycolors.reset)

    hashow(hashtemp)
    if (down == 1):
         downhash(hashtemp)
    print(mycolors.reset)
    exit(0)


def filechecking(ffpname2):
    GS = []
    targetfile = ffpname2
    mymd5hash=''
    mysha256hash=''
    dname = str(os.path.dirname(targetfile))
    if os.path.abspath(dname) == False:
        dname = os.path.abspath('.') + "/" + dname
    fname = os.path.basename(targetfile)
    magictype = ftype(targetfile)

    print(mycolors.reset, end=' ')

    try:

        if re.match(r'^PE[0-9]{2}|^MS-DOS', magictype):
            fmype = pefile.PE(targetfile)
            mymd5hash = md5hash(targetfile)
            mysha256hash = sha256hash(targetfile)
            GS = generalstatus(targetfile)
            fimph = fmype.get_imphash()
            S = []
            if (bkg == 1):
                print((mycolors.foreground.lightcyan), end = '')
            else:
                print((mycolors.foreground.blue), end = '')
            print(("\nFile Name:   %s" % targetfile))
            print(("File Type:   %s\n" % magictype))
            print(("MD5:         %s" % mymd5hash))
            print(("SHA256:      %s" % mysha256hash))
            print(("Imphash:     %s\n" % fimph))
            if (bkg == 1):
                print((mycolors.foreground.lightred + "entropy: %8.2f" % GS[2]))
            else:
                print((mycolors.foreground.red + "entropy: %8.2f" % GS[2]))
            print(("Packed?: %10s" % GS[3]))
            print(("Overlay?: %10s" % GS[1]))
            print(("VirusTotal: %6s" % GS[0]))
            print(mycolors.reset)
            if(bkg == 1):
                print((mycolors.foreground.yellow + ""))
            else:
                print((mycolors.foreground.green + ""))

            listsections(targetfile)

            if (showreport == 1):
                print(mycolors.reset)
                print("\nMain Antivirus Reports:")
                print((40*'-').ljust(40))
                vtshow(mysha256hash,url,param)

            if (ha == 1):
                hashow(mysha256hash)

            if (ie == 1):
                impext(targetfile)

            print(mycolors.reset)

            if (ovrly == 1):
                status_over = overextract(targetfile)

            listdlls(targetfile)

            print(mycolors.reset)
            exit(0)

        else:
            vtfinal = ''
            mymd5hash = md5hash(targetfile)
            mysha256hash = sha256hash(targetfile)
            if (bkg == 1):
                print((mycolors.foreground.yellow + "\nFile Name:   %s" % targetfile))
            else:
                print((mycolors.foreground.purple + "\nFile Name:   %s" % targetfile))
            print(("File Type:   %s" % magictype))
            if (bkg == 1):
                print((mycolors.foreground.lightcyan + "MD5:         %s" % mymd5hash))
                print(("SHA256:      %s" % mysha256hash))
            else:
                print((mycolors.foreground.cyan + "MD5:         %s" % mymd5hash))
                print(("SHA256:      %s" % mysha256hash))
            print(mycolors.reset)
            if (vt>=1):
                vtfinal = vtcheck(mysha256hash, url, param)
            if(bkg == 1):
                print((mycolors.foreground.lightred + "VirusTotal: %6s\n" % vtfinal))
            else:
                print((mycolors.foreground.red + "VirusTotal: %6s\n" % vtfinal))
            if (showreport == 1):
                print(mycolors.reset)
                print("\nMain Antivirus Reports:")
                print((40*'-').ljust(40))
                vtshow(mysha256hash,url,param)
            if (ha == 1):
                hashow(mysha256hash)
            print(mycolors.reset)
            exit(0)

    except (AttributeError, NameError) as e:
        if (bkg == 1):
            print((mycolors.foreground.yellow + "\t\tThe file %s seems not having a valid Import Table.\n" % targetfile))
            pass
        else:
            print((mycolors.foreground.red + "\t\tThe file %s seems not having a valid Import Table.\n" % targetfile))
        print(mycolors.reset)
        exit(1)


def quickhashow(filehash):

    hatext = ''
    haresponse = ''
    final = 'Yes'
    verdict = '-'
    avdetect = '0'
    totalsignatures = '-'
    threatscore = '-'
    totalprocesses = '-'
    networkconnections = '-'

    try:

        resource = filehash
        requestsession = requests.Session( )
        requestsession.headers.update({'user-agent': user_agent})
        requestsession.headers.update({'api-key': HAAPI})
        requestsession.headers.update({'content-type': 'application/json'})

        if (xx == 0):
            finalurl = '/'.join([haurl,'report', resource + ':100', 'summary'])
        elif (xx == 1):
            finalurl = '/'.join([haurl,'report', resource + ':110', 'summary'])
        elif (xx == 2):
            finalurl = '/'.join([haurl,'report', resource + ':120', 'summary'])
        elif (xx == 3):
            finalurl = '/'.join([haurl,'report', resource + ':200', 'summary'])
        else:
            finalurl = '/'.join([haurl,'report', resource + ':300', 'summary'])

        haresponse = requestsession.get(url=finalurl)
        hatext = json.loads(haresponse.text)

        rc = str(hatext)
        if 'message' in rc:
            final = 'Not Found'
            return (final, verdict, avdetect, totalsignatures, threatscore, totalprocesses, networkconnections)
        
        rc2 = (hatext)
        if (rc2 == 0):
            final = 'Not Found'
            return (final, verdict, avdetect, totalsignatures, threatscore, totalprocesses, networkconnections)

        if 'verdict' in hatext:
            verdict = str(hatext['verdict'])
        else:
            verdict = ''

        if 'threat_score' in hatext:
            threatscore = str(hatext['threat_score'])
        else:
            threatscore = ''

        if 'av_detect' in hatext:
            avdetect = str(hatext['av_detect'])
        else:
            avdetect = ''

        if 'total_signatures' in hatext:
            totalsignatures = str(hatext['total_signatures'])
        else:
            totalsignatures = ''

        if 'total_processes' in hatext:
            totalprocesses = str(hatext['total_processes'])
        else:
            totalprocesses = ''

        if 'total_network_connections' in hatext:
            networkconnections =  str(hatext['total_network_connections'])
        else:
            networkconnections = ''

        return (final, verdict, avdetect, totalsignatures, threatscore, totalprocesses, networkconnections)

    except ValueError as e:
        print(e)
        if (bkg == 1):
            print((mycolors.foreground.lightred + "Error while connecting to Hybrid-Analysis!\n"))
        else:
            print((mycolors.foreground.red + "Error while connecting to Hybrid-Analysis!\n"))
        print(mycolors.reset)


def nothreadworks(key, value, tm, n, result, prev1, prev2):

    key1 = key
    value1 = value
    tm1 = tm
    n1 = n
    result1 = result
    prev1a = prev1
    prev2a = prev2

    if (vt==1):
        if (gt == 1):
            tm1 = tm1 + 1
            if tm1 % 4 == 0:
                time.sleep(61)
            myhashdir = sha256hash(key1)
            vtfinal = vtcheck(myhashdir, url, param)
        else:
            myhashdir = sha256hash(key1)
            vtfinal = vtcheck(myhashdir, url, param)

    myfiletype = magic.from_file(key1)

    if myfiletype is None:

        ovr = '-'
        result1 = '-'
        entr = 0.00

    elif (('PE32' or 'PE32+') in myfiletype):

        mype2 = pefile.PE(key1)
        over = mype2.get_overlay_data_start_offset()
        if over == None:
            ovr =  ""
        else:
            ovr =  "OVERLAY"
        rf = mype2.write()
        entr = mype2.sections[0].entropy_H(rf)
        pack = packed(mype2)
        if pack == False:
            result1 = "no"
        elif pack == True:
            result1 = "PACKED"
        else:
            result1 = "Likely"

    else:

        ovr = '-'.center(7)
        result1 = 'no'
        entr = 0.00
        width = 32
        value1 = (myfiletype[:32]) if len(myfiletype) > 30 else f'{myfiletype: <{width}}'
        

    if (bkg == 1):
        if ((prev2a == prev1a) and (n1 < 97)):
            print(("\033[%dm" % n1 + "%-68s" % key1), end=' ')
            print(("\033[%dm" % n1 + "  %-2s" % value1), end=' ')
            print(("\033[%dm" % n1 + "  %-6s" % result1), end=' ')
            print(("\033[%dm" % n1 + "  %7s" % ovr), end=' ')
            print(("\033[%dm" % n1 + "      %4.2f" % entr) + mycolors.reset, end=' ')
            if (vt == 1):
                print(("\033[%dm" % n1 + "  %8s" % vtfinal) + mycolors.reset)
            else:
                print(("\033[%dm" % n1 + "  %8s" % '     ') + mycolors.reset)
        else:
            if ((n1 > 96) and (prev1a != prev2a)):
                n1 = 90
            elif (n1 > 96):
                n1 = 96
            n1 = n1 + 1
            print(("\033[%dm" % n1 + "%-68s" % key1), end=' ')
            print(("\033[%dm" % n1 + "  %-2s" % value1), end=' ')
            print(("\033[%dm" % n1 + "  %-6s" % result1), end=' ')
            print(("\033[%dm" % n1 + "  %7s" % ovr), end=' ')
            print(("\033[%dm" % n1 + "      %4.2f" % entr) + mycolors.reset, end =' ')
            if (vt == 1):
                print(("\033[%dm" % n1 + "  %8s" % vtfinal) + mycolors.reset)
            else:
                print(("\033[%dm" % n1 + "  %8s" % '     ') + mycolors.reset)

            prev2a = value1

    else:
        if ((prev2a == prev1a) and (n1 < 96)):
            print(("\033[%dm" % n1 + "%-68s" % key1), end=' ')
            print(("\033[%dm" % n1 + "  %-2s" % value1), end=' ')
            print(("\033[%dm" % n1 + "  %-6s" % result1), end=' ')
            print(("\033[%dm" % n1 + "  %7s" % ovr), end=' ')
            print(("\033[%dm" % n1 + "      %4.2f" % entr) + mycolors.reset, end=' ')
            if (vt == 1):
                print(("\033[%dm" % n1 + "  %8s" % vtfinal) + mycolors.reset)
            else:
                print(("\033[%dm" % n1 + "  %8s" % '     ') + mycolors.reset)
        else:
            if ((n1 > 95) and (prev1a != prev2a)):
                n1 = 89
            elif (n1 > 95):
                n1 = 95
            n1 = n1 + 1
            print(("\033[%dm" % n1 + "%-68s" % key1), end=' ')
            print(("\033[%dm" % n1 + "  %-2s" % value1), end=' ')
            print(("\033[%dm" % n1 + "  %-6s" % result1), end=' ')
            print(("\033[%dm" % n1 + "  %7s" % ovr), end=' ')
            print(("\033[%dm" % n1 + "      %4.2f" % entr) + mycolors.reset, end=' ')
            if (vt == 1):
                print(("\033[%dm" % n1 + "  %8s" % vtfinal) + mycolors.reset)
            else:
                print(("\033[%dm" % n1 + "  %8s" % '     ') + mycolors.reset)

            prev2a = value1

    prev1 = prev1a
    prev2 = prev2a
    n = n1
    result = result1
    tm = tm1
    return (prev1, prev2, n, result, tm)


class abThread(threading.Thread):

    def __init__(self, key, value):

        threading.Thread.__init__(self)
        self.key = key
        self.value = value

    def run(self):

        key1 = self.key
        value1 = self.value

        if (vt==1):
            myhashdir = sha256hash(key1)
            vtfinal = vtcheck(myhashdir, url, param)

        myfiletype = magic.from_file(key1)

        if myfiletype is None:

            ovr = '-'
            result1 = '-'
            entr = 0.00

        elif (('PE32' or 'PE32+') in myfiletype):

            mype2 = pefile.PE(key1)
            over = mype2.get_overlay_data_start_offset()
            if over == None:
                 ovr =  ""
            else:
                ovr =  "OVERLAY"
            rf = mype2.write()
            entr = mype2.sections[0].entropy_H(rf)
            pack = packed(mype2)
            if pack == False:
                result1 = "no"
            elif pack == True:
                result1 = "PACKED"
            else:
                result1 = "Likely"

        else:

            ovr = '-'.center(7)
            result1 = 'no'
            entr = 0.00
            width = 32
            value1 = (myfiletype[:32]) if len(myfiletype) > 30 else f'{myfiletype: <{width}}'


        if (bkg == 1):
            print((mycolors.foreground.yellow + "%-68s" % key1), end=' ')
            print((mycolors.foreground.lightcyan + "  %-2s" % value1), end=' ')
            print((mycolors.foreground.lightred + "  %-6s" % result1), end=' ')
            print((mycolors.foreground.pink + "  %7s" % ovr), end=' ')
            print((mycolors.foreground.lightgreen + "      %4.2f" % entr) + mycolors.reset, end=' ')
            if (vt == 1):
                print((mycolors.foreground.yellow + "  %8s" % vtfinal + mycolors.reset))
            else:
                print(("  %8s" % '     ') + mycolors.reset)
        else:
            print((mycolors.foreground.red + "%-68s" % key1), end=' ')
            print((mycolors.foreground.cyan + "  %-2s" % value1), end=' ')
            print((mycolors.foreground.blue + "  %-6s" % result1), end=' ')
            print((mycolors.foreground.purple + "  %7s" % ovr), end=' ')
            print((mycolors.foreground.green + "      %4.2f" % entr) + mycolors.reset, end =' ')
            if (vt == 1):
                print((mycolors.foreground.red + "  %8s" % vtfinal + mycolors.reset))
            else:
                print(("  %8s" % '     ') + mycolors.reset)


class quickVTThread(threading.Thread):

    def __init__(self, key):

        threading.Thread.__init__(self)
        self.key = key

    def run(self):

        key1 = self.key

        myhashdir = sha256hash(key1)
        vtfinal = vtcheck(myhashdir, url, param)

        if (bkg == 1):
            print((mycolors.foreground.orange +  "%-68s" % key1), end=' ')
            print((mycolors.reset + "|" + mycolors.foreground.lightgreen + "%8s" % vtfinal + mycolors.reset))
        else:
            print((mycolors.foreground.cyan + "%-68s" % key1), end=' ')
            print((mycolors.reset + "|" + mycolors.foreground.red + "%8s" % vtfinal + mycolors.reset))


class quickHAThread(threading.Thread):

    def __init__(self, key):

        threading.Thread.__init__(self)
        self.key = key

    def run(self):

        key1 = self.key

        myhashdir = sha256hash(key1)
        (final, verdict, avdetect, totalsignatures, threatscore, totalprocesses, networkconnections) =  quickhashow(myhashdir)

        if (bkg == 1):
            print((mycolors.foreground.orange + "%-70s" % key1), end=' ')
            print((mycolors.foreground.lightcyan + "%9s" % final), end='')
            print((mycolors.foreground.lightred + "%11s" % verdict), end='')
            if(avdetect == 'None'):
                print((mycolors.foreground.pink + "%7s" % avdetect), end='')
            else:
                print((mycolors.foreground.pink + "%6s%%" % avdetect), end='')
            print((mycolors.foreground.yellow + "%7s" % totalsignatures), end='')
            if(threatscore == 'None'):
                print((mycolors.foreground.lightred + "%12s" % threatscore), end='')
            else:
                print((mycolors.foreground.lightred + "%8s/100" % threatscore), end='')
            print((mycolors.foreground.lightgreen + "%6s" % totalprocesses), end='')
            print((mycolors.foreground.lightgreen + "%6s" % networkconnections + mycolors.reset))
        else:
            print((mycolors.foreground.lightcyan + "%-70s" % key1), end=' ')
            print((mycolors.foreground.cyan + "%9s" % final), end='')
            print((mycolors.foreground.red + "%11s" % verdict), end='')
            if (avdetect == 'None'):
                print((mycolors.foreground.purple + "%7s" % avdetect), end='')
            else:
                print((mycolors.foreground.purple + "%6s%%" % avdetect), end='')
            print((mycolors.foreground.green + "%7s" % totalsignatures), end='')
            if(threatscore == 'None'):
                print((mycolors.foreground.red + "%12s" % threatscore), end='')
            else:
                print((mycolors.foreground.red + "%8s/100" % threatscore), end='')
            print((mycolors.foreground.blue + "%6s" % totalprocesses), end='')
            print((mycolors.foreground.blue + "%6s" % networkconnections + mycolors.reset))


def dirwork(d):

    x = d
    global n
    n = 90
    global prev1
    prev1 = 0
    global prev2
    prev2 = 0
    global result
    result = ""
    global tm
    tm = 0
    global value

    for key,value in sorted(iter(x.items()), key=lambda k_v:(k_v[1],k_v[0])):

        vtfinal=''

        if (T == 1):
            if (windows == 1):
                thread = abThread(key, value)
                thread.start()
                thread.join()
            else:
                thread = abThread(key, value)
                thread.start()
        else:
            prev1 = value
            (prev1, prev2, n, result, tm) = nothreadworks(key, value, tm, n, result, prev1, prev2)


def dirquick(d):

    y = d

    if (vt == 1):
        print("FileName".center(70) +  "VT".center(12))
        print((83*'-').center(41))
    if (ha >= 1):
        print("FileName".center(70) + "Found?".center(10) + "Verdict".center(14) + "AVdet".center(6) + "Sigs".center(5) + "Score".center(14) + "Procs".center(6) + "Conns".center(6))
        print((130*'-').center(60))

    for key,value in sorted(iter(y.items()), key=lambda k_v:(k_v[1],k_v[0])):

        if (ha >= 1):
            if (windows == 1):
                thread = quickHAThread(key)
                thread.start()
                thread.join()
            else:
                thread = quickHAThread(key)
                thread.start()

        if (vt == 1):
            if (windows == 1):
                thread = quickVTThread(key)
                thread.start()
                thread.join()
            else:
                thread = quickVTThread(key)
                thread.start()


def malsharedown(filehash):

    maltext3 = ''
    malresponse3 = ''
    resource = ''

    try:

        resource = filehash
        requestsession3 = requests.Session( )
        finalurl3 = ''.join([urlmalshare, MALSHAREAPI, '&action=getfile&hash=', resource])
        malresponse3 = requestsession3.get(url=finalurl3, allow_redirects=True)
        open(resource, 'wb').write(malresponse3.content)

        print("\n")
        print((mycolors.reset + "MALWARE SAMPLE SAVED! "))
        print((mycolors.reset))

    except (BrokenPipeError, IOError):
        print(mycolors.reset , file=sys.stderr)
        exit(1)

    except ValueError as e:
        print(e)
        if(bkg == 1):
            print((mycolors.foreground.lightred + "Error while connecting to Malshare.com!\n"))
        else:
            print((mycolors.foreground.red + "Error while connecting to Malshare.com!\n"))
        print(mycolors.reset)


def urltoip(urltarget):

    geoloc= ''
    target = ''
    finalip = ''
    result = ''

    try:
        target = urlparse(urltarget)
        result = target.netloc
        finalip = socket.gethostbyname(result)
        if finalip is not None:
            geoloc = geocoder.ip(finalip)
            if (geoloc is not None):
                return geoloc.city
            else:
                result = ''
                return result 
        else:
            result = "Not Found"
            return result

    except:
        result = "Not Found"
        return result
        print(mycolors.reset)


def malsharehashsearch(filehash):

    maltext2 = ''
    malresponse2 = ''
    resource = ''

    try:
        
        print("\n")
        print((mycolors.reset + "MALSHARE REPORT ".center(74)), end='')
        print("\n" + (74*'-').center(37))
        print((mycolors.reset))

        resource = filehash
        requestsession2 = requests.Session( )
        requestsession2.headers.update({'accept': 'application/json'})
        finalurl2 = ''.join([urlmalshare, MALSHAREAPI, '&action=search&query=', resource])
        malresponse2 = requestsession2.get(url=finalurl2)
        if (malresponse2.text == ''):
            if(bkg == 1):
               print(mycolors.foreground.lightred + "This sample couldn't be found on Malshare.\n" + mycolors.reset) 
               exit(1)
            else:
               print(mycolors.foreground.red + "This sample couldn't be found on Malshare.\n" + mycolors.reset) 
               exit(1)

        maltext2 = json.loads(malresponse2.text)
        if (maltext2):
            try:
                if ((maltext2[0])['sha256']):
                    urltemp = (maltext2[0])['source']
                    if (validators.url(urltemp)) == True:
                        loc = urltoip(urltemp)
                    else:
                        loc = ''
                    if (bkg == 1):
                        print((mycolors.reset + "sha256: " + mycolors.foreground.yellow + "%s\n" % (maltext2[0])['sha256'] + mycolors.reset + "sha1:   " + mycolors.foreground.yellow + "%s\n" % (maltext2[0])['sha1'] + mycolors.reset + "md5:    " + mycolors.foreground.yellow + "%s\n" %  (maltext2[0])['md5'] + mycolors.reset + "type:   " + mycolors.foreground.lightcyan + "%s\n" % (maltext2[0])['type'] + mycolors.reset + "source: " + mycolors.foreground.lightred + "%s\n" % (maltext2[0])['source'] + mycolors.reset + "city:   " + mycolors.foreground.lightgreen + "%s" % loc))
                        for k in (maltext2[0])['yarahits']['yara']:
                            print(mycolors.reset + "Yara Hits: " + mycolors.foreground.lightgreen + str(k))
                    else:
                        print((mycolors.reset + "sha256: " + mycolors.foreground.green + "%s\n" % (maltext2[0])['sha256'] + mycolors.reset + "sha1:   " + mycolors.foreground.green + "%s\n" % (maltext2[0])['sha1'] + mycolors.reset + "md5:    " + mycolors.foreground.green +"%s\n" %  (maltext2[0])['md5'] + mycolors.reset + "type:   " + mycolors.foreground.cyan + "%s\n" % (maltext2[0])['type'] + mycolors.reset + "source: " + mycolors.foreground.red + "%s\n" % (maltext2[0])['source'] + mycolors.reset + "city:   " + mycolors.foreground.blue + "%s" % loc))
                        for k in (maltext2[0])['yarahits']['yara']:
                            print(mycolors.reset + "Yara Hits: " + mycolors.foreground.purple + str(k))

                if (maldownload == 1):
                    malsharedown(filehash)

            except KeyError as e:
                pass

            except (BrokenPipeError, IOError):
                print(mycolors.reset , file=sys.stderr)
                exit(1)
    except ValueError as e:
        print(e)
        if(bkg == 1):
            print((mycolors.foreground.lightred + "Error while connecting to Malshare.com!\n"))
        else:
            print((mycolors.foreground.red + "Error while connecting to Malshare.com!\n"))
        print(mycolors.reset)


class LocationThread(threading.Thread):

    def __init__(self, key):

        threading.Thread.__init__(self)
        self.key = key

    def run(self):

        url = self.key
        if (validators.url(url)) == True:
            loc = urltoip(url)
        else:
            loc = 'URL not valid.'
        if (bkg == 1):
            print((mycolors.reset + "URL: " + mycolors.foreground.yellow + "%-100s" % url + mycolors.reset + "  City: " + mycolors.foreground.lightred + "%s" % loc + mycolors.reset))
        else:
            print((mycolors.reset + "URL: " + mycolors.foreground.blue + "%-100s" % url + mycolors.reset + "  City: " + mycolors.foreground.red + "%s" % loc + mycolors.reset))


def malsharelastlist(typex):

    maltext = ''
    malresponse = ''
    filetype = ''
    maltype = typex

    if (maltype == 1):
        filetype = 'PE32'
    elif (maltype == 2):
        filetype = 'Dalvik'
    elif (maltype == 3):
        filetype = 'ELF'
    elif (maltype == 4):
        filetype = 'HTML'
    elif (maltype == 5):
        filetype = 'ASCII'
    elif (maltype == 6):
        filetype = 'PHP'
    elif (maltype == 7):
        filetype = 'Java'
    elif (maltype == 8):
        filetype = 'RAR'
    elif (maltype == 9):
        filetype = 'Zip'
    elif (maltype == 10):
        filetype = 'UTF-8'
    elif (maltype == 11):
        filetype = 'MS-DOS'
    elif (maltype == 12):
        filetype = 'data'
    elif (maltype == 13):
        filetype = 'PDF'
    else:
        filetype = 'Composite'

    try:

        print("\n")
        print((mycolors.reset + "SHA256 hash".center(75)), end='')
        print((mycolors.reset + "MD5 hash".center(38)), end='')
        print((mycolors.reset + "File type".center(8)), end='')
        print("\n" + (126*'-').center(59))
        print((mycolors.reset))

        requestsession = requests.Session( )
        requestsession.headers.update({'accept': 'application/json'})
        finalurl = ''.join([urlmalshare, MALSHAREAPI, '&action=type&type=', filetype])
        malresponse = requestsession.get(url=finalurl)
        maltext = json.loads(malresponse.text)

        if ((maltext)):
            try:
                for i in range(0, len(maltext)):
                    if (maltext[i].get('sha256')):
                        if (bkg == 1):
                            print((mycolors.reset + "sha256: " + mycolors.foreground.yellow + "%s" % maltext[i]['sha256'] + mycolors.reset + "  md5: " + mycolors.foreground.lightgreen + "%s" % maltext[i]['md5'] + mycolors.reset + "  type: " + mycolors.foreground.lightred + "%s" % filetype))
                        else:
                            print((mycolors.reset + "sha256: " + mycolors.foreground.red + "%s" % maltext[i]['sha256'] + mycolors.reset + "  md5: " + mycolors.foreground.blue + "%s" % maltext[i]['md5'] + mycolors.reset + "   type: " + mycolors.foreground.purple + "%s" % filetype))

            except KeyError as e:
                pass

            except (BrokenPipeError, IOError):
                print(mycolors.reset, file=sys.stderr)
                exit(1)

    except ValueError as e:
        print(e)
        if (bkg == 1):
            print((mycolors.foreground.lightred + "Error while connecting to Malshare.com!\n"))
        else:
            print((mycolors.foreground.red + "Error while connecting to Malshare.com!\n"))
        print(mycolors.reset)

    return


def urlhauscheck(urlx, haus):

    haustext = ''
    hausresponse = ''
    finalurl5 = ''

    try:
        
        print("\n")
        print((mycolors.reset + "URLhaus Report".center(100)), end='')
        print((mycolors.reset + "".center(28)), end='')
        print("\n" + (126*'-').center(59))

        requestsession = requests.Session( )
        requestsession.headers.update({'accept': 'application/json'})
        params = {"url": urlx}
        hausresponse = requestsession.post(haus, data=params)
        haustext = json.loads(hausresponse.text)


        if (haustext.get('id') is None):
            if (bkg == 1):
                print(mycolors.foreground.lightred + "URL not found!\n" + mycolors.reset)
            else:
                print(mycolors.foreground.red + "URL not found!\n" + mycolors.reset)
            exit(1)

        if 'query_status' in haustext:
            if (bkg == 1):
                print(mycolors.foreground.lightgreen + "Is available?: \t"  +  haustext.get('query_status').upper())
            else:
                print(mycolors.foreground.purple + "Is available?: \t"  +  haustext.get('query_status').upper())
        else:
            if (bkg == 1):
                print(mycolors.foreground.lightgreen + 'Is availble?: ')
            else:
                print(mycolors.foreground.purple + 'Is available: ')

        if 'url' in haustext:
            if(validators.url(haustext.get('url'))) == True:
                urlcity = urltoip(haustext.get('url'))
                if(urlcity is None):
                    urlcity = 'Not found'
            else:
                urlcity = 'Not found' 
            if (bkg == 1):
                print(mycolors.foreground.lightgreen + "URL: \t\t"  +  haustext.get('url') + "  (city: " +  urlcity + ")" )
            else:
                print(mycolors.foreground.purple + "URL: \t\t"  +  haustext.get('url') + "  (city: " +  urlcity + ")" )
        else:
            if (bkg == 1):
                print(mycolors.foreground.lightgreen + 'URL: ')
            else:
                print(mycolors.foreground.purple + 'URL: ')
        
        if 'url_status' in haustext:
            if (bkg == 1):
                if(haustext.get('url_status') == 'online'):
                    print(mycolors.foreground.lightgreen + "Status: \t"  + mycolors.reverse + haustext.get('url_status') + mycolors.reset)
                if(haustext.get('url_status') == 'offline'):
                    print(mycolors.foreground.lightred + "Status: \t"  +  mycolors.reverse + haustext.get('url_status') + mycolors.reset)
                if(haustext.get('url_status') == ''):
                    print(mycolors.foreground.lightblue + "Status: \t"  +  mycolors.reverse + "unknown" + mycolors.reset)
            else:
                if(haustext.get('url_status') == 'online'):
                    print(mycolors.foreground.green + "Status: \t"  + mycolors.reverse + haustext.get('url_status') + mycolors.reset)
                if(haustext.get('url_status') == 'offline'):
                    print(mycolors.foreground.red + "Status: \t"  +  mycolors.reverse + haustext.get('url_status') + mycolors.reset)
                if(haustext.get('url_status') == ''):
                    print(mycolors.foreground.cyan + "Status: \t"  +  mycolors.reverse + "unknown" + mycolors.reset)
        else:
            if (bkg == 1):
                print(mycolors.foreground.lightred + 'Status: ')
            else:
                print(mycolors.foreground.red + 'Status: ')

        if 'host' in haustext:
            if haustext.get('host') is not None:
                if (bkg == 1):
                    print(mycolors.foreground.yellow + "Host: \t\t"  +  haustext.get('host'))
                else:
                    print(mycolors.foreground.blue + "Host: \t\t"  +  haustext.get('host'))
            else:
                if (bkg == 1):
                    print(mycolors.foreground.yellow + 'Host: ')
                else:
                    print(mycolors.foreground.blue + 'Host: ')

        if 'date_added' in haustext:
            if haustext.get('date_added') is not None:
                if (bkg == 1):
                    print(mycolors.foreground.pink + "Date Added: \t"  +  haustext.get('date_added'))
                else:
                    print(mycolors.foreground.green + "Date Added: \t"  +  haustext.get('date_added'))
            else:
                if (bkg == 1):
                    print(mycolors.foreground.pink + 'Date Added: ')
                else:
                    print(mycolors.foreground.green + 'Date Added: ')

        if 'threat' in haustext:
            if haustext.get('threat') is not None:
                if (bkg == 1):
                    print(mycolors.foreground.pink + "Threat: \t"  +  haustext.get('threat'))
                else:
                    print(mycolors.foreground.green + "Threat: \t"  +  haustext.get('threat'))
            else:
                if (bkg == 1):
                    print(mycolors.foreground.pink + 'Threat: ')
                else:
                    print(mycolors.foreground.green + 'Threat: ')

        if 'blacklists' in haustext:
            blacks = haustext.get('blacklists')
            if(bkg == 1):
                if 'gsb' in (blacks):
                    print(mycolors.foreground.lightred + "Google(gsb): \t" + blacks['gsb'])
                if 'surbl' in (blacks):
                    print(mycolors.foreground.lightred + "Surbl: \t\t" + blacks['surbl'])
                if 'spamhaus_dbl' in (blacks):
                    print(mycolors.foreground.lightred + "Spamhaus DBL:   " + blacks['spamhaus_dbl'])
            else:
                if 'gsb' in (blacks):
                    print(mycolors.foreground.red + "Google(gsb): \t" + blacks['gsb'])
                if 'surbl' in (blacks):
                    print(mycolors.foreground.red + "Surbl: \t\t" + blacks['surbl'])
                if 'spamhaus_dbl' in (blacks):
                    print(mycolors.foreground.red + "Spamhaus DBL:   " + blacks['spamhaus_dbl'])
        else:
            if(bkg == 1):
                print(mycolors.foreground.lightred + "Google(gsb): \t")
                print(mycolors.foreground.lightred + "Surbl: \t\t")
                print(mycolors.foreground.lightred + "Spamhaus DBL:   ")
            else:
                print(mycolors.foreground.red + "Google(gsb): \t")
                print(mycolors.foreground.red + "Surbl: \t\t")
                print(mycolors.foreground.red + "Spamhaus DBL:   ")

        if 'reporter' in haustext:
            if haustext.get('reporter') is not None:
                if (bkg == 1):
                    print(mycolors.foreground.lightblue + "Reporter: \t"  +  haustext.get('reporter'))
                else:
                    print(mycolors.foreground.blue + "Reporter: \t"  +  haustext.get('reporter'))
            else:
                if (bkg == 1):
                    print(mycolors.foreground.lightblue + 'Reporter: ')
                else:
                    print(mycolors.foreground.blue + 'Reporter: ')

        if 'larted' in haustext:
            if haustext.get('larted') is not None:
                if (bkg == 1):
                    print(mycolors.foreground.lightblue + "Larted: \t" + haustext.get('larted'))
                else:
                    print(mycolors.foreground.blue + "Larted: \t" + haustext.get('larted'))

            else:
                if (bkg == 1):
                    print(mycolors.foreground.lightblue + "Larted: ")
                else:
                    print(mycolors.foreground.blue + "Larted: ")

        if 'tags' in haustext:
            if (haustext.get('tags') is not None):
                alltags = haustext.get('tags')
                if (bkg == 1):
                    print(mycolors.foreground.yellow + "Tags:\t\t", end='')
                else:
                    print(mycolors.foreground.red + "Tags:\t\t", end='')
                for i in alltags:
                    print(i, end=' ')
            else:
                if (bkg == 1):
                    print(mycolors.foreground.yellow + "Tags: ")
                else:
                    print(mycolors.foreground.red + "Tags: ")
        else:
            if (bkg == 1):
                print(mycolors.foreground.yellow + "Tags: ")
            else:
                print(mycolors.foreground.red + "Tags: ")

        if 'payloads' in haustext:
            if haustext.get('payloads') is not None:
                allpayloads = haustext.get('payloads')
                x = 0
                z = 0
                results = {}

                if (bkg == 1):
                    print(Fore.WHITE + "\n")
                else:
                    print(Fore.BLACK + "\n")

                for i in allpayloads:
                    x = x + 1
                    if (bkg == 1):
                        print(mycolors.reset + "Payload_%d:\t" % x, end='')
                        print(mycolors.foreground.pink + "firstseen:%12s" % i['firstseen'], end = '     ' )
                        print(mycolors.foreground.yellow + "filename: %-30s" % i['filename'], end = ' ' + "\t")
                        print(mycolors.foreground.lightred + "filetype: %s" % i['file_type'] + Fore.WHITE, end= ' ' + "\t")
                        results = i['virustotal']
                        if (results) is not None:
                            print(mycolors.foreground.lightgreen + "VirusTotal: %s" % results['result'] + Fore.WHITE)
                        else:
                            print(mycolors.foreground.lightgreen + "VirusTotal: Not Found" + Fore.WHITE)
                    else:
                        print(mycolors.reset + "Payload_%d:\t" % x, end='')
                        print(mycolors.foreground.purple + "firstseen:%12s" % i['firstseen'], end = '     ')
                        print(mycolors.foreground.green + "filename: %-30s" % i['filename'], end = ' ' + "\t")
                        print(mycolors.foreground.red + "filetype: %s" % i['file_type'] + Fore.BLACK, end = '' + "\t")
                        results = i['virustotal']
                        if (results) is not None:
                            print(mycolors.foreground.blue + "VirusTotal: %s" % results['result'] + Fore.BLACK)
                        else:
                            print(mycolors.foreground.blue + "VirusTotal: Not Found" + Fore.BLACK)

                print(mycolors.reset + "\nSample Hashes")
                print(13 * '-' + "\n")

                for j in allpayloads:
                    z = z + 1
                    if (bkg == 1):
                        print(mycolors.reset + "Payload_%d:\t" % z, end='')
                        print(mycolors.foreground.lightgreen + j['response_sha256'])
                    else:
                        print(mycolors.reset + "Payload_%d:\t" % z, end='')
                        print(mycolors.foreground.blue + j['response_sha256'])

        print(mycolors.reset)

    except (BrokenPipeError, IOError, TypeError):
        print(mycolors.reset , file=sys.stderr)
        exit(1)

    except ValueError as e:
        print(e)
        if (bkg == 1):
            print((mycolors.foreground.lightred + "Error while connecting to URLhaus!\n"))
        else:
            print((mycolors.foreground.red + "Error while connecting to URLhaus!\n"))
        print(mycolors.reset)


def haushashsearch(hashx, haus):

    haustext = ''
    hausresponse = ''
    finalurl9 = ''
    params = ''

    try:
        
        print("\n")
        print((mycolors.reset + "URLHaus Report".center(126)), end='')
        print((mycolors.reset + "".center(28)), end='')
        print("\n" + (126*'-').center(59))

        requestsession = requests.Session( )
        requestsession.headers.update({'accept': 'application/json'})
        if ((len(hashx)==32)):
            params = {"md5_hash": hashx}
        hausresponse = requestsession.post(haus, data=params)
        haustext = json.loads(hausresponse.text)

        if ((len(hashx)==64)):
            params = {"sha256_hash": hashx}
        hausresponse = requests.post(haus, data=params)
        haustext = json.loads(hausresponse.text)

        if ((haustext.get('md5_hash') is None) and (haustext.get('sha256_hash') is None)):
            if (bkg == 1):
                print(mycolors.foreground.lightred + "Hash not found!\n" + mycolors.reset)
            else:
                print(mycolors.foreground.red + "Hash not found!\n" + mycolors.reset)
            exit(1)

        if 'query_status' in haustext:
            if (bkg == 1):
                print(mycolors.foreground.lightgreen + "Is available?: \t"  +  haustext.get('query_status').upper())
            else:
                print(mycolors.foreground.green + "Is available?: \t"  +  haustext.get('query_status').upper())
        else:
            if (bkg == 1):
                print(mycolors.foreground.lightgreen + 'Is availble?: Not available')
            else:
                print(mycolors.foreground.green + 'Is available?: Not available')

        if 'md5_hash' in haustext:
            if haustext.get('md5_hash') is not None:
                if (bkg == 1):
                    print(mycolors.foreground.yellow + "MD5: \t\t"  +  haustext.get('md5_hash'))
                else:
                    print(mycolors.foreground.blue + "MD5: \t\t"  +  haustext.get('md5_hash'))
            else:
                if (bkg == 1):
                    print(mycolors.foreground.yellow + 'MD5: ')
                else:
                    print(mycolors.foreground.blue + 'MD5: ')

        if 'sha256_hash' in haustext:
            if haustext.get('md5_hash') is not None:
                if (bkg == 1):
                    print(mycolors.foreground.yellow + "SHA256:\t\t"  +  haustext.get('sha256_hash'))
                else:
                    print(mycolors.foreground.blue + "SHA256:\t\t"  +  haustext.get('sha256_hash'))
            else:
                if (bkg == 1):
                    print(mycolors.foreground.yellow + 'SHA256: ')
                else:
                    print(mycolors.foreground.blue + 'SHA256: ')

        if 'file_type' in haustext:
            if haustext.get('file_type') is not None:
                if (bkg == 1):
                    print(mycolors.foreground.pink + "File Type: \t"  +  haustext.get('file_type'))
                else:
                    print(mycolors.foreground.purple + "File Type: \t"  +  haustext.get('file_type'))
            else:
                if (bkg == 1):
                    print(mycolors.foreground.pink + 'File Type: ')
                else:
                    print(mycolors.foreground.purple + 'File Type: ')

        if 'file_size' in haustext:
            if haustext.get('file_size') is not None:
                if (bkg == 1):
                    print(mycolors.foreground.pink + "File Size: \t"  +  haustext.get('file_size') + " bytes")
                else:
                    print(mycolors.foreground.purple + "File Size: \t"  +  haustext.get('file_size') + " bytes")
            else:
                if (bkg == 1):
                    print(mycolors.foreground.pink + 'File Size: ')
                else:
                    print(mycolors.foreground.purple + 'File Size: ')

        if 'firstseen' in haustext:
            if haustext.get('firstseen') is not None:
                if (bkg == 1):
                    print(mycolors.foreground.lightcyan + "First Seen: \t"  +  haustext.get('firstseen'))
                else:
                    print(mycolors.foreground.cyan + "First Seen: \t"  +  haustext.get('firstseen'))
            else:
                if (bkg == 1):
                    print(mycolors.foreground.lightcyan + 'First Seen: ')
                else:
                    print(mycolors.foreground.cyan + 'First Seen: ')

        if 'lastseen' in haustext:
            if haustext.get('lastseen') is not None:
                if (bkg == 1):
                    print(mycolors.foreground.lightcyan + "Last Seen: \t"  +  haustext.get('lastseen'))
                else:
                    print(mycolors.foreground.cyan + "Last Seen: \t"  +  haustext.get('lastseen'))
            else:
                if (bkg == 1):
                    print(mycolors.foreground.lightcyan + 'Last Seen: ')
                else:
                    print(mycolors.foreground.cyan + 'Last Seen: ')

        if 'urlhaus_download' in haustext:
            if haustext.get('urlhaus_download') is not None:
                if (bkg == 1):
                    print(mycolors.foreground.lightred + "URL Download: \t"  +  haustext.get('urlhaus_download'))
                else:
                    print(mycolors.foreground.red + "URL Download: \t"  +  haustext.get('urlhaus_download'))
            else:
                if (bkg == 1):
                    print(mycolors.foreground.lightred + 'URL Download: ')
                else:
                    print(mycolors.foreground.red + 'URL Download: ')

        if 'virustotal' in haustext:
            if haustext.get('virustotal') is not None:
                if (bkg == 1):
                    print(mycolors.foreground.lightred + "Virus Total: \t"  +  haustext['virustotal'].get('result'))
                else:
                    print(mycolors.foreground.red + "Virus Total: \t"  +  haustext['virustotal'].get('result'))
            else:
                if (bkg == 1):
                    print(mycolors.foreground.lightred + 'Virus Total: \tNot Found')
                else:
                    print(mycolors.foreground.red + 'Virus Total: \tNot Found')

        if 'urls' in haustext:
            if (haustext.get('urls')) is not None:
                if (bkg == 1):
                    print(mycolors.reset + "\nStatus".center(9) + " Filename".ljust(36) + "  Location".ljust(23) + "Associated URL".ljust(20))
                    print("-" * 126 + "\n")
                else:
                    print(mycolors.reset + "\nStatus".center(9) + " Filename".ljust(36) + "  Location".ljust(23) + "Associated URL".ljust(20))
                    print("-" * 126 + "\n")
                allurls = haustext.get('urls')
                for w in allurls:
                    if (bkg == 1):
                        if(w['url_status'] == 'online'):
                            print(mycolors.foreground.lightgreen + mycolors.reverse + w['url_status'] + " " + mycolors.reset, end=' ')
                        if(w['url_status'] == 'offline'):
                            print(mycolors.foreground.lightred + mycolors.reverse + w['url_status'] + mycolors.reset, end=' ')
                        if(w['url_status'] == ''):
                            print(mycolors.foreground.lightblue + mycolors.reverse + "unknown" + mycolors.reset, end=' ')
                        if w['filename'] is not None:
                            print(mycolors.foreground.pink + "%-36s" % w['filename'] + mycolors.reset, end=' ')
                        else:
                            print(mycolors.foreground.pink + "%-36s" % "Filename not reported!" + mycolors.reset, end=' ')
                        if (w['url'] is not None):
                            if(validators.url(w['url'])):
                                print(mycolors.foreground.lightgreen + urltoip((w['url'])).ljust(20) + mycolors.reset, end=' ')
                            else:
                                print(mycolors.foreground.lightgreen + "Not located".center(20) + mycolors.reset, end=' ')
                            print(mycolors.foreground.yellow + w['url'] + mycolors.reset)
                        else:
                            print(mycolors.foreground.lightgreen + "Not located".center(20) + mycolors.reset, end=' ')
                            print(mycolors.foreground.lightgreen + "URL not provided".center(20) + mycolors.reset, end=' ')

                    else:
                        if(w['url_status'] == 'online'):
                            print(mycolors.foreground.green + mycolors.reverse + w['url_status'] + " " + mycolors.reset, end=' ')
                        if(w['url_status'] == 'offline'):
                            print(mycolors.foreground.red + mycolors.reverse + w['url_status'] + mycolors.reset, end=' ')
                        if(w['url_status'] == ''):
                            print(mycolors.foreground.cyan +  mycolors.reverse + "unknown" + mycolors.reset, end=' ')
                        if w['filename'] is not None:
                            print(mycolors.foreground.pink + "%-36s" % w['filename'] + mycolors.reset, end=' ')
                        else:
                            print(mycolors.foreground.pink + "%-36s" %  "Filename not reported!" + mycolors.reset, end=' ')
                        if (w['url']):
                            if(validators.url(w['url'])):
                                print(mycolors.foreground.green + (urltoip(w['url'])).ljust(20) + mycolors.reset, end=' ')
                            else:
                                print(mycolors.foreground.green + "Not located".center(20) + mycolors.reset, end=' ')
                            print(mycolors.foreground.blue + w['url'] + mycolors.reset)
                        else:
                            print(mycolors.foreground.lightgreen + "Not located".center(20) + mycolors.reset, end=' ')
                            print(mycolors.foreground.lightgreen + "URL not provided".center(20) + mycolors.reset, end=' ')

        print(mycolors.reset)

    except (BrokenPipeError, IOError, TypeError):
        print(mycolors.reset , file=sys.stderr)
        exit(1)

    except ValueError as e:
        print(e)
        if (bkg == 1):
            print((mycolors.foreground.lightred + "Error while connecting to URLhaus!\n"))
        else:
            print((mycolors.foreground.lightred + "Error while connecting to URLhaus!\n"))
        print(mycolors.reset)


def bazaar_hash(bazaarx, bazaar):

    bazaartext = ''
    bazaarresponse = ''
    params = ''

    try:
        
        print("\n")
        print((mycolors.reset + "MALWARE BAZAAR REPORT".center(100)), end='')
        print((mycolors.reset + "".center(28)), end='')
        print("\n" + (100*'-').center(50))

        requestsession = requests.Session( )
        requestsession.headers.update({'accept': 'application/json'})
        params = {'query':'get_info',"hash": bazaarx}
        bazaarresponse = requestsession.post(bazaar, data=params)
        bazaartext = json.loads(bazaarresponse.text)

        if bazaartext['query_status'] == "hash_not_found":
            if (bkg == 1):
                print(mycolors.foreground.lightred + "\nThe provided hash was not found!\n" + mycolors.reset)
            else:
                print(mycolors.foreground.red + "\nThe provided hash was not found!\n" + mycolors.reset)
            exit(1)

        if bazaartext['query_status'] == "illegal_hash":
            if (bkg == 1):
                print(mycolors.foreground.lightred + "\nThe provided hash is not valid!\n" + mycolors.reset)
            else:
                print(mycolors.foreground.red + "\nThe provided hash is not valid!\n" + mycolors.reset)
            exit(1)

        if (bkg == 1):
            for i in bazaartext.keys():
                if (i == "data"):
                    if (bazaartext['data'] is not None):
                        for d in bazaartext['data']:
                            y = d.keys()    
                            if ("sha256_hash" in y):
                                if d['sha256_hash']:
                                    print(mycolors.foreground.lightgreen + "\nsha256_hash: ".ljust(15) + mycolors.reset + d['sha256_hash'],end=' ')

                            if ("sha1_hash" in y):
                                if d['sha1_hash']:
                                    print(mycolors.foreground.lightgreen + "\nsha1_hash: ".ljust(15) + mycolors.reset + d['sha1_hash'], end=' ')

                            if ("md5_hash" in y):
                                if d['md5_hash']:
                                    print(mycolors.foreground.lightgreen + "\nmd5_hash: ".ljust(15) + mycolors.reset + d['md5_hash'], end=' ')

                            if ("first_seen" in y):
                                if d['first_seen']:
                                    print(mycolors.foreground.lightgreen + "\nfirst_seen: ".ljust(15) + mycolors.reset + d['first_seen'], end=' ')

                            if ("last_seen" in y):
                                if d['last_seen']:
                                    print(mycolors.foreground.lightgreen + "\nlast_seen: ".ljust(15) + mycolors.reset + d['last_seen'], end=' ')

                            if ("file_name" in y):
                                if d['file_name']:
                                    print(mycolors.foreground.lightgreen + "\nfile_name: ".ljust(15) + mycolors.reset + d['file_name'], end=' ')

                            if ("file_size" in y):
                                if d['file_size']:
                                    print(mycolors.foreground.lightgreen + "\nfile_size: ".ljust(15) + mycolors.reset + str(d['file_size']) + " bytes", end=' ')

                            if ("file_type" in y):
                                if d['file_type']:
                                    print(mycolors.foreground.lightgreen + "\nfile_type: ".ljust(15) + mycolors.reset + str(d['file_type']), end=' ')

                            if ("file_type_mime" in y):
                                if d['file_type_mime']:
                                    print(mycolors.foreground.lightgreen + "\nmime_type: ".ljust(15) + mycolors.reset + str(d['file_type_mime']), end=' ')
                            if ("origin_country" in y):
                                if d['origin_country']:
                                    print(mycolors.foreground.lightgreen + "\ncountry: ".ljust(15) + mycolors.reset + d['origin_country'], end=' ')

                            if ("imphash" in y):
                                if d['imphash']:
                                    print(mycolors.foreground.lightgreen + "\nimphash: ".ljust(15) + mycolors.reset + d['imphash'], end=' ')

                            if ("tlsh" in y):
                                if d['tlsh']:
                                    print(mycolors.foreground.lightgreen + "\ntlsh: ".ljust(15) + mycolors.reset + d['tlsh'], end=' ')

                            if ("comment" in y):
                                if d['comment']:
                                    print(mycolors.foreground.lightgreen + "\ncomments: ".ljust(15) + mycolors.reset, end='')
                                    s = d['comment'].split('\n')
                                    for n in range(len(s)):
                                        print("\n".ljust(15) + s[n], end=' ')

                            if ("reporter" in y):
                                if d['reporter']:
                                    print(mycolors.foreground.lightgreen + "\nreporter: ".ljust(15) + mycolors.reset + d['reporter'], end=' ')

                            if ("oleinformation" in y):
                                print(mycolors.foreground.lightgreen + "\noleinformation: ".ljust(15),end='') 
                                for t in d['oleinformation']:
                                    print(mycolors.reset + t, end=' ')

                            if ("delivery_method" in y):
                                if d['delivery_method']:
                                    print(mycolors.foreground.lightgreen + "\ndelivery: ".ljust(15) + mycolors.reset + d['delivery_method'], end=' ')

                            if ("tags" in y):
                                if d['tags']:
                                    print(mycolors.foreground.lightgreen + "\ntags: ".ljust(15),end='') 
                                    for t in d['tags']:
                                        print(mycolors.reset + t, end=' ')

                            if ("file_information" in y):
                                if (d['file_information'] is not None):
                                    for x in d['file_information']:
                                        if ("context" in x):
                                            if (x['context'] == "twitter"):
                                                print(mycolors.foreground.orange + "\nTwitter: ".ljust(15) + mycolors.reset + x['value'], end=' ')
                                            if (x['context'] == "cape"):
                                                print(mycolors.foreground.orange + "\nCape: ".ljust(15) + mycolors.reset + x['value'], end=' ')

                            if ("vendor_intel" in y):
                                if (d['vendor_intel'] is not None):
                                    if ("UnpacMe" in d['vendor_intel']):
                                        if (d['vendor_intel']['UnpacMe']):
                                            print(mycolors.foreground.orange + "\nUnpacMe: ".ljust(15) + mycolors.reset, end=' ')
                                            filtered_list = []
                                            for j in d['vendor_intel']['UnpacMe']:
                                                    if ("link" in j):
                                                        if j['link'] not in filtered_list:
                                                            filtered_list.append(j['link'])
                                                            for h in filtered_list:
                                                                print('\n'.ljust(15) + h, end=' ')

                                    if ("ANY.RUN" in d['vendor_intel']):
                                        print(mycolors.foreground.orange + "\nAny.Run: ".ljust(15) + mycolors.reset, end=' ')
                                        for j in d['vendor_intel']['ANY.RUN']:
                                            if ("analysis_url" in j):
                                                print("\n".ljust(15) + j['analysis_url'], end=' ')

                                    if ("Triage" in d['vendor_intel']):
                                        for j in d['vendor_intel']['Triage']:
                                            if ("link" in j):
                                                print(mycolors.foreground.orange + "\n\nTriage: ".ljust(16) + mycolors.reset + d['vendor_intel']['Triage']['link'], end=' ')

                                        if (d['vendor_intel']['Triage']['signatures']):
                                            print(mycolors.foreground.orange + "\nTriage sigs: ".ljust(15) + mycolors.reset,end='\n')
                                            for m in d['vendor_intel']['Triage']['signatures']:
                                                if ("signature" in m):
                                                    print(mycolors.reset + "".ljust(14) + m['signature'])

                                    if ("vxCube" in d['vendor_intel']):
                                        for j in d['vendor_intel']['vxCube']:
                                            if ("behaviour" in j):
                                                print(mycolors.foreground.orange + "\nDr.Web rules: ".ljust(15) + mycolors.reset)
                                                for m in d['vendor_intel']['vxCube']['behaviour']:
                                                    if ("rule" in m):
                                                        print(mycolors.reset + "".ljust(14) + m['rule'])

        if (bkg == 0):
            for i in bazaartext.keys():
                if (i == "data"):
                    if (bazaartext['data'] is not None):
                        for d in bazaartext['data']:
                            y = d.keys()    
                            if ("sha256_hash" in y):
                                if d['sha256_hash']:
                                    print(mycolors.foreground.green + "\nsha256_hash: ".ljust(15) + mycolors.reset + d['sha256_hash'],end=' ')

                            if ("sha1_hash" in y):
                                if d['sha1_hash']:
                                    print(mycolors.foreground.green + "\nsha1_hash: ".ljust(15) + mycolors.reset + d['sha1_hash'], end=' ')

                            if ("md5_hash" in y):
                                if d['md5_hash']:
                                    print(mycolors.foreground.green + "\nmd5_hash: ".ljust(15) + mycolors.reset + d['md5_hash'], end=' ')

                            if ("first_seen" in y):
                                if d['first_seen']:
                                    print(mycolors.foreground.green + "\nfirst_seen: ".ljust(15) + mycolors.reset + d['first_seen'], end=' ')

                            if ("last_seen" in y):
                                if d['last_seen']:
                                    print(mycolors.foreground.green + "\nlast_seen: ".ljust(15) + mycolors.reset + d['last_seen'], end=' ')

                            if ("file_name" in y):
                                if d['file_name']:
                                    print(mycolors.foreground.green + "\nfile_name: ".ljust(15) + mycolors.reset + d['file_name'], end=' ')

                            if ("file_size" in y):
                                if d['file_size']:
                                    print(mycolors.foreground.green + "\nfile_size: ".ljust(15) + mycolors.reset + str(d['file_size']) + " bytes", end=' ')

                            if ("file_type" in y):
                                if d['file_type']:
                                    print(mycolors.foreground.green + "\nfile_type: ".ljust(15) + mycolors.reset + str(d['file_type']), end=' ')

                            if ("file_type_mime" in y):
                                if d['file_type_mime']:
                                    print(mycolors.foreground.green + "\nmime_type: ".ljust(15) + mycolors.reset + str(d['file_type_mime']), end=' ')
                            if ("origin_country" in y):
                                if d['origin_country']:
                                    print(mycolors.foreground.green + "\ncountry: ".ljust(15) + mycolors.reset + d['origin_country'], end=' ')

                            if ("imphash" in y):
                                if d['imphash']:
                                    print(mycolors.foreground.green + "\nimphash: ".ljust(15) + mycolors.reset + d['imphash'], end=' ')

                            if ("tlsh" in y):
                                if d['tlsh']:
                                    print(mycolors.foreground.green + "\ntlsh: ".ljust(15) + mycolors.reset + d['tlsh'], end=' ')

                            if ("comment" in y):
                                if d['comment']:
                                    print(mycolors.foreground.green + "\ncomments: ".ljust(15) + mycolors.reset, end='')
                                    s = d['comment'].split('\n')
                                    for n in range(len(s)):
                                        print("\n".ljust(15) + s[n], end=' ')

                            if ("reporter" in y):
                                if d['reporter']:
                                    print(mycolors.foreground.green + "\nreporter: ".ljust(15) + mycolors.reset + d['reporter'], end=' ')

                            if ("oleinformation" in y):
                                print(mycolors.foreground.green + "\noleinformation: ".ljust(15),end='') 
                                for t in d['oleinformation']:
                                    print(mycolors.reset + t, end=' ')

                            if ("delivery_method" in y):
                                if d['delivery_method']:
                                    print(mycolors.foreground.green + "\ndelivery: ".ljust(15) + mycolors.reset + d['delivery_method'], end=' ')

                            if ("tags" in y):
                                if d['tags']:
                                    print(mycolors.foreground.green + "\ntags: ".ljust(15),end='') 
                                    for t in d['tags']:
                                        print(mycolors.reset + t, end=' ')

                            if ("file_information" in y):
                                if (d['file_information'] is not None):
                                    for x in d['file_information']:
                                        if ("context" in x):
                                            if (x['context'] == "twitter"):
                                                print(mycolors.foreground.red + "\nTwitter: ".ljust(15) + mycolors.reset + x['value'], end=' ')
                                            if (x['context'] == "cape"):
                                                print(mycolors.foreground.red + "\nCape: ".ljust(15) + mycolors.reset + x['value'], end=' ')

                            if ("vendor_intel" in y):
                                if (d['vendor_intel'] is not None):
                                    if ("UnpacMe" in d['vendor_intel']):
                                        if (d['vendor_intel']['UnpacMe']):
                                            print(mycolors.foreground.red + "\nUnpacMe: ".ljust(15) + mycolors.reset, end=' ')
                                            filtered_list = []
                                            for j in d['vendor_intel']['UnpacMe']:
                                                    if ("link" in j):
                                                        if j['link'] not in filtered_list:
                                                            filtered_list.append(j['link'])
                                                            for h in filtered_list:
                                                                print('\n'.ljust(15) + h, end=' ')

                                    if ("ANY.RUN" in d['vendor_intel']):
                                        print(mycolors.foreground.red + "\nAny.Run: ".ljust(15) + mycolors.reset, end=' ')
                                        for j in d['vendor_intel']['ANY.RUN']:
                                            if ("analysis_url" in j):
                                                print("\n".ljust(15) + j['analysis_url'], end=' ')

                                    if ("Triage" in d['vendor_intel']):
                                        for j in d['vendor_intel']['Triage']:
                                            if ("link" in j):
                                                print(mycolors.foreground.red + "\n\nTriage: ".ljust(16) + mycolors.reset + d['vendor_intel']['Triage']['link'], end=' ')

                                        if (d['vendor_intel']['Triage']['signatures']):
                                            print(mycolors.foreground.red + "\nTriage sigs: ".ljust(15) + mycolors.reset,end='\n')
                                            for m in d['vendor_intel']['Triage']['signatures']:
                                                if ("signature" in m):
                                                    print(mycolors.reset + "".ljust(14) + m['signature'])

                                    if ("vxCube" in d['vendor_intel']):
                                        for j in d['vendor_intel']['vxCube']:
                                            if ("behaviour" in j):
                                                print(mycolors.foreground.red + "\nDr.Web rules: ".ljust(15) + mycolors.reset)
                                                for m in d['vendor_intel']['vxCube']['behaviour']:
                                                    if ("rule" in m):
                                                        print(mycolors.reset + "".ljust(14) + m['rule'])


        print(mycolors.reset)
        exit(0)
    
    except ValueError as e:
        print(e)
        if (bkg == 1):
            print((mycolors.foreground.lightred + "\nError while connecting to Malware Bazaar!\n"))
        else:
            print((mycolors.foreground.lightred + "\nError while connecting to Malware Bazaar!\n"))
        print(mycolors.reset)


def bazaar_tag(bazaarx, bazaar):

    bazaartext = ''
    bazaarresponse = ''
    params = ''

    try:
        
        print("\n")
        print((mycolors.reset + "MALWARE BAZAAR REPORT".center(100)), end='')
        print((mycolors.reset + "".center(28)), end='')
        print("\n" + (100*'-').center(50))

        requestsession = requests.Session( )
        requestsession.headers.update({'accept': 'application/json'})
        params = {'query':'get_taginfo',"tag": bazaarx,"limit": 50}
        bazaarresponse = requestsession.post(bazaar, data=params)
        bazaartext = json.loads(bazaarresponse.text)

        if bazaartext['query_status'] == "tag_not_found":
            if (bkg == 1):
                print(mycolors.foreground.lightred + "\nThe provided tag was not found!\n" + mycolors.reset)
            else:
                print(mycolors.foreground.red + "\nThe provided tag was not found!\n" + mycolors.reset)
            exit(1)

        if bazaartext['query_status'] == "illegal_tag":
            if (bkg == 1):
                print(mycolors.foreground.lightred + "\nThe provided tag is not valid!\n" + mycolors.reset)
            else:
                print(mycolors.foreground.red + "\nThe provided tag is not valid!\n" + mycolors.reset)
            exit(1)

        if bazaartext['query_status'] == "no_results":
            if (bkg == 1):
                print(mycolors.foreground.lightred + "\nYour query yield no results!\n" + mycolors.reset)
            else:
                print(mycolors.foreground.red + "\nYour query yield no results!\n" + mycolors.reset)
            exit(1)

        if (bkg == 1):
            for i in bazaartext.keys():
                if (i == "data"):
                    if (bazaartext['data'] is not None):
                        for d in bazaartext['data']:
                            y = d.keys()    
                            print("\n" + (90*'-').center(45), end=' ')
                            if ("sha256_hash" in y):
                                if d['sha256_hash']:
                                    print(mycolors.foreground.lightcyan + "\nsha256_hash: ".ljust(15) + mycolors.reset + d['sha256_hash'],end=' ')

                            if ("sha1_hash" in y):
                                if d['sha1_hash']:
                                    print(mycolors.foreground.lightcyan + "\nsha1_hash: ".ljust(15) + mycolors.reset + d['sha1_hash'], end=' ')

                            if ("md5_hash" in y):
                                if d['md5_hash']:
                                    print(mycolors.foreground.lightcyan + "\nmd5_hash: ".ljust(15) + mycolors.reset + d['md5_hash'], end=' ')

                            if ("first_seen" in y):
                                if d['first_seen']:
                                    print(mycolors.foreground.lightcyan + "\nfirst_seen: ".ljust(15) + mycolors.reset + d['first_seen'], end=' ')

                            if ("last_seen" in y):
                                if d['last_seen']:
                                    print(mycolors.foreground.lightcyan + "\nlast_seen: ".ljust(15) + mycolors.reset + d['last_seen'], end=' ')

                            if ("file_name" in y):
                                if d['file_name']:
                                    print(mycolors.foreground.lightcyan + "\nfile_name: ".ljust(15) + mycolors.reset + d['file_name'], end=' ')

                            if ("file_size" in y):
                                if d['file_size']:
                                    print(mycolors.foreground.lightcyan + "\nfile_size: ".ljust(15) + mycolors.reset + str(d['file_size']) + " bytes", end=' ')

                            if ("file_type" in y):
                                if d['file_type']:
                                    print(mycolors.foreground.lightcyan + "\nfile_type: ".ljust(15) + mycolors.reset + str(d['file_type']), end=' ')

                            if ("file_type_mime" in y):
                                if d['file_type_mime']:
                                    print(mycolors.foreground.lightcyan + "\nmime_type: ".ljust(15) + mycolors.reset + str(d['file_type_mime']), end=' ')
                            if ("origin_country" in y):
                                if d['origin_country']:
                                    print(mycolors.foreground.lightcyan + "\ncountry: ".ljust(15) + mycolors.reset + d['origin_country'], end=' ')

                            if ("imphash" in y):
                                if d['imphash']:
                                    print(mycolors.foreground.lightcyan + "\nimphash: ".ljust(15) + mycolors.reset + d['imphash'], end=' ')

                            if ("tlsh" in y):
                                if d['tlsh']:
                                    print(mycolors.foreground.lightcyan + "\ntlsh: ".ljust(15) + mycolors.reset + d['tlsh'], end=' ')

                            if ("reporter" in y):
                                if d['reporter']:
                                    print(mycolors.foreground.lightcyan + "\nreporter: ".ljust(15) + mycolors.reset + d['reporter'], end=' ')

                            if ("signature" in y):
                                if d['signature']:
                                    print(mycolors.foreground.lightcyan + "\nsignature: ".ljust(15) + mycolors.reset + d['signature'], end=' ')

                            if ("tags" in y):
                                if d['tags']:
                                    print(mycolors.foreground.lightcyan + "\ntags: ".ljust(15),end='') 
                                    for t in d['tags']:
                                        print(mycolors.reset + t, end=' ')

        if (bkg == 0):
            for i in bazaartext.keys():
                if (i == "data"):
                    if (bazaartext['data'] is not None):
                        for d in bazaartext['data']:
                            y = d.keys()    
                            print("\n" + (90*'-').center(45), end=' ')
                            if ("sha256_hash" in y):
                                if d['sha256_hash']:
                                    print(mycolors.foreground.blue + "\nsha256_hash: ".ljust(15) + mycolors.reset + d['sha256_hash'],end=' ')

                            if ("sha1_hash" in y):
                                if d['sha1_hash']:
                                    print(mycolors.foreground.blue + "\nsha1_hash: ".ljust(15) + mycolors.reset + d['sha1_hash'], end=' ')

                            if ("md5_hash" in y):
                                if d['md5_hash']:
                                    print(mycolors.foreground.blue + "\nmd5_hash: ".ljust(15) + mycolors.reset + d['md5_hash'], end=' ')

                            if ("first_seen" in y):
                                if d['first_seen']:
                                    print(mycolors.foreground.blue + "\nfirst_seen: ".ljust(15) + mycolors.reset + d['first_seen'], end=' ')

                            if ("last_seen" in y):
                                if d['last_seen']:
                                    print(mycolors.foreground.blue + "\nlast_seen: ".ljust(15) + mycolors.reset + d['last_seen'], end=' ')

                            if ("file_name" in y):
                                if d['file_name']:
                                    print(mycolors.foreground.blue + "\nfile_name: ".ljust(15) + mycolors.reset + d['file_name'], end=' ')

                            if ("file_size" in y):
                                if d['file_size']:
                                    print(mycolors.foreground.blue + "\nfile_size: ".ljust(15) + mycolors.reset + str(d['file_size']) + " bytes", end=' ')

                            if ("file_type" in y):
                                if d['file_type']:
                                    print(mycolors.foreground.blue + "\nfile_type: ".ljust(15) + mycolors.reset + str(d['file_type']), end=' ')

                            if ("file_type_mime" in y):
                                if d['file_type_mime']:
                                    print(mycolors.foreground.blue + "\nmime_type: ".ljust(15) + mycolors.reset + str(d['file_type_mime']), end=' ')
                            if ("origin_country" in y):
                                if d['origin_country']:
                                    print(mycolors.foreground.blue + "\ncountry: ".ljust(15) + mycolors.reset + d['origin_country'], end=' ')

                            if ("imphash" in y):
                                if d['imphash']:
                                    print(mycolors.foreground.blue + "\nimphash: ".ljust(15) + mycolors.reset + d['imphash'], end=' ')

                            if ("tlsh" in y):
                                if d['tlsh']:
                                    print(mycolors.foreground.blue + "\ntlsh: ".ljust(15) + mycolors.reset + d['tlsh'], end=' ')

                            if ("reporter" in y):
                                if d['reporter']:
                                    print(mycolors.foreground.blue + "\nreporter: ".ljust(15) + mycolors.reset + d['reporter'], end=' ')

                            if ("signature" in y):
                                if d['signature']:
                                    print(mycolors.foreground.blue + "\nsignature: ".ljust(15) + mycolors.reset + d['signature'], end=' ')

                            if ("tags" in y):
                                if d['tags']:
                                    print(mycolors.foreground.blue + "\ntags: ".ljust(15),end='') 
                                    for t in d['tags']:
                                        print(mycolors.reset + t, end=' ')

        print(mycolors.reset)
        exit(0)
    
    except ValueError as e:
        print(e)
        if (bkg == 1):
            print((mycolors.foreground.lightred + "\nError while connecting to Malware Bazaar!\n"))
        else:
            print((mycolors.foreground.lightred + "\nError while connecting to Malware Bazaar!\n"))
        print(mycolors.reset)


def bazaar_imphash(bazaarx, bazaar):

    bazaartext = ''
    params = ''

    try:
        
        print("\n")
        print((mycolors.reset + "MALWARE BAZAAR REPORT".center(100)), end='')
        print((mycolors.reset + "".center(28)), end='')
        print("\n" + (100*'-').center(50))

        requestsession = requests.Session( )
        requestsession.headers.update({'accept': 'application/json'})
        params = {'query':'get_imphash',"imphash": bazaarx,"limit": 50}
        bazaarresponse = requestsession.post(bazaar, data=params)
        bazaartext = json.loads(bazaarresponse.text)
        
        if bazaartext['query_status'] == "imphash_not_found":
            if (bkg == 1):
                print(mycolors.foreground.lightred + "\nThe provided imphash was not found!\n" + mycolors.reset)
            else:
                print(mycolors.foreground.red + "\nThe provided imphash was not found!\n" + mycolors.reset)
            exit(1)

        if bazaartext['query_status'] == "illegal_imphash":
            if (bkg == 1):
                print(mycolors.foreground.lightred + "\nThe provided imphash is not valid!\n" + mycolors.reset)
            else:
                print(mycolors.foreground.red + "\nThe provided imphash is not valid!\n" + mycolors.reset)
            exit(1)

        if bazaartext['query_status'] == "no_results":
            if (bkg == 1):
                print(mycolors.foreground.lightred + "\nYour query yield no results!\n" + mycolors.reset)
            else:
                print(mycolors.foreground.red + "\nYour query yield no results!\n" + mycolors.reset)
            exit(1)


        if (bkg == 1):
            for i in bazaartext.keys():
                if (i == "data"):
                    if (bazaartext['data'] is not None):
                        for d in bazaartext['data']:
                            y = d.keys()    
                            print("\n" + (90*'-').center(45), end=' ')
                            if ("sha256_hash" in y):
                                if d['sha256_hash']:
                                    print(mycolors.foreground.pink + "\nsha256_hash: ".ljust(15) + mycolors.reset + d['sha256_hash'],end=' ')

                            if ("sha1_hash" in y):
                                if d['sha1_hash']:
                                    print(mycolors.foreground.pink + "\nsha1_hash: ".ljust(15) + mycolors.reset + d['sha1_hash'], end=' ')

                            if ("md5_hash" in y):
                                if d['md5_hash']:
                                    print(mycolors.foreground.pink + "\nmd5_hash: ".ljust(15) + mycolors.reset + d['md5_hash'], end=' ')

                            if ("first_seen" in y):
                                if d['first_seen']:
                                    print(mycolors.foreground.pink + "\nfirst_seen: ".ljust(15) + mycolors.reset + d['first_seen'], end=' ')

                            if ("last_seen" in y):
                                if d['last_seen']:
                                    print(mycolors.foreground.pink + "\nlast_seen: ".ljust(15) + mycolors.reset + d['last_seen'], end=' ')

                            if ("file_name" in y):
                                if d['file_name']:
                                    print(mycolors.foreground.pink + "\nfile_name: ".ljust(15) + mycolors.reset + d['file_name'], end=' ')

                            if ("file_size" in y):
                                if d['file_size']:
                                    print(mycolors.foreground.pink + "\nfile_size: ".ljust(15) + mycolors.reset + str(d['file_size']) + " bytes", end=' ')

                            if ("file_type" in y):
                                if d['file_type']:
                                    print(mycolors.foreground.pink + "\nfile_type: ".ljust(15) + mycolors.reset + str(d['file_type']), end=' ')

                            if ("file_type_mime" in y):
                                if d['file_type_mime']:
                                    print(mycolors.foreground.pink + "\nmime_type: ".ljust(15) + mycolors.reset + str(d['file_type_mime']), end=' ')
                            if ("origin_country" in y):
                                if d['origin_country']:
                                    print(mycolors.foreground.pink + "\ncountry: ".ljust(15) + mycolors.reset + d['origin_country'], end=' ')

                            if ("imphash" in y):
                                if d['imphash']:
                                    print(mycolors.foreground.pink + "\nimphash: ".ljust(15) + mycolors.reset + d['imphash'], end=' ')

                            if ("tlsh" in y):
                                if d['tlsh']:
                                    print(mycolors.foreground.pink + "\ntlsh: ".ljust(15) + mycolors.reset + d['tlsh'], end=' ')

                            if ("reporter" in y):
                                if d['reporter']:
                                    print(mycolors.foreground.pink + "\nreporter: ".ljust(15) + mycolors.reset + d['reporter'], end=' ')

                            if ("signature" in y):
                                if d['signature']:
                                    print(mycolors.foreground.pink + "\nsignature: ".ljust(15) + mycolors.reset + d['signature'], end=' ')

                            if ("tags" in y):
                                if d['tags']:
                                    print(mycolors.foreground.pink + "\ntags: ".ljust(15),end='') 
                                    for t in d['tags']:
                                        print(mycolors.reset + t, end=' ')

        if (bkg == 0):
            for i in bazaartext.keys():
                if (i == "data"):
                    if (bazaartext['data'] is not None):
                        for d in bazaartext['data']:
                            y = d.keys()    
                            print("\n" + (90*'-').center(45), end=' ')
                            if ("sha256_hash" in y):
                                if d['sha256_hash']:
                                    print(mycolors.foreground.purple + "\nsha256_hash: ".ljust(15) + mycolors.reset + d['sha256_hash'],end=' ')

                            if ("sha1_hash" in y):
                                if d['sha1_hash']:
                                    print(mycolors.foreground.purple + "\nsha1_hash: ".ljust(15) + mycolors.reset + d['sha1_hash'], end=' ')

                            if ("md5_hash" in y):
                                if d['md5_hash']:
                                    print(mycolors.foreground.purple + "\nmd5_hash: ".ljust(15) + mycolors.reset + d['md5_hash'], end=' ')

                            if ("first_seen" in y):
                                if d['first_seen']:
                                    print(mycolors.foreground.purple + "\nfirst_seen: ".ljust(15) + mycolors.reset + d['first_seen'], end=' ')

                            if ("last_seen" in y):
                                if d['last_seen']:
                                    print(mycolors.foreground.purple + "\nlast_seen: ".ljust(15) + mycolors.reset + d['last_seen'], end=' ')

                            if ("file_name" in y):
                                if d['file_name']:
                                    print(mycolors.foreground.purple + "\nfile_name: ".ljust(15) + mycolors.reset + d['file_name'], end=' ')

                            if ("file_size" in y):
                                if d['file_size']:
                                    print(mycolors.foreground.purple + "\nfile_size: ".ljust(15) + mycolors.reset + str(d['file_size']) + " bytes", end=' ')

                            if ("file_type" in y):
                                if d['file_type']:
                                    print(mycolors.foreground.purple + "\nfile_type: ".ljust(15) + mycolors.reset + str(d['file_type']), end=' ')

                            if ("file_type_mime" in y):
                                if d['file_type_mime']:
                                    print(mycolors.foreground.purple + "\nmime_type: ".ljust(15) + mycolors.reset + str(d['file_type_mime']), end=' ')
                            if ("origin_country" in y):
                                if d['origin_country']:
                                    print(mycolors.foreground.purple + "\ncountry: ".ljust(15) + mycolors.reset + d['origin_country'], end=' ')

                            if ("imphash" in y):
                                if d['imphash']:
                                    print(mycolors.foreground.purple + "\nimphash: ".ljust(15) + mycolors.reset + d['imphash'], end=' ')

                            if ("tlsh" in y):
                                if d['tlsh']:
                                    print(mycolors.foreground.purple + "\ntlsh: ".ljust(15) + mycolors.reset + d['tlsh'], end=' ')

                            if ("reporter" in y):
                                if d['reporter']:
                                    print(mycolors.foreground.purple + "\nreporter: ".ljust(15) + mycolors.reset + d['reporter'], end=' ')

                            if ("signature" in y):
                                if d['signature']:
                                    print(mycolors.foreground.purple + "\nsignature: ".ljust(15) + mycolors.reset + d['signature'], end=' ')

                            if ("tags" in y):
                                if d['tags']:
                                    print(mycolors.foreground.purple + "\ntags: ".ljust(15),end='') 
                                    for t in d['tags']:
                                        print(mycolors.reset + t, end=' ')

        print(mycolors.reset)
        exit(0)
    
    except ValueError as e:
        print(e)
        if (bkg == 1):
            print((mycolors.foreground.lightred + "\nError while connecting to Malware Bazaar!\n"))
        else:
            print((mycolors.foreground.lightred + "\nError while connecting to Malware Bazaar!\n"))
        print(mycolors.reset)


def bazaar_lastsamples(bazaarx, bazaar):

    bazaartext = ''
    bazaarresponse = ''
    params = ''

    try:
        
        print("\n")
        print((mycolors.reset + "MALWARE BAZAAR REPORT".center(100)), end='')
        print((mycolors.reset + "".center(28)), end='')
        print("\n" + (100*'-').center(50))

        requestsession = requests.Session( )
        requestsession.headers.update({'accept': 'application/json'})
        params = {'query':'get_recent',"selector": bazaarx}
        bazaarresponse = requestsession.post(bazaar, data=params)
        bazaartext = json.loads(bazaarresponse.text)

        if bazaartext['query_status'] == "unknown_selector":
            if (bkg == 1):
                print(mycolors.foreground.lightred + "\nYou didn't provided a valid selector!\n" + mycolors.reset)
            else:
                print(mycolors.foreground.red + "\nYour search did not yield any result!\n" + mycolors.reset)
            exit(1)

        if bazaartext['query_status'] == "no_results":
            if (bkg == 1):
                print(mycolors.foreground.lightred + "\nThe query yield no results!\n" + mycolors.reset)
            else:
                print(mycolors.foreground.red + "\nThe query yield no results!\n" + mycolors.reset)
            exit(1)
        
        if (bkg == 1):
            for i in bazaartext.keys():
                if (i == "data"):
                    if (bazaartext['data'] is not None):
                        for d in bazaartext['data']:
                            y = d.keys()    
                            print("\n" + (90*'-').center(45), end=' ')
                            if ("sha256_hash" in y):
                                if d['sha256_hash']:
                                    print(mycolors.foreground.orange + "\nsha256_hash: ".ljust(15) + mycolors.reset + d['sha256_hash'],end=' ')

                            if ("sha1_hash" in y):
                                if d['sha1_hash']:
                                    print(mycolors.foreground.orange + "\nsha1_hash: ".ljust(15) + mycolors.reset + d['sha1_hash'], end=' ')

                            if ("md5_hash" in y):
                                if d['md5_hash']:
                                    print(mycolors.foreground.orange + "\nmd5_hash: ".ljust(15) + mycolors.reset + d['md5_hash'], end=' ')

                            if ("first_seen" in y):
                                if d['first_seen']:
                                    print(mycolors.foreground.orange + "\nfirst_seen: ".ljust(15) + mycolors.reset + d['first_seen'], end=' ')

                            if ("last_seen" in y):
                                if d['last_seen']:
                                    print(mycolors.foreground.orange + "\nlast_seen: ".ljust(15) + mycolors.reset + d['last_seen'], end=' ')

                            if ("file_name" in y):
                                if d['file_name']:
                                    print(mycolors.foreground.orange + "\nfile_name: ".ljust(15) + mycolors.reset + d['file_name'], end=' ')

                            if ("file_size" in y):
                                if d['file_size']:
                                    print(mycolors.foreground.orange + "\nfile_size: ".ljust(15) + mycolors.reset + str(d['file_size']) + " bytes", end=' ')

                            if ("file_type" in y):
                                if d['file_type']:
                                    print(mycolors.foreground.orange + "\nfile_type: ".ljust(15) + mycolors.reset + str(d['file_type']), end=' ')

                            if ("file_type_mime" in y):
                                if d['file_type_mime']:
                                    print(mycolors.foreground.orange + "\nmime_type: ".ljust(15) + mycolors.reset + str(d['file_type_mime']), end=' ')
                            if ("origin_country" in y):
                                if d['origin_country']:
                                    print(mycolors.foreground.orange + "\ncountry: ".ljust(15) + mycolors.reset + d['origin_country'], end=' ')

                            if ("imphash" in y):
                                if d['imphash']:
                                    print(mycolors.foreground.orange + "\nimphash: ".ljust(15) + mycolors.reset + d['imphash'], end=' ')

                            if ("tlsh" in y):
                                if d['tlsh']:
                                    print(mycolors.foreground.orange + "\ntlsh: ".ljust(15) + mycolors.reset + d['tlsh'], end=' ')

                            if ("reporter" in y):
                                if d['reporter']:
                                    print(mycolors.foreground.orange + "\nreporter: ".ljust(15) + mycolors.reset + d['reporter'], end=' ')

                            if ("signature" in y):
                                if d['signature']:
                                    print(mycolors.foreground.orange + "\nsignature: ".ljust(15) + mycolors.reset + d['signature'], end=' ')

                            if ("tags" in y):
                                if d['tags']:
                                    print(mycolors.foreground.orange + "\ntags: ".ljust(15),end='') 
                                    for t in d['tags']:
                                        print(mycolors.reset + t, end=' ')

        if (bkg == 0):
            for i in bazaartext.keys():
                if (i == "data"):
                    if (bazaartext['data'] is not None):
                        for d in bazaartext['data']:
                            y = d.keys()    
                            print("\n" + (90*'-').center(45), end=' ')
                            if ("sha256_hash" in y):
                                if d['sha256_hash']:
                                    print(mycolors.foreground.cyan + "\nsha256_hash: ".ljust(15) + mycolors.reset + d['sha256_hash'],end=' ')

                            if ("sha1_hash" in y):
                                if d['sha1_hash']:
                                    print(mycolors.foreground.cyan + "\nsha1_hash: ".ljust(15) + mycolors.reset + d['sha1_hash'], end=' ')

                            if ("md5_hash" in y):
                                if d['md5_hash']:
                                    print(mycolors.foreground.cyan + "\nmd5_hash: ".ljust(15) + mycolors.reset + d['md5_hash'], end=' ')

                            if ("first_seen" in y):
                                if d['first_seen']:
                                    print(mycolors.foreground.cyan + "\nfirst_seen: ".ljust(15) + mycolors.reset + d['first_seen'], end=' ')

                            if ("last_seen" in y):
                                if d['last_seen']:
                                    print(mycolors.foreground.cyan + "\nlast_seen: ".ljust(15) + mycolors.reset + d['last_seen'], end=' ')

                            if ("file_name" in y):
                                if d['file_name']:
                                    print(mycolors.foreground.cyan + "\nfile_name: ".ljust(15) + mycolors.reset + d['file_name'], end=' ')

                            if ("file_size" in y):
                                if d['file_size']:
                                    print(mycolors.foreground.cyan + "\nfile_size: ".ljust(15) + mycolors.reset + str(d['file_size']) + " bytes", end=' ')

                            if ("file_type" in y):
                                if d['file_type']:
                                    print(mycolors.foreground.cyan + "\nfile_type: ".ljust(15) + mycolors.reset + str(d['file_type']), end=' ')

                            if ("file_type_mime" in y):
                                if d['file_type_mime']:
                                    print(mycolors.foreground.cyan + "\nmime_type: ".ljust(15) + mycolors.reset + str(d['file_type_mime']), end=' ')
                            if ("origin_country" in y):
                                if d['origin_country']:
                                    print(mycolors.foreground.cyan + "\ncountry: ".ljust(15) + mycolors.reset + d['origin_country'], end=' ')

                            if ("imphash" in y):
                                if d['imphash']:
                                    print(mycolors.foreground.cyan + "\nimphash: ".ljust(15) + mycolors.reset + d['imphash'], end=' ')

                            if ("tlsh" in y):
                                if d['tlsh']:
                                    print(mycolors.foreground.cyan + "\ntlsh: ".ljust(15) + mycolors.reset + d['tlsh'], end=' ')

                            if ("reporter" in y):
                                if d['reporter']:
                                    print(mycolors.foreground.cyan + "\nreporter: ".ljust(15) + mycolors.reset + d['reporter'], end=' ')

                            if ("signature" in y):
                                if d['signature']:
                                    print(mycolors.foreground.cyan + "\nsignature: ".ljust(15) + mycolors.reset + d['signature'], end=' ')

                            if ("tags" in y):
                                if d['tags']:
                                    print(mycolors.foreground.cyan + "\ntags: ".ljust(15),end='') 
                                    for t in d['tags']:
                                        print(mycolors.reset + t, end=' ')

        print(mycolors.reset)
        exit(0)
    
    except ValueError as e:
        print(e)
        if (bkg == 1):
            print((mycolors.foreground.lightred + "\nError while connecting to Malware Bazaar!\n"))
        else:
            print((mycolors.foreground.lightred + "\nError while connecting to Malware Bazaar!\n"))
        print(mycolors.reset)


def bazaar_download(bazaarx, bazaar):

    bazaartext = ''
    bazaarresponse = ''
    params = ''
    resource=bazaarx

    try:
        
        print("\n")
        print((mycolors.reset + "MALWARE BAZAAR REPORT".center(100)), end='')
        print((mycolors.reset + "".center(28)), end='')
        print("\n" + (100*'-').center(50))

        requestsession = requests.Session( )
        requestsession.headers.update({'accept': 'application/gzip'})
        params = {'query':'get_file',"sha256_hash": bazaarx}
        bazaarresponse = requestsession.post(bazaar, data=params, allow_redirects=True)
        bazaartext = bazaarresponse.text

        if "illegal_sha256_hash" in bazaartext:
            if (bkg == 1):
                print(mycolors.foreground.lightred + "\nYou didn't provided a valid sha256 hash!\n" + mycolors.reset)
            else:
                print(mycolors.foreground.red + "\nYou didn't provided a valid selector!\n" + mycolors.reset)
            exit(1)

        if "file_not_found" in bazaartext:
            if (bkg == 1):
                print(mycolors.foreground.lightred + "\nNo malware samples found for the provided sha256 hash!\n" + mycolors.reset)
            else:
                print(mycolors.foreground.red + "\nNo malware samples found for the provided sha256 hash!\n" + mycolors.reset)
            exit(1)

        open(resource + '.zip', 'wb').write(bazaarresponse.content)
        final = '\nSAMPLE SAVED!'

        if (bkg == 1):
            print((mycolors.foreground.yellow + final + "\n"))
        else:
            print((mycolors.foreground.green + final + "\n"))

        print(mycolors.reset)
        exit(0)

    except ValueError as e:
        print(e)
        if (bkg == 1):
            print((mycolors.foreground.lightred + "Error while connecting to Malware Bazaar!\n"))
        else:
            print((mycolors.foreground.lightred + "Error while connecting to Malware Bazaar!\n"))
        print(mycolors.reset)


def threatfox_listiocs(bazaarx, bazaar):

    bazaartext = ''
    bazaarresponse = ''
    params = ''

    try:
        
        print("\n")
        print((mycolors.reset + "THREATFOX REPORT".center(100)), end='')
        print((mycolors.reset + "".center(28)), end='')
        print("\n" + (100*'-').center(50))

        requestsession = requests.Session( )
        requestsession.headers.update({'accept':'application/json'})
        params = {'query':"get_iocs" , 'days':bazaarx}
        bazaarresponse = requestsession.post(url=bazaar, data=json.dumps(params))
        bazaartext = json.loads(bazaarresponse.text)

        if (bkg == 1):
            for i in bazaartext.keys():
                if (i == "data"):
                    if (bazaartext['data'] is not None):
                        for d in bazaartext['data']:
                            y = d.keys()    
                            print("\n" + (90*'-').center(45), end=' ')
                            if ("ioc" in y):
                                if d['ioc']:
                                    print(mycolors.foreground.orange + "\nioc: ".ljust(16) + mycolors.reset + d['ioc'],end=' ')

                            if ("id" in y):
                                if d['id']:
                                    print(mycolors.foreground.orange + "\nid: ".ljust(16) + mycolors.reset + d['id'],end=' ')

                            if ("threat_type" in y):
                                if d['threat_type']:
                                    print(mycolors.foreground.orange + "\nthreat_type: ".ljust(16) + mycolors.reset + d['threat_type'], end=' ')

                            if ("threat_type_desc" in y):
                                if d['threat_type_desc']:
                                    print(mycolors.foreground.orange + "\nthreat_desc: ".ljust(16) + mycolors.reset + d['threat_type_desc'], end=' ')

                            if ("ioc_type" in y):
                                if d['ioc_type']:
                                    print(mycolors.foreground.orange + "\nioc_type: ".ljust(16) + mycolors.reset + d['ioc_type'], end=' ')

                            if ("ioc_type_desc" in y):
                                if d['ioc_type_desc']:
                                    print(mycolors.foreground.orange + "\nioc_desc: ".ljust(16) + mycolors.reset + d['ioc_type_desc'], end=' ')

                            if ("malware" in y):
                                if d['malware']:
                                    print(mycolors.foreground.orange + "\nmalware: ".ljust(16) + mycolors.reset + d['malware'], end=' ')

                            if ("malware_printable" in y):
                                if d['malware_printable']:
                                    print(mycolors.foreground.orange + "\nmalware_desc: ".ljust(16) + mycolors.reset + d['malware_printable'], end=' ')

                            if ("malware_alias" in y):
                                if d['malware_alias']:
                                    print(mycolors.foreground.orange + "\nmalware_alias: ".ljust(16) + mycolors.reset + d['malware_alias'], end=' ')

                            if ("malware_malpedia" in y):
                                if d['malware_malpedia']:
                                    print(mycolors.foreground.orange + "\nmalpedia: ".ljust(16) + mycolors.reset + d['malware_malpedia'], end=' ')

                            if ("confidence_level" in y):
                                if d['confidence_level']:
                                    print(mycolors.foreground.orange + "\nconfidence: ".ljust(16) + mycolors.reset + str(d['confidence_level']), end=' ')

                            if ("first_seen" in y):
                                if d['first_seen']:
                                    print(mycolors.foreground.orange + "\nfirst_seen: ".ljust(16) + mycolors.reset + str(d['first_seen']), end=' ')

                            if ("last_seen" in y):
                                if d['last_seen']:
                                    print(mycolors.foreground.orange + "\nlast_seen: ".ljust(16) + mycolors.reset + str(d['last_seen']), end=' ')

                            if ("reporter" in y):
                                if d['reporter']:
                                    print(mycolors.foreground.orange + "\nreporter: ".ljust(16) + mycolors.reset + str(d['reporter']), end=' ')

                            if ("reference" in y):
                                if d['reference']:
                                    print(mycolors.foreground.orange + "\nreference: ".ljust(16) + mycolors.reset + d['reference'], end=' ')

                            if ("tags" in y):
                                if d['tags']:
                                    print(mycolors.foreground.orange + "\ntags: ".ljust(16),end='') 
                                    for t in d['tags']:
                                        print(mycolors.reset + t, end=' ')

        if (bkg == 0):
            for i in bazaartext.keys():
                if (i == "data"):
                    if (bazaartext['data'] is not None):
                        for d in bazaartext['data']:
                            y = d.keys()    
                            print("\n" + (90*'-').center(45), end=' ')
                            if ("ioc" in y):
                                if d['ioc']:
                                    print(mycolors.foreground.red + "\nioc: ".ljust(16) + mycolors.reset + d['ioc'],end=' ')

                            if ("id" in y):
                                if d['id']:
                                    print(mycolors.foreground.red + "\nid: ".ljust(16) + mycolors.reset + d['id'],end=' ')

                            if ("threat_type" in y):
                                if d['threat_type']:
                                    print(mycolors.foreground.red + "\nthreat_type: ".ljust(16) + mycolors.reset + d['threat_type'], end=' ')

                            if ("threat_type_desc" in y):
                                if d['threat_type_desc']:
                                    print(mycolors.foreground.red + "\nthreat_desc: ".ljust(16) + mycolors.reset + d['threat_type_desc'], end=' ')

                            if ("ioc_type" in y):
                                if d['ioc_type']:
                                    print(mycolors.foreground.red + "\nioc_type: ".ljust(16) + mycolors.reset + d['ioc_type'], end=' ')

                            if ("ioc_type_desc" in y):
                                if d['ioc_type_desc']:
                                    print(mycolors.foreground.red + "\nioc_desc: ".ljust(16) + mycolors.reset + d['ioc_type_desc'], end=' ')

                            if ("malware" in y):
                                if d['malware']:
                                    print(mycolors.foreground.red + "\nmalware: ".ljust(16) + mycolors.reset + d['malware'], end=' ')

                            if ("malware_printable" in y):
                                if d['malware_printable']:
                                    print(mycolors.foreground.red + "\nmalware_desc: ".ljust(16) + mycolors.reset + d['malware_printable'], end=' ')

                            if ("malware_alias" in y):
                                if d['malware_alias']:
                                    print(mycolors.foreground.red + "\nmalware_alias: ".ljust(16) + mycolors.reset + d['malware_alias'], end=' ')

                            if ("malware_malpedia" in y):
                                if d['malware_malpedia']:
                                    print(mycolors.foreground.red + "\nmalpedia: ".ljust(16) + mycolors.reset + d['malware_malpedia'], end=' ')

                            if ("confidence_level" in y):
                                if d['confidence_level']:
                                    print(mycolors.foreground.red + "\nconfidence: ".ljust(16) + mycolors.reset + str(d['confidence_level']), end=' ')

                            if ("first_seen" in y):
                                if d['first_seen']:
                                    print(mycolors.foreground.red + "\nfirst_seen: ".ljust(16) + mycolors.reset + str(d['first_seen']), end=' ')

                            if ("last_seen" in y):
                                if d['last_seen']:
                                    print(mycolors.foreground.red + "\nlast_seen: ".ljust(16) + mycolors.reset + str(d['last_seen']), end=' ')

                            if ("reporter" in y):
                                if d['reporter']:
                                    print(mycolors.foreground.red + "\nreporter: ".ljust(16) + mycolors.reset + str(d['reporter']), end=' ')

                            if ("reference" in y):
                                if d['reference']:
                                    print(mycolors.foreground.red + "\nreference: ".ljust(16) + mycolors.reset + d['reference'], end=' ')

                            if ("tags" in y):
                                if d['tags']:
                                    print(mycolors.foreground.red + "\ntags: ".ljust(16),end='') 
                                    for t in d['tags']:
                                        print(mycolors.reset + t, end=' ')

        print(mycolors.reset)
        exit(0)
    
    except ValueError as e:
        print(e)
        if (bkg == 1):
            print((mycolors.foreground.lightred + "\nError while connecting to ThreatFox!\n"))
        else:
            print((mycolors.foreground.lightred + "\nError while connecting to ThreatFox!\n"))
        print(mycolors.reset)


def threatfox_searchiocs(bazaarx, bazaar):

    bazaartext = ''
    bazaarresponse = ''
    params = ''

    try:
        
        print("\n")
        print((mycolors.reset + "THREATFOX REPORT".center(100)), end='')
        print((mycolors.reset + "".center(28)), end='')
        print("\n" + (100*'-').center(50))

        requestsession = requests.Session( )
        requestsession.headers.update({'accept':'application/json'})
        params = {'query':"search_ioc" , 'search_term':bazaarx}
        bazaarresponse = requestsession.post(url=bazaar, data=json.dumps(params))
        bazaartext = json.loads(bazaarresponse.text)

        if bazaartext['query_status'] == "no_result":
            if (bkg == 1):
                print(mycolors.foreground.lightred + "\nYour search did not yield any result!\n" + mycolors.reset)
            else:
                print(mycolors.foreground.red + "\nYour search did not yield any result!\n" + mycolors.reset)
            exit(1)

        if bazaartext['query_status'] == "illegal_search_term":
            if (bkg == 1):
                print(mycolors.foreground.lightred + "\nThe search term you have provided is not valid!\n" + mycolors.reset)
            else:
                print(mycolors.foreground.red + "\nThe search term you have provided is not valid!\n" + mycolors.reset)
            exit(1)

        if (bkg == 1):
            for i in bazaartext.keys():
                if (i == "data"):
                    if (bazaartext['data'] is not None):
                        for d in bazaartext['data']:
                            y = d.keys()    
                            print("\n" + (90*'-').center(45), end=' ')
                            if ("ioc" in y):
                                if d['ioc']:
                                    print(mycolors.foreground.orange + "\nioc: ".ljust(16) + mycolors.reset + d['ioc'],end=' ')

                            if ("id" in y):
                                if d['ioc']:
                                    print(mycolors.foreground.orange + "\nid: ".ljust(16) + mycolors.reset + d['id'],end=' ')

                            if ("threat_type" in y):
                                if d['threat_type']:
                                    print(mycolors.foreground.orange + "\nthreat_type: ".ljust(16) + mycolors.reset + d['threat_type'], end=' ')

                            if ("threat_type_desc" in y):
                                if d['threat_type_desc']:
                                    print(mycolors.foreground.orange + "\nthreat_desc: ".ljust(16) + mycolors.reset + d['threat_type_desc'], end=' ')

                            if ("ioc_type" in y):
                                if d['ioc_type']:
                                    print(mycolors.foreground.orange + "\nioc_type: ".ljust(16) + mycolors.reset + d['ioc_type'], end=' ')

                            if ("ioc_type_desc" in y):
                                if d['ioc_type_desc']:
                                    print(mycolors.foreground.orange + "\nioc_desc: ".ljust(16) + mycolors.reset + d['ioc_type_desc'], end=' ')

                            if ("malware" in y):
                                if d['malware']:
                                    print(mycolors.foreground.orange + "\nmalware: ".ljust(16) + mycolors.reset + d['malware'], end=' ')

                            if ("malware_printable" in y):
                                if d['malware_printable']:
                                    print(mycolors.foreground.orange + "\nmalware_desc: ".ljust(16) + mycolors.reset + d['malware_printable'], end=' ')

                            if ("malware_alias" in y):
                                if d['malware_alias']:
                                    print(mycolors.foreground.orange + "\nmalware_alias: ".ljust(16) + mycolors.reset + d['malware_alias'], end=' ')

                            if ("malware_malpedia" in y):
                                if d['malware_malpedia']:
                                    print(mycolors.foreground.orange + "\nmalpedia: ".ljust(16) + mycolors.reset + d['malware_malpedia'], end=' ')

                            if ("confidence_level" in y):
                                if d['confidence_level']:
                                    print(mycolors.foreground.orange + "\nconfidence: ".ljust(16) + mycolors.reset + str(d['confidence_level']), end=' ')

                            if ("first_seen" in y):
                                if d['first_seen']:
                                    print(mycolors.foreground.orange + "\nfirst_seen: ".ljust(16) + mycolors.reset + str(d['first_seen']), end=' ')

                            if ("last_seen" in y):
                                if d['last_seen']:
                                    print(mycolors.foreground.orange + "\nlast_seen: ".ljust(16) + mycolors.reset + str(d['last_seen']), end=' ')

                            if ("reporter" in y):
                                if d['reporter']:
                                    print(mycolors.foreground.orange + "\nreporter: ".ljust(16) + mycolors.reset + str(d['reporter']), end=' ')

                            if ("reference" in y):
                                if d['reference']:
                                    print(mycolors.foreground.orange + "\nreference: ".ljust(16) + mycolors.reset + d['reference'], end=' ')

                            if ("tags" in y):
                                if d['tags']:
                                    print(mycolors.foreground.orange + "\ntags: ".ljust(16),end='') 
                                    for t in d['tags']:
                                        print(mycolors.reset + t, end=' ')

        if (bkg == 0):
            for i in bazaartext.keys():
                if (i == "data"):
                    if (bazaartext['data'] is not None):
                        for d in bazaartext['data']:
                            y = d.keys()    
                            print("\n" + (90*'-').center(45), end=' ')
                            if ("ioc" in y):
                                if d['ioc']:
                                    print(mycolors.foreground.red + "\nioc: ".ljust(16) + mycolors.reset + d['ioc'],end=' ')

                            if ("id" in y):
                                if d['ioc']:
                                    print(mycolors.foreground.red + "\nid: ".ljust(16) + mycolors.reset + d['id'],end=' ')

                            if ("threat_type" in y):
                                if d['threat_type']:
                                    print(mycolors.foreground.red + "\nthreat_type: ".ljust(16) + mycolors.reset + d['threat_type'], end=' ')

                            if ("threat_type_desc" in y):
                                if d['threat_type_desc']:
                                    print(mycolors.foreground.red + "\nthreat_desc: ".ljust(16) + mycolors.reset + d['threat_type_desc'], end=' ')

                            if ("ioc_type" in y):
                                if d['ioc_type']:
                                    print(mycolors.foreground.red + "\nioc_type: ".ljust(16) + mycolors.reset + d['ioc_type'], end=' ')

                            if ("ioc_type_desc" in y):
                                if d['ioc_type_desc']:
                                    print(mycolors.foreground.red + "\nioc_desc: ".ljust(16) + mycolors.reset + d['ioc_type_desc'], end=' ')

                            if ("malware" in y):
                                if d['malware']:
                                    print(mycolors.foreground.red + "\nmalware: ".ljust(16) + mycolors.reset + d['malware'], end=' ')

                            if ("malware_printable" in y):
                                if d['malware_printable']:
                                    print(mycolors.foreground.red + "\nmalware_desc: ".ljust(16) + mycolors.reset + d['malware_printable'], end=' ')

                            if ("malware_alias" in y):
                                if d['malware_alias']:
                                    print(mycolors.foreground.red + "\nmalware_alias: ".ljust(16) + mycolors.reset + d['malware_alias'], end=' ')

                            if ("malware_malpedia" in y):
                                if d['malware_malpedia']:
                                    print(mycolors.foreground.red + "\nmalpedia: ".ljust(16) + mycolors.reset + d['malware_malpedia'], end=' ')

                            if ("confidence_level" in y):
                                if d['confidence_level']:
                                    print(mycolors.foreground.red + "\nconfidence: ".ljust(16) + mycolors.reset + str(d['confidence_level']), end=' ')

                            if ("first_seen" in y):
                                if d['first_seen']:
                                    print(mycolors.foreground.red + "\nfirst_seen: ".ljust(16) + mycolors.reset + str(d['first_seen']), end=' ')

                            if ("last_seen" in y):
                                if d['last_seen']:
                                    print(mycolors.foreground.red + "\nlast_seen: ".ljust(16) + mycolors.reset + str(d['last_seen']), end=' ')

                            if ("reporter" in y):
                                if d['reporter']:
                                    print(mycolors.foreground.red + "\nreporter: ".ljust(16) + mycolors.reset + str(d['reporter']), end=' ')

                            if ("reference" in y):
                                if d['reference']:
                                    print(mycolors.foreground.red + "\nreference: ".ljust(16) + mycolors.reset + d['reference'], end=' ')

                            if ("tags" in y):
                                if d['tags']:
                                    print(mycolors.foreground.red + "\ntags: ".ljust(16),end='') 
                                    for t in d['tags']:
                                        print(mycolors.reset + t, end=' ')

        print(mycolors.reset)
        exit(0)
    
    except ValueError as e:
        print(e)
        if (bkg == 1):
            print((mycolors.foreground.lightred + "\nError while connecting to ThreatFox!\n"))
        else:
            print((mycolors.foreground.lightred + "\nError while connecting to ThreatFox!\n"))
        print(mycolors.reset)


def threatfox_searchtags(bazaarx, bazaar):

    bazaartext = ''
    bazaarresponse = ''
    params = ''

    try:
        
        print("\n")
        print((mycolors.reset + "THREATFOX REPORT".center(100)), end='')
        print((mycolors.reset + "".center(28)), end='')
        print("\n" + (100*'-').center(50))

        requestsession = requests.Session( )
        requestsession.headers.update({'accept':'application/json'})
        params = {'query':"taginfo" , 'tag':bazaarx}
        bazaarresponse = requestsession.post(url=bazaar, data=json.dumps(params))
        bazaartext = json.loads(bazaarresponse.text)

        if bazaartext['query_status'] == "no_result":
            if (bkg == 1):
                print(mycolors.foreground.lightred + "\nYour search did not yield any result!\n" + mycolors.reset)
            else:
                print(mycolors.foreground.red + "\nYour search did not yield any result!\n" + mycolors.reset)
            exit(1)

        if bazaartext['query_status'] == "illegal_search_term":
            if (bkg == 1):
                print(mycolors.foreground.lightred + "\nThe search term you have provided is not valid!\n" + mycolors.reset)
            else:
                print(mycolors.foreground.red + "\nThe search term you have provided is not valid!\n" + mycolors.reset)
            exit(1)

        if bazaartext['query_status'] == "illegal_tag":
            if (bkg == 1):
                print(mycolors.foreground.lightred + "\nThe tag you have provided is not valid!\n" + mycolors.reset)
            else:
                print(mycolors.foreground.red + "\nThe tag you have provided is not valid!\n" + mycolors.reset)
            exit(1)

        if (bkg == 1):
            for i in bazaartext.keys():
                if (i == "data"):
                    if (bazaartext['data'] is not None):
                        for d in bazaartext['data']:
                            y = d.keys()    
                            print("\n" + (90*'-').center(45), end=' ')
                            if ("ioc" in y):
                                if d['ioc']:
                                    print(mycolors.foreground.lightgreen + "\nioc: ".ljust(16) + mycolors.reset + d['ioc'],end=' ')

                            if ("id" in y):
                                if d['ioc']:
                                    print(mycolors.foreground.lightgreen + "\nid: ".ljust(16) + mycolors.reset + d['id'],end=' ')

                            if ("threat_type" in y):
                                if d['threat_type']:
                                    print(mycolors.foreground.lightgreen + "\nthreat_type: ".ljust(16) + mycolors.reset + d['threat_type'], end=' ')

                            if ("threat_type_desc" in y):
                                if d['threat_type_desc']:
                                    print(mycolors.foreground.lightgreen + "\nthreat_desc: ".ljust(16) + mycolors.reset + d['threat_type_desc'], end=' ')

                            if ("ioc_type" in y):
                                if d['ioc_type']:
                                    print(mycolors.foreground.lightgreen + "\nioc_type: ".ljust(16) + mycolors.reset + d['ioc_type'], end=' ')

                            if ("ioc_type_desc" in y):
                                if d['ioc_type_desc']:
                                    print(mycolors.foreground.lightgreen + "\nioc_desc: ".ljust(16) + mycolors.reset + d['ioc_type_desc'], end=' ')

                            if ("malware" in y):
                                if d['malware']:
                                    print(mycolors.foreground.lightgreen + "\nmalware: ".ljust(16) + mycolors.reset + d['malware'], end=' ')

                            if ("malware_printable" in y):
                                if d['malware_printable']:
                                    print(mycolors.foreground.lightgreen + "\nmalware_desc: ".ljust(16) + mycolors.reset + d['malware_printable'], end=' ')

                            if ("malware_alias" in y):
                                if d['malware_alias']:
                                    print(mycolors.foreground.lightgreen + "\nmalware_alias: ".ljust(16) + mycolors.reset + d['malware_alias'], end=' ')

                            if ("malware_malpedia" in y):
                                if d['malware_malpedia']:
                                    print(mycolors.foreground.lightgreen + "\nmalpedia: ".ljust(16) + mycolors.reset + d['malware_malpedia'], end=' ')

                            if ("confidence_level" in y):
                                if d['confidence_level']:
                                    print(mycolors.foreground.lightgreen + "\nconfidence: ".ljust(16) + mycolors.reset + str(d['confidence_level']), end=' ')

                            if ("first_seen" in y):
                                if d['first_seen']:
                                    print(mycolors.foreground.lightgreen + "\nfirst_seen: ".ljust(16) + mycolors.reset + str(d['first_seen']), end=' ')

                            if ("last_seen" in y):
                                if d['last_seen']:
                                    print(mycolors.foreground.lightgreen + "\nlast_seen: ".ljust(16) + mycolors.reset + str(d['last_seen']), end=' ')

                            if ("reporter" in y):
                                if d['reporter']:
                                    print(mycolors.foreground.lightgreen + "\nreporter: ".ljust(16) + mycolors.reset + str(d['reporter']), end=' ')

                            if ("reference" in y):
                                if d['reference']:
                                    print(mycolors.foreground.lightgreen + "\nreference: ".ljust(16) + mycolors.reset + d['reference'], end=' ')

                            if ("tags" in y):
                                if d['tags']:
                                    print(mycolors.foreground.lightgreen + "\ntags: ".ljust(16),end='') 
                                    for t in d['tags']:
                                        print(mycolors.reset + t, end=' ')

        if (bkg == 0):
            for i in bazaartext.keys():
                if (i == "data"):
                    if (bazaartext['data'] is not None):
                        for d in bazaartext['data']:
                            y = d.keys()    
                            print("\n" + (90*'-').center(45), end=' ')
                            if ("ioc" in y):
                                if d['ioc']:
                                    print(mycolors.foreground.cyan + "\nioc: ".ljust(16) + mycolors.reset + d['ioc'],end=' ')

                            if ("id" in y):
                                if d['ioc']:
                                    print(mycolors.foreground.cyan + "\nid: ".ljust(16) + mycolors.reset + d['id'],end=' ')

                            if ("threat_type" in y):
                                if d['threat_type']:
                                    print(mycolors.foreground.cyan + "\nthreat_type: ".ljust(16) + mycolors.reset + d['threat_type'], end=' ')

                            if ("threat_type_desc" in y):
                                if d['threat_type_desc']:
                                    print(mycolors.foreground.cyan + "\nthreat_desc: ".ljust(16) + mycolors.reset + d['threat_type_desc'], end=' ')

                            if ("ioc_type" in y):
                                if d['ioc_type']:
                                    print(mycolors.foreground.cyan + "\nioc_type: ".ljust(16) + mycolors.reset + d['ioc_type'], end=' ')

                            if ("ioc_type_desc" in y):
                                if d['ioc_type_desc']:
                                    print(mycolors.foreground.cyan + "\nioc_desc: ".ljust(16) + mycolors.reset + d['ioc_type_desc'], end=' ')

                            if ("malware" in y):
                                if d['malware']:
                                    print(mycolors.foreground.cyan + "\nmalware: ".ljust(16) + mycolors.reset + d['malware'], end=' ')

                            if ("malware_printable" in y):
                                if d['malware_printable']:
                                    print(mycolors.foreground.cyan + "\nmalware_desc: ".ljust(16) + mycolors.reset + d['malware_printable'], end=' ')

                            if ("malware_alias" in y):
                                if d['malware_alias']:
                                    print(mycolors.foreground.cyan + "\nmalware_alias: ".ljust(16) + mycolors.reset + d['malware_alias'], end=' ')

                            if ("malware_malpedia" in y):
                                if d['malware_malpedia']:
                                    print(mycolors.foreground.cyan + "\nmalpedia: ".ljust(16) + mycolors.reset + d['malware_malpedia'], end=' ')

                            if ("confidence_level" in y):
                                if d['confidence_level']:
                                    print(mycolors.foreground.cyan + "\nconfidence: ".ljust(16) + mycolors.reset + str(d['confidence_level']), end=' ')

                            if ("first_seen" in y):
                                if d['first_seen']:
                                    print(mycolors.foreground.cyan + "\nfirst_seen: ".ljust(16) + mycolors.reset + str(d['first_seen']), end=' ')

                            if ("last_seen" in y):
                                if d['last_seen']:
                                    print(mycolors.foreground.cyan + "\nlast_seen: ".ljust(16) + mycolors.reset + str(d['last_seen']), end=' ')

                            if ("reporter" in y):
                                if d['reporter']:
                                    print(mycolors.foreground.cyan + "\nreporter: ".ljust(16) + mycolors.reset + str(d['reporter']), end=' ')

                            if ("reference" in y):
                                if d['reference']:
                                    print(mycolors.foreground.cyan + "\nreference: ".ljust(16) + mycolors.reset + d['reference'], end=' ')

                            if ("tags" in y):
                                if d['tags']:
                                    print(mycolors.foreground.cyan + "\ntags: ".ljust(16),end='') 
                                    for t in d['tags']:
                                        print(mycolors.reset + t, end=' ')

        print(mycolors.reset)
        exit(0)
    
    except ValueError as e:
        print(e)
        if (bkg == 1):
            print((mycolors.foreground.lightred + "\nError while connecting to ThreatFox!\n"))
        else:
            print((mycolors.foreground.lightred + "\nError while connecting to ThreatFox!\n"))
        print(mycolors.reset)


def threatfox_searchmalware(bazaarx, bazaar):

    bazaartext = ''
    bazaarresponse = ''
    params = ''

    try:
        
        print("\n")
        print((mycolors.reset + "THREATFOX REPORT".center(100)), end='')
        print((mycolors.reset + "".center(28)), end='')
        print("\n" + (100*'-').center(50))

        requestsession = requests.Session( )
        requestsession.headers.update({'accept':'application/json'})
        params = {'query':"malwareinfo" , 'malware':bazaarx}
        bazaarresponse = requestsession.post(url=bazaar, data=json.dumps(params))
        bazaartext = json.loads(bazaarresponse.text)

        if bazaartext['query_status'] == "no_result":
            if (bkg == 1):
                print(mycolors.foreground.lightred + "\nYour search did not yield any result!\n" + mycolors.reset)
            else:
                print(mycolors.foreground.red + "\nYour search did not yield any result!\n" + mycolors.reset)
            exit(1)

        if bazaartext['query_status'] == "illegal_search_term":
            if (bkg == 1):
                print(mycolors.foreground.lightred + "\nThe search term you have provided is not valid!\n" + mycolors.reset)
            else:
                print(mycolors.foreground.red + "\nThe search term you have provided is not valid!\n" + mycolors.reset)
            exit(1)

        if (bkg == 1):
            for i in bazaartext.keys():
                if (i == "data"):
                    if (bazaartext['data'] is not None):
                        for d in bazaartext['data']:
                            y = d.keys()    
                            print("\n" + (90*'-').center(45), end=' ')
                            if ("ioc" in y):
                                if d['ioc']:
                                    print(mycolors.foreground.lightcyan + "\nioc: ".ljust(16) + mycolors.reset + d['ioc'],end=' ')

                            if ("id" in y):
                                if d['ioc']:
                                    print(mycolors.foreground.lightcyan + "\nid: ".ljust(16) + mycolors.reset + d['id'],end=' ')

                            if ("threat_type" in y):
                                if d['threat_type']:
                                    print(mycolors.foreground.lightcyan + "\nthreat_type: ".ljust(16) + mycolors.reset + d['threat_type'], end=' ')

                            if ("threat_type_desc" in y):
                                if d['threat_type_desc']:
                                    print(mycolors.foreground.lightcyan + "\nthreat_desc: ".ljust(16) + mycolors.reset + d['threat_type_desc'], end=' ')

                            if ("ioc_type" in y):
                                if d['ioc_type']:
                                    print(mycolors.foreground.lightcyan + "\nioc_type: ".ljust(16) + mycolors.reset + d['ioc_type'], end=' ')

                            if ("ioc_type_desc" in y):
                                if d['ioc_type_desc']:
                                    print(mycolors.foreground.lightcyan + "\nioc_desc: ".ljust(16) + mycolors.reset + d['ioc_type_desc'], end=' ')

                            if ("malware" in y):
                                if d['malware']:
                                    print(mycolors.foreground.lightcyan + "\nmalware: ".ljust(16) + mycolors.reset + d['malware'], end=' ')

                            if ("malware_printable" in y):
                                if d['malware_printable']:
                                    print(mycolors.foreground.lightcyan + "\nmalware_desc: ".ljust(16) + mycolors.reset + d['malware_printable'], end=' ')

                            if ("malware_alias" in y):
                                if d['malware_alias']:
                                    print(mycolors.foreground.lightcyan + "\nmalware_alias: ".ljust(16) + mycolors.reset + d['malware_alias'], end=' ')

                            if ("malware_malpedia" in y):
                                if d['malware_malpedia']:
                                    print(mycolors.foreground.lightcyan + "\nmalpedia: ".ljust(16) + mycolors.reset + d['malware_malpedia'], end=' ')

                            if ("confidence_level" in y):
                                if d['confidence_level']:
                                    print(mycolors.foreground.lightcyan + "\nconfidence: ".ljust(16) + mycolors.reset + str(d['confidence_level']), end=' ')

                            if ("first_seen" in y):
                                if d['first_seen']:
                                    print(mycolors.foreground.lightcyan + "\nfirst_seen: ".ljust(16) + mycolors.reset + str(d['first_seen']), end=' ')

                            if ("last_seen" in y):
                                if d['last_seen']:
                                    print(mycolors.foreground.lightcyan + "\nlast_seen: ".ljust(16) + mycolors.reset + str(d['last_seen']), end=' ')

                            if ("reporter" in y):
                                if d['reporter']:
                                    print(mycolors.foreground.lightcyan + "\nreporter: ".ljust(16) + mycolors.reset + str(d['reporter']), end=' ')

                            if ("reference" in y):
                                if d['reference']:
                                    print(mycolors.foreground.lightcyan + "\nreference: ".ljust(16) + mycolors.reset + d['reference'], end=' ')

                            if ("tags" in y):
                                if d['tags']:
                                    print(mycolors.foreground.lightcyan + "\ntags: ".ljust(16),end='') 
                                    for t in d['tags']:
                                        print(mycolors.reset + t, end=' ')

        if (bkg == 0):
            for i in bazaartext.keys():
                if (i == "data"):
                    if (bazaartext['data'] is not None):
                        for d in bazaartext['data']:
                            y = d.keys()    
                            print("\n" + (90*'-').center(45), end=' ')
                            if ("ioc" in y):
                                if d['ioc']:
                                    print(mycolors.foreground.green + "\nioc: ".ljust(16) + mycolors.reset + d['ioc'],end=' ')

                            if ("id" in y):
                                if d['ioc']:
                                    print(mycolors.foreground.green + "\nid: ".ljust(16) + mycolors.reset + d['id'],end=' ')

                            if ("threat_type" in y):
                                if d['threat_type']:
                                    print(mycolors.foreground.green + "\nthreat_type: ".ljust(16) + mycolors.reset + d['threat_type'], end=' ')

                            if ("threat_type_desc" in y):
                                if d['threat_type_desc']:
                                    print(mycolors.foreground.green + "\nthreat_desc: ".ljust(16) + mycolors.reset + d['threat_type_desc'], end=' ')

                            if ("ioc_type" in y):
                                if d['ioc_type']:
                                    print(mycolors.foreground.green + "\nioc_type: ".ljust(16) + mycolors.reset + d['ioc_type'], end=' ')

                            if ("ioc_type_desc" in y):
                                if d['ioc_type_desc']:
                                    print(mycolors.foreground.green + "\nioc_desc: ".ljust(16) + mycolors.reset + d['ioc_type_desc'], end=' ')

                            if ("malware" in y):
                                if d['malware']:
                                    print(mycolors.foreground.green + "\nmalware: ".ljust(16) + mycolors.reset + d['malware'], end=' ')

                            if ("malware_printable" in y):
                                if d['malware_printable']:
                                    print(mycolors.foreground.green + "\nmalware_desc: ".ljust(16) + mycolors.reset + d['malware_printable'], end=' ')

                            if ("malware_alias" in y):
                                if d['malware_alias']:
                                    print(mycolors.foreground.green + "\nmalware_alias: ".ljust(16) + mycolors.reset + d['malware_alias'], end=' ')

                            if ("malware_malpedia" in y):
                                if d['malware_malpedia']:
                                    print(mycolors.foreground.green + "\nmalpedia: ".ljust(16) + mycolors.reset + d['malware_malpedia'], end=' ')

                            if ("confidence_level" in y):
                                if d['confidence_level']:
                                    print(mycolors.foreground.green + "\nconfidence: ".ljust(16) + mycolors.reset + str(d['confidence_level']), end=' ')

                            if ("first_seen" in y):
                                if d['first_seen']:
                                    print(mycolors.foreground.green + "\nfirst_seen: ".ljust(16) + mycolors.reset + str(d['first_seen']), end=' ')

                            if ("last_seen" in y):
                                if d['last_seen']:
                                    print(mycolors.foreground.green + "\nlast_seen: ".ljust(16) + mycolors.reset + str(d['last_seen']), end=' ')

                            if ("reporter" in y):
                                if d['reporter']:
                                    print(mycolors.foreground.green + "\nreporter: ".ljust(16) + mycolors.reset + str(d['reporter']), end=' ')

                            if ("reference" in y):
                                if d['reference']:
                                    print(mycolors.foreground.green + "\nreference: ".ljust(16) + mycolors.reset + d['reference'], end=' ')

                            if ("tags" in y):
                                if d['tags']:
                                    print(mycolors.foreground.green + "\ntags: ".ljust(16),end='') 
                                    for t in d['tags']:
                                        print(mycolors.reset + t, end=' ')

        print(mycolors.reset)
        exit(0)
    
    except ValueError as e:
        print(e)
        if (bkg == 1):
            print((mycolors.foreground.lightred + "\nError while connecting to ThreatFox!\n"))
        else:
            print((mycolors.foreground.lightred + "\nError while connecting to ThreatFox!\n"))
        print(mycolors.reset)


def threatfox_listmalware(bazaarx, bazaar):

    bazaartext = ''
    bazaarresponse = ''
    params = ''

    try:
        
        print("\n")
        print((mycolors.reset + "THREATFOX REPORT".center(100)), end='')
        print((mycolors.reset + "".center(28)), end='')
        print("\n" + (100*'-').center(50))

        requestsession = requests.Session( )
        requestsession.headers.update({'accept':'application/json'})
        params = {'query':"malware_list"}
        bazaarresponse = requestsession.post(url=bazaar, data=json.dumps(params))
        bazaartext = json.loads(bazaarresponse.text)

        if bazaartext['query_status'] == "no_result":
            if (bkg == 1):
                print(mycolors.foreground.lightred + "\nYour search did not yield any result!\n" + mycolors.reset)
            else:
                print(mycolors.foreground.red + "\nYour search did not yield any result!\n" + mycolors.reset)
            exit(1)

        if (bkg == 1):
            for i in bazaartext.keys():
                if (i == "data"):
                    if (bazaartext['data'] is not None):
                        for d in bazaartext['data']:
                            for reference,info in bazaartext['data'].items():
                                print("\n" + (80*'-').center(40), end=' ')
                                print(mycolors.foreground.yellow + "\nmalware_family: ".ljust(16) + mycolors.reset + reference,end=' ')
                                for key in info:
                                    print(mycolors.reset + "\n".ljust(17) + "%-18s" % key + ': ',end='')
                                    print(info[key],end='')
                            break

        if (bkg == 0):
            for i in bazaartext.keys():
                if (i == "data"):
                    if (bazaartext['data'] is not None):
                        for d in bazaartext['data']:
                            for reference,info in bazaartext['data'].items():
                                print("\n" + (80*'-').center(40), end=' ')
                                print(mycolors.foreground.purple + "\nmalware_family: ".ljust(16) + mycolors.reset + reference,end=' ')
                                for key in info:
                                    print(mycolors.reset + "\n".ljust(17) + "%-18s" % key + ': ',end='')
                                    print(info[key],end='')
                            break

        print(mycolors.reset)
        exit(0)
    
    except ValueError as e:
        print(e)
        if (bkg == 1):
            print((mycolors.foreground.lightred + "\nError while connecting to ThreatFox!\n"))
        else:
            print((mycolors.foreground.lightred + "\nError while connecting to ThreatFox!\n"))
        print(mycolors.reset)



def haussigsearchroutine(payloadtagx, haus):

    haustext = ''
    hausresponse = ''
    finalurl9 = ''
    params = ''

    try:
        
        print("\n")
        print((mycolors.reset + "URLHaus Report".center(126)), end='')
        print((mycolors.reset + "".center(28)), end='')
        print("\n" + (126*'-').center(59))

        requestsession9 = requests.Session( )
        requestsession9.headers.update({'accept': 'application/json'})
        params = {"signature": payloadtagx}
        hausresponse = requestsession9.post(haus, data=params)
        haustext = json.loads(hausresponse.text)

        if 'query_status' in haustext:
            if (bkg == 1):
                print(mycolors.foreground.lightgreen + "Is available?: \t"  +  haustext.get('query_status').upper())
            else:
                print(mycolors.foreground.green + "Is available?: \t"  +  haustext.get('query_status').upper())
        else:
            if (bkg == 1):
                print(mycolors.foreground.lightgreen + 'Is availble?: Not available')
            else:
                print(mycolors.foreground.green + 'Is available?: Not available')

        if 'firstseen' in haustext:
            if haustext.get('firstseen') is not None:
                if (bkg == 1):
                    print(mycolors.foreground.lightcyan + "First Seen: \t"  +  haustext.get('firstseen'))
                else:
                    print(mycolors.foreground.cyan + "First Seen: \t"  +  haustext.get('firstseen'))
            else:
                if (bkg == 1):
                    print(mycolors.foreground.lightcyan + 'First Seen: ')
                else:
                    print(mycolors.foreground.cyan + 'First Seen: ')

        if 'lastseen' in haustext:
            if haustext.get('lastseen') is not None:
                if (bkg == 1):
                    print(mycolors.foreground.lightcyan + "Last Seen: \t"  +  haustext.get('lastseen'))
                else:
                    print(mycolors.foreground.cyan + "Last Seen: \t"  +  haustext.get('lastseen'))
            else:
                if (bkg == 1):
                    print(mycolors.foreground.lightcyan + 'Last Seen: ')
                else:
                    print(mycolors.foreground.cyan + 'Last Seen: ')

        if 'url_count' in haustext:
            if haustext.get('url_count') is not None:
                if (bkg == 1):
                    print(mycolors.foreground.lightred + "URL count: \t"  +  haustext.get('url_count'))
                else:
                    print(mycolors.foreground.red + "URL count: \t"  +  haustext.get('url_count'))
            else:
                if (bkg == 1):
                    print(mycolors.foreground.lightred + 'URL count: ')
                else:
                    print(mycolors.foreground.red + 'URL count: ')

        if 'payload_count' in haustext:
            if haustext.get('payload_count') is not None:
                if (bkg == 1):
                    print(mycolors.foreground.lightred + "Payload count: \t"  +  haustext.get('payload_count'))
                else:
                    print(mycolors.foreground.red + "Payload count: \t"  +  haustext.get('payload_count'))
            else:
                if (bkg == 1):
                    print(mycolors.foreground.lightred + 'Payload count: ')
                else:
                    print(mycolors.foreground.red + 'Payload count: ')

        if (bkg == 1):
            print(mycolors.foreground.orange + "Tag:\t\t%s" %  payloadtagx)
        else:
            print(mycolors.foreground.pink + "Tag:\t\t%s" %  payloadtagx)

        if 'urls' in haustext:
            if ('url_id' in haustext['urls']) is not None:
                print(mycolors.reset + "\nStatus".center(9) + " " * 2 + "File Type".ljust(10) + " SHA256 Hash".center(64) + " " * 5 + "Virus Total".ljust(14) + ' ' * 2 + "URL to Payload".center(45))
                print("-" * 170 + "\n")
                for w in haustext['urls']:
                    if (bkg == 1):
                        if(w['url_status'] == 'online'):
                            print(mycolors.foreground.lightgreen + mycolors.reverse + w['url_status'] + " " + mycolors.reset, end=' ')
                        if(w['url_status'] == 'offline'):
                            print(mycolors.foreground.lightred + mycolors.reverse + w['url_status'] + mycolors.reset, end=' ')
                        if(w['url_status'] == ''):
                            print(mycolors.foreground.lightblue + mycolors.reverse + "unknown" + mycolors.reset, end=' ')
                        if w['file_type']:
                            print(mycolors.foreground.lightcyan + ' ' * 2 + "%-10s" % w['file_type'] + mycolors.reset, end=' ')
                        else:
                            print(mycolors.foreground.lightcyan + ' ' * 2 + "%-10s" % "unknown" + mycolors.reset, end=' ')
                        if w['sha256_hash']:
                            print(mycolors.foreground.yellow + w['sha256_hash'] + mycolors.reset, end= ' ')
                        if w['virustotal']:
                            print(mycolors.foreground.lightgreen + ' ' * 2 + "%-9s" % w['virustotal'].get('result') + mycolors.reset, end= ' ')
                        else:
                            print(mycolors.foreground.lightgreen + ' ' * 2 + "%-9s" % "Not Found" + mycolors.reset, end= ' ')
                        if (w['url']):
                            print(mycolors.foreground.pink + ' ' * 2 + w['url'] + mycolors.reset)
                        else:
                            print(mycolors.foreground.pink + ' ' * 2 + "URL not provided".center(20) + mycolors.reset)

                    else:
                        if(w['url_status'] == 'online'):
                            print(mycolors.foreground.green + mycolors.reverse + w['url_status'] + " " + mycolors.reset, end=' ')
                        if(w['url_status'] == 'offline'):
                            print(mycolors.foreground.red + mycolors.reverse + w['url_status'] + mycolors.reset, end=' ')
                        if(w['url_status'] == ''):
                            print(mycolors.foreground.blue + mycolors.reverse + "unknown" + mycolors.reset, end=' ')
                        if w['file_type']:
                            print(mycolors.foreground.purple + ' ' * 2 + "%-10s" % w['file_type'] + mycolors.reset, end=' ')
                        else:
                            print(mycolors.foreground.purple + ' ' * 2 + "%-10s" % "unknown" + mycolors.reset, end=' ')
                        if w['sha256_hash']:
                            print(mycolors.foreground.red + w['sha256_hash'] + mycolors.reset, end= ' ')
                        if w['virustotal']:
                            print(mycolors.foreground.cyan + ' ' * 2 + "%-9s" % w['virustotal'].get('result') + mycolors.reset, end= ' ')
                        else:
                            print(mycolors.foreground.cyan + ' ' * 2 + "%-9s" % "Not Found" + mycolors.reset, end= ' ')
                        if (w['url']):
                            print(mycolors.foreground.green + ' ' * 2 + w['url'] + mycolors.reset)
                        else:
                            print(mycolors.foreground.green + ' ' * 2 + "URL not provided".center(20) + mycolors.reset)

        print(mycolors.reset)

    except (BrokenPipeError, IOError, TypeError):
        print(mycolors.reset , file=sys.stderr)
        exit(1)

    except ValueError as e:
        print(e)
        if (bkg == 1):
            print((mycolors.foreground.lightred + "Error while connecting to URLhaus!\n"))
        else:
            print((mycolors.foreground.lightred + "Error while connecting to URLhaus!\n"))
        print(mycolors.reset)


def haustagsearchroutine(haustag, hausurltag):

    haustext = ''
    hausresponse = ''
    params = ''

    try:

        print("\n")
        print((mycolors.reset + "URLHaus Report".center(126)), end='')
        print((mycolors.reset + "".center(28)), end='')
        print("\n" + (130*'-').center(59))

        params = {"tag": haustag}
        requestsession = requests.Session( )
        requestsession.headers.update({'accept': 'application/json'})
        hausresponse = requestsession.post(hausurltag, data=params)
        haustext = json.loads(hausresponse.text)

        if 'query_status' in haustext:
            if (bkg == 1):
                print(mycolors.foreground.lightgreen + "Is available?: \t"  +  haustext.get('query_status').upper())
            else:
                print(mycolors.foreground.green + "Is available?: \t"  +  haustext.get('query_status').upper())
        else:
            if (bkg == 1):
                print(mycolors.foreground.lightgreen + 'Is availble?: Not available')
            else:
                print(mycolors.foreground.green + 'Is available?: Not available')

        if 'firstseen' in haustext:
            if haustext.get('firstseen') is not None:
                if (bkg == 1):
                    print(mycolors.foreground.lightcyan + "First Seen: \t"  +  haustext.get('firstseen'))
                else:
                    print(mycolors.foreground.cyan + "First Seen: \t"  +  haustext.get('firstseen'))
            else:
                if (bkg == 1):
                    print(mycolors.foreground.lightcyan + 'First Seen: ')
                else:
                    print(mycolors.foreground.cyan + 'First Seen: ')

        if 'lastseen' in haustext:
            if haustext.get('lastseen') is not None:
                if (bkg == 1):
                    print(mycolors.foreground.lightcyan + "Last Seen: \t"  +  haustext.get('lastseen'))
                else:
                    print(mycolors.foreground.cyan + "Last Seen: \t"  +  haustext.get('lastseen'))
            else:
                if (bkg == 1):
                    print(mycolors.foreground.lightcyan + 'Last Seen: ')
                else:
                    print(mycolors.foreground.cyan + 'Last Seen: ')

        if 'url_count' in haustext:
            if haustext.get('url_count') is not None:
                if (bkg == 1):
                    print(mycolors.foreground.lightred + "URL count: \t"  +  haustext.get('url_count'))
                else:
                    print(mycolors.foreground.red + "URL count: \t"  +  haustext.get('url_count'))
            else:
                if (bkg == 1):
                    print(mycolors.foreground.lightred + 'URL count: \tNot Found')
                else:
                    print(mycolors.foreground.red + 'URL count: \tNot Found')

        if (bkg == 1):
            print(mycolors.foreground.orange + "Tag:\t\t%s" %  haustag)
        else:
            print(mycolors.foreground.pink + "Tag:\t\t%s" %  haustag)


        if 'urls' in haustext:
            if ('url_id' in haustext['urls']) is not None:
                print(mycolors.reset + "\nStatus".center(9) + " " * 6  +  " " * 2 + "Date Added".ljust(22) + " Threat".ljust(17) + " " * 28 + "Associated URL".ljust(80))
                print("-" * 130 + "\n")

                for w in haustext['urls']:
                    if (bkg == 1):
                        if(w['url_status'] == 'online'):
                            print(mycolors.foreground.lightgreen + mycolors.reverse + w['url_status'] + " " + mycolors.reset, end=' ')
                        if(w['url_status'] == 'offline'):
                            print(mycolors.foreground.lightred + mycolors.reverse + w['url_status'] + mycolors.reset, end=' ')
                        if(w['url_status'] == ''):
                            print(mycolors.foreground.lightblue + mycolors.reverse + "unknown" + mycolors.reset, end=' ')
                        if (w['url']):
                            if (w['dateadded']):
                                print(mycolors.foreground.lightcyan + " " * 2 + (w['dateadded']).ljust(22) + mycolors.reset, end=' ')
                            else:
                                print(mycolors.foreground.lightcyan + " " * 2 + "not provided".center(17) + mycolors.reset, end=' ')
                            if (w['threat']):
                                print(mycolors.foreground.pink + (w['threat']).ljust(17) + mycolors.reset, end=' ')
                            else:
                                print(mycolors.foreground.pink + "not provided".center(22) + mycolors.reset, end=' ')
                            if (w['url']):
                                print(mycolors.foreground.yellow + " " * 2 + (w['url']).ljust(80) + mycolors.reset)
                            else:
                                print(mycolors.foreground.yellow + " " * 2 + "URL not provided".center(80) + mycolors.reset)

                    else:
                        if(w['url_status'] == 'online'):
                            print(mycolors.foreground.green + mycolors.reverse + w['url_status'] + " " + mycolors.reset, end=' ')
                        if(w['url_status'] == 'offline'):
                            print(mycolors.foreground.red + mycolors.reverse + w['url_status'] + mycolors.reset, end=' ')
                        if(w['url_status'] == ''):
                            print(mycolors.foreground.cyan +  mycolors.reverse + "unknown" + mycolors.reset, end=' ')
                        if (w['url']):
                            if (w['dateadded']):
                                print(mycolors.foreground.purple + " " * 2 + (w['dateadded']).ljust(22) + mycolors.reset, end=' ')
                            else:
                                print(mycolors.foreground.purple + " " * 2 + "not provided".center(17) + mycolors.reset, end=' ')
                            if (w['threat']):
                                print(mycolors.foreground.blue + (w['threat']).ljust(17) + mycolors.reset, end=' ')
                            else:
                                print(mycolors.foreground.blue + "not provided".center(22) + mycolors.reset, end=' ')
                            if (w['url']):
                                print(mycolors.foreground.red + " " * 2 + (w['url']).ljust(80) + mycolors.reset)
                            else:
                                print(mycolors.foreground.red + " " * 2 + "URL not provided".center(80) + mycolors.reset, end=' ')

        print(mycolors.reset)

    except (BrokenPipeError, IOError, TypeError):
        print(mycolors.reset , file=sys.stderr)
        exit(1)

    except ValueError as e:
        print(e)
        if (bkg == 1):
            print((mycolors.foreground.lightred + "Error while connecting to URLhaus!\n"))
        else:
            print((mycolors.foreground.lightred + "Error while connecting to URLhaus!\n"))
        print(mycolors.reset)


def haussample(hashx, haus):

        hatext = ''
        response = ''
        finalurl = ''

        try:

            resource = hashx 
            requestsession = requests.Session( )
            requestsession.headers.update({'accept': 'application/gzip'})
            finalurl = ''.join([haus, resource])
            response = requestsession.get(url=finalurl, allow_redirects=True)
            hatext = response.text

            rc = str(hatext)
            if 'not_found' in rc:
                final = 'Malware sample is not available to download.'
                if (bkg == 1):
                    print((mycolors.foreground.lightred + "\n" + final + "\n" + mycolors.reset))
                else:
                    print((mycolors.foreground.red + "\n" + final + "\n" + mycolors.reset))
                exit(1)
            if 'copy_error' in rc:
                final = 'It has occured an error while downloading.'
                if (bkg == 1):
                    print((mycolors.foreground.lightred + "\n" + final + "\n" + mycolors.reset))
                else:
                    print((mycolors.foreground.red + "\n" + final + "\n" + mycolors.reset))
                exit(1)

            open(resource + '.zip', 'wb').write(response.content)
            final = '\nSAMPLE SAVED!'

            if (bkg == 1):
                print((mycolors.foreground.yellow + final + "\n"))
            else:
                print((mycolors.foreground.green + final + "\n"))

        except (BrokenPipeError, IOError, TypeError):
            print(mycolors.reset , file=sys.stderr)
            exit(1)

        except ValueError as e:
            print(e)
            if (bkg == 1):
                print((mycolors.foreground.lightred + "Error while connecting to URLhaus!\n"))
            else:
                print((mycolors.foreground.red + "Error while connecting to URLhaus!\n"))
            print(mycolors.reset)

        print(mycolors.reset)
        exit(0)


def hausgetbatch(haus):

    haustext = ''
    hausresponse = ''
    nurl = 0
    alltags = ''
    l = 0

    try:
        
        print("\n")
        print((mycolors.reset + "URLhaus Recent Malicious URLs".center(104)), end='')
        print((mycolors.reset + "".center(28)), end='')
        print("\n" + (126*'-').center(59))

        requestsession7 = requests.Session( )
        requestsession7.headers.update({'accept': 'application/json'})
        hausresponse = requestsession7.get(haus)
        haustext = json.loads(hausresponse.text)
        nurl = len(haustext['urls'])
        
        if (nurl > 0):
            try:
                for i in range(0,nurl):
                    if 'url' in haustext['urls'][i]:
                        if (bkg == 1):
                            if(haustext['urls'][i].get('url_status') == 'online'):
                                print(mycolors.foreground.lightgreen + haustext['urls'][i].get('url_status') + " " + mycolors.reset, end=' ')
                            if(haustext['urls'][i].get('url_status') == 'offline'):
                                print(mycolors.foreground.lightred + haustext['urls'][i].get('url_status') + mycolors.reset, end=' ')
                            if(haustext['urls'][i].get('url_status')  == ''):
                                print(mycolors.foreground.lightblue + "unknown" + mycolors.reset, end=' ')
                            if 'tags' in haustext['urls'][i]:
                                print(mycolors.foreground.yellow, end='')
                                if haustext['urls'][i].get('tags') is not None:
                                    alltags = haustext['urls'][i].get('tags')
                                    for t in alltags:
                                        print("%s" % t, end=' ')
                                        l += len(t)
                                    print(" " * ((28 - l) - len(alltags)) , end=' ')
                                else:
                                    print(" " * 28, end=' ')
                            print(mycolors.reset + ("\n".ljust(38)).join(textwrap.wrap((haustext['urls'][i].get('url')).ljust(14), width=90)), end='\n')
                            l = 0
                        else:
                            if(haustext['urls'][i].get('url_status') == 'online'):
                                print(mycolors.foreground.green + haustext['urls'][i].get('url_status') + " " + mycolors.reset, end=' ')
                            if(haustext['urls'][i].get('url_status') == 'offline'):
                                print(mycolors.foreground.red + haustext['urls'][i].get('url_status') + mycolors.reset, end=' ')
                            if(haustext['urls'][i].get('url_status') == ''):
                                print(mycolors.foreground.cyan + "unknown" + mycolors.reset, end=' ')
                            if 'tags' in haustext['urls'][i]:
                                print(mycolors.foreground.blue, end='')
                                if haustext['urls'][i].get('tags') is not None:
                                    alltags = haustext['urls'][i].get('tags')
                                    for t in alltags:
                                        print("%s" % t, end=' ')
                                        l += len(t)
                                    print(" " * ((28 - l) - len(alltags)) , end=' ')
                                else:
                                    print(" " * 28, end=' ')
                            print(mycolors.reset + ("\n".ljust(38)).join(textwrap.wrap((haustext['urls'][i].get('url')).ljust(14), width=90)), end='\n')
                            l = 0

                print(mycolors.reset , file=sys.stderr)

            except KeyError as e:
                pass

            except (BrokenPipeError, IOError, TypeError):
                print(mycolors.reset , file=sys.stderr)

        print(mycolors.reset)

    except KeyError as e:
        pass

    except (BrokenPipeError, IOError, TypeError):
        print(mycolors.reset)
        exit(1)

    except ValueError as e:
        print(e)
        if (bkg == 1):
            print((mycolors.foreground.lightred + "Error while connecting to URLhaus!\n"))
        else:
            print((mycolors.foreground.red + "Error while connecting to URLhaus!\n"))
        print(mycolors.reset)


def hauspayloadslist(haus):

    haustext = ''
    hausresponse = ''
    npayloads = 0

    try:

        print("\n")
        print((mycolors.reset + "Haus Downloadable Links to Recent Payloads".center(146)), end='')
        print((mycolors.reset + "".center(28)), end='')
        print("\n" + (146*'-').center(59))

        requestsession8 = requests.Session( )
        requestsession8.headers.update({'accept': 'application/json'})
        hausresponse = requestsession8.get(haus)
        haustext = json.loads(hausresponse.text)
        npayloads = len(haustext['payloads'])

        if (npayloads > 0):
            try:
                for i in range(0,npayloads):
                    if 'sha256_hash' in haustext['payloads'][i]:
                        if (bkg == 1):
                            print(mycolors.foreground.lightred + "%-8s" % haustext['payloads'][i].get('file_type'), end=' ')
                            print(mycolors.foreground.lightgreen + haustext['payloads'][i].get('firstseen'), end=" ")
                            results = haustext['payloads'][i]['virustotal']
                            if (results) is not None:
                                print(mycolors.foreground.yellow + (results['result']).center(9), end=' ')
                            else:
                                print(mycolors.foreground.yellow + "Not Found", end=' ')
                            print(mycolors.foreground.lightcyan + haustext['payloads'][i].get('urlhaus_download'))
                        else:
                            print(mycolors.foreground.red + "%-8s" % haustext['payloads'][i].get('file_type'), end=' ')
                            print(mycolors.foreground.green + haustext['payloads'][i].get('firstseen'), end=" ")
                            results = haustext['payloads'][i]['virustotal']
                            if (results) is not None:
                                print(mycolors.foreground.purple + (results['result']).center(9), end=' ')
                            else:
                                print(mycolors.foreground.purple + "Not Found", end=' ')
                            print(mycolors.foreground.blue + haustext['payloads'][i].get('urlhaus_download'))

                print(mycolors.reset , file=sys.stderr)

            except KeyError as e:
                pass

            except (BrokenPipeError, IOError, TypeError):
                print(mycolors.reset , file=sys.stderr)

        print(mycolors.reset , file=sys.stderr)

    except KeyError as e:
        pass

    except (BrokenPipeError, IOError, TypeError):
        print(mycolors.reset , file=sys.stderr)
        exit(1)

    except ValueError as e:
        print(e)
        if (bkg == 1):
            print((mycolors.foreground.lightred + "Error while connecting to URLhaus!\n"))
        else:
            print((mycolors.foreground.red + "Error while connecting to URLhaus!\n"))
        print(mycolors.reset)


def urlhauspost(urlx, haus, mytags):

    haustext = ''
    hausresponse = ''
    finalurl6 = ''

    try:

        print("\n")
        print((mycolors.reset + "URLhaus Submission Report".center(100)), end='')
        print((mycolors.reset + "".center(28)), end='')
        print("\n" + (100*'-').center(40))

        postdata = { 
                'token' : HAUSSUBMITAPI,
                'anonymous': '0',
                'submission' : [
                    {
                        'url' : urlx,
                        'threat' : "malware_download",
                        'tags': mytags  
                    }
                ]
            }

        requestsession6 = requests.Session()
        requestsession6.headers.update({'Content-Type': 'application/json'})
        requestsession6.headers.update({'user-agent': 'URLhaus Malwoverview'})
        params = {"url": urlx}
        hausresponse = requests.post(haus, json=postdata, timeout=15)
        if(bkg == 1):
            print(mycolors.foreground.lightgreen + "URLhaus Submission Status: " + hausresponse.text)
        else:
            print(mycolors.foreground.red + "URLhaus Submission Status: " + hausresponse.text)

        print(mycolors.reset , file=sys.stderr)
        exit(1)

    except KeyError as e:
        pass

    except (BrokenPipeError, IOError, TypeError):

        print(mycolors.reset , file=sys.stderr)
        exit(1)

    except ValueError as e:
        print(e)
        if (bkg == 1):
            print((mycolors.foreground.lightred + "Error while connecting to URLhaus!\n"))
        else:
            print((mycolors.foreground.red + "Error while connecting to URLhaus!\n"))
        print(mycolors.reset)


def alien_subscribed(url, arg1):

    hatext = ''
    haresponse = ''
    history = arg1
    user_agent = {'X-OTX-API-KEY': ALIENAPI}
    search_params = {'limit': history}
    myargs = arg1

    try:

        resource = url
        requestsession = requests.Session( )
        requestsession.headers.update({'Content-Type': 'application/json'})
        finalurl = '/'.join([resource,'pulses', 'subscribed'])
        haresponse = requestsession.post(url=finalurl, headers=user_agent, params=search_params)
        hatext = json.loads(haresponse.text)
        rc = str(hatext)

        if(bkg == 1):
            if 'results' in hatext:
                x = 0
                c = 1
                for d in hatext['results']:
                    print(mycolors.reset)
                    print(mycolors.foreground.cyan + "INFORMATION: %d" % c)
                    print(mycolors.reset + '-' * 15 + "\n")
                    if d['name']:
                        print(mycolors.foreground.yellow + "Headline:".ljust(13) + mycolors.reset + hatext['results'][x]['name'], end='\n')
                    if d['description']:
                        print(mycolors.foreground.yellow + "Description:" + "\n".ljust(14) + mycolors.reset + ("\n".ljust(14)).join(textwrap.wrap((hatext['results'][x]['description']).ljust(14), width=90)), end='\n')
                    if hatext['results'][x]['references']:
                        for r in hatext['results'][x]['references']:
                            print(mycolors.foreground.yellow + "\nReferences: ".ljust(14) + mycolors.reset + ("\n".ljust(14)).join(textwrap.wrap(r,width=100)), end='')
                    if hatext['results'][x]['tags']:
                        if (hatext['results'][x]['tags']):
                            print(mycolors.foreground.yellow + "\nTags:".ljust(13) + mycolors.reset, end=' ')
                            b = 0
                            for z in hatext['results'][x]['tags']:
                                b = b + 1
                                if ((b % 5) == 0):
                                    print(mycolors.reset + z, end='\n'.ljust(14))
                                else:
                                    print(mycolors.reset + z, end=' ')
                                if (b == (len(hatext['results'][x]['tags']))):
                                    print(mycolors.reset + z, end='\n')

                    if hatext['results'][x]['industries']:
                        print(mycolors.foreground.yellow + "\nIndustries: ".ljust(14), end='')
                        for r in hatext['results'][x]['industries']:
                            print(mycolors.reset + ("\n".ljust(14)).join(textwrap.wrap(r,width=100)), end='\n'.ljust(14))
                    if hatext['results'][x]['created']:
                        print(mycolors.foreground.yellow + "\nCreated: ".ljust(14) + mycolors.reset + hatext['results'][x]['created'], end='')
                    if hatext['results'][x]['modified']:
                        print(mycolors.foreground.yellow + "\nModified: ".ljust(14) + mycolors.reset + hatext['results'][x]['modified'], end='')
                    if hatext['results'][x]['malware_families']:
                        print(mycolors.foreground.yellow + "\nFamily: ".ljust(14), end='')
                        for r in hatext['results'][x]['malware_families']:
                            print(mycolors.reset + r, end=' ')
                    if hatext['results'][x]['adversary']:
                        print(mycolors.foreground.yellow + "\nAdversary: ".ljust(14) + mycolors.reset + hatext['results'][x]['adversary'], end='')
                    if hatext['results'][x]['targeted_countries']:
                        print(mycolors.foreground.yellow + "\nTargets: ".ljust(14), end='')
                        for r in hatext['results'][x]['targeted_countries']:
                            print(mycolors.reset + r, end=' ')
                    if hatext['results'][x]['indicators']:
                        limit = 0
                        print("\n")
                        for r in hatext['results'][x]['indicators']:
                            if r['indicator']:
                                print(mycolors.foreground.yellow + "Indicator: ".ljust(13) + mycolors.reset + r['indicator'].ljust(64), end='\t')
                                print(mycolors.foreground.yellow + "Title: " + mycolors.reset + r['title'], end='\n')
                                limit = limit + 1
                            if (limit > 9):
                                break
                    x = x + 1
                    c = c + 1

        else:
            if 'results' in hatext:
                x = 0
                c = 1
                for d in hatext['results']:
                    print(mycolors.reset)
                    print(mycolors.foreground.purple + "INFORMATION: %d" % c)
                    print(mycolors.reset + '-' * 15 + "\n")
                    if d['name']:
                        print(mycolors.foreground.blue + "Headline:".ljust(13) + mycolors.reset + hatext['results'][x]['name'], end='\n')
                    if d['description']:
                        print(mycolors.foreground.blue + "Description:" + "\n".ljust(14) + mycolors.reset + ("\n".ljust(14)).join(textwrap.wrap((hatext['results'][x]['description']).ljust(14), width=90)), end='\n')
                    if hatext['results'][x]['references']:
                        for r in hatext['results'][x]['references']:
                            print(mycolors.foreground.blue + "\nReferences: ".ljust(14) + mycolors.reset + ("\n".ljust(14)).join(textwrap.wrap(r,width=100)), end='')
                    if hatext['results'][x]['tags']:
                        print(mycolors.foreground.blue + "\nTags:".ljust(13) + mycolors.reset, end=' ')
                        b = 0
                        for z in hatext['results'][x]['tags']:
                            b = b + 1
                            if ((b % 5) == 0):
                                print(mycolors.reset + z, end='\n'.ljust(14))
                            else:
                                print(mycolors.reset + z, end=' ')
                            if (b == (len(hatext['results'][x]['tags']))):
                                print(mycolors.reset + z, end='\n')

                    if hatext['results'][x]['industries']:
                        print(mycolors.foreground.blue + "\nIndustries: ".ljust(14), end='')
                        for r in hatext['results'][x]['industries']:
                            print(mycolors.reset + ("\n".ljust(14)).join(textwrap.wrap(r,width=100)), end='\n'.ljust(14))
                    if hatext['results'][x]['created']:
                        print(mycolors.foreground.blue + "\nCreated: ".ljust(14) + mycolors.reset + hatext['results'][x]['created'], end='')
                    if hatext['results'][x]['modified']:
                        print(mycolors.foreground.blue + "\nModified: ".ljust(14) + mycolors.reset + hatext['results'][x]['modified'], end='')
                    if hatext['results'][x]['malware_families']:
                        print(mycolors.foreground.blue + "\nFamily: ".ljust(14), end='')
                        for r in hatext['results'][x]['malware_families']:
                            print(mycolors.reset + r, end=' ')
                    if hatext['results'][x]['adversary']:
                        print(mycolors.foreground.blue + "\nAdversary: ".ljust(14) + mycolors.reset + hatext['results'][x]['adversary'], end='')
                    if hatext['results'][x]['targeted_countries']:
                        print(mycolors.foreground.blue + "\nTargets: ".ljust(14), end='')
                        for r in hatext['results'][x]['targeted_countries']:
                            print(mycolors.reset + r, end=' ')
                    if hatext['results'][x]['indicators']:
                        limit = 0
                        print("\n")
                        for r in hatext['results'][x]['indicators']:
                            if r['indicator']:
                                print(mycolors.foreground.blue + "Indicator: ".ljust(13) + mycolors.reset + r['indicator'].ljust(64), end='\t')
                                print(mycolors.foreground.blue + "Title: " + mycolors.reset + r['title'], end='\n')
                                limit = limit + 1
                            if (limit > 9):
                                break
                    x = x + 1
                    c = c + 1

    except ValueError as e:
        print(e)
        if (bkg == 1):
            print((mycolors.foreground.lightred + "Error while connecting to Alien Vault!\n"))
        else:
            print((mycolors.foreground.red + "Error while connecting to Alien Vault!\n"))
        print(mycolors.reset)


def alien_ipv4(url, arg1):

    hatext = ''
    haresponse = ''
    history = '10'
    user_agent = {'X-OTX-API-KEY': ALIENAPI}
    search_params = {'limit': history}
    myargs = arg1

    try:

        resource = url
        requestsession = requests.Session( )
        requestsession.headers.update({'Content-Type': 'application/json'})
        finalurl = '/'.join([resource,'indicators', 'IPv4', myargs])
        haresponse = requestsession.post(url=finalurl, headers=user_agent, params=search_params)
        hatext = json.loads(haresponse.text)

        if(bkg == 1):
            if 'sections' in hatext:
                print(mycolors.reset)
                if hatext['asn']:
                    print(mycolors.foreground.lightgreen + "ASN:".ljust(13) + mycolors.reset + hatext['asn'], end='\n')
                if hatext['city']:
                    print(mycolors.foreground.lightgreen + "City:".ljust(13) + mycolors.reset + hatext['city'], end='\n')
                if hatext['country_name']:
                    print(mycolors.foreground.lightgreen + "Country:".ljust(13) + mycolors.reset + hatext['country_name'], end='\n')
                if hatext['pulse_info']:
                    if 'count' in (hatext['pulse_info']):
                        if ((hatext['pulse_info']['count']) == 0):
                            print(mycolors.foreground.red + "\nNo further information about the provided IP address!\n" + mycolors.reset)
                            exit(0)
                    z = 0
                    i = 0
                    for key in hatext['pulse_info']:
                        if (isinstance(hatext['pulse_info'][key], list)):
                            while i < len(hatext['pulse_info'][key]):
                                if(isinstance(hatext['pulse_info'][key][i], dict)):
                                    if 'malware_families' in hatext['pulse_info'][key][i]:
                                        print(mycolors.foreground.lightgreen + "\nMalware:".ljust(13) + mycolors.reset)
                                        for z in hatext['pulse_info'][key][i]['malware_families']:
                                            print("".ljust(13) + z['display_name'])
                                    if 'tags' in hatext['pulse_info'][key][i]:
                                        print(mycolors.foreground.lightgreen + "Tags:".ljust(12) + mycolors.reset, end=' ')
                                        if (hatext['pulse_info'][key][i]['tags']):
                                            b = 0
                                            for z in hatext['pulse_info'][key][i]['tags']:
                                                b = b + 1
                                                if ((b % 5) == 0):
                                                    print(mycolors.reset + z, end='\n'.ljust(14))
                                                else:
                                                    print(mycolors.reset + z, end=' ')
                                                if (b == (len(hatext['pulse_info'][key][i]['tags']))):
                                                    print(mycolors.reset + z, end='\n')
                                i = i + 1
                if hatext['pulse_info']:
                    if hatext['pulse_info']['pulses']:
                        i = 0
                        while (i < len(hatext['pulse_info']['pulses'])):
                            if "modified" in (hatext['pulse_info']['pulses'][i]):
                                print(mycolors.foreground.lightgreen + "\nModified:".ljust(14) + mycolors.reset + (hatext['pulse_info']['pulses'][i]['modified']), end='')
                            if "name" in (hatext['pulse_info']['pulses'][i]):
                                print(mycolors.foreground.lightgreen + "\nNews:".ljust(14) + mycolors.reset + (hatext['pulse_info']['pulses'][i]['name']), end='')
                            if "created" in (hatext['pulse_info']['pulses'][i]):
                                print(mycolors.foreground.lightgreen + "\nCreated:".ljust(14) + mycolors.reset + (hatext['pulse_info']['pulses'][i]['created']), end='')
                                break
                            else:
                                i = i + i

                        k = 0
                        print(mycolors.foreground.lightgreen + "\n\nDescription:" + mycolors.reset, end='')
                        while (k < len(hatext['pulse_info']['pulses'])):
                            for key in hatext['pulse_info']['pulses'][k]:
                                if (key == 'description'):
                                    if (hatext['pulse_info']['pulses'][k]['description']):
                                        print("\n".ljust(14) + mycolors.reset + ("\n".ljust(14)).join(textwrap.wrap(hatext['pulse_info']['pulses'][k]['description'],width=100)), end='\n')
                                        break
                            k = k + 1

                if hatext['pulse_info']:
                    if hatext['pulse_info']['references']:
                        print(mycolors.foreground.lightgreen + "\nReferences: ".ljust(14) + mycolors.reset, end=' ')
                        for r in hatext['pulse_info']['references']:
                            print("\n".ljust(14) + mycolors.reset + ("\n".ljust(14)).join(textwrap.wrap(r,width=100)), end='\n')
        else:
            if 'sections' in hatext:
                print(mycolors.reset + "\n\n" + "ALIEN VAULT IPv4 REPORT".center(120))
                print(mycolors.reset)
                print(mycolors.reset + '-' * 120 + "\n")
                if hatext['asn']:
                    print(mycolors.foreground.green + "ASN:".ljust(13) + mycolors.reset + hatext['asn'], end='\n')
                if hatext['city']:
                    print(mycolors.foreground.green + "City:".ljust(13) + mycolors.reset + hatext['city'], end='\n')
                if hatext['country_name']:
                    print(mycolors.foreground.green + "Country:".ljust(13) + mycolors.reset + hatext['country_name'], end='\n')
                if hatext['pulse_info']:
                    if 'count' in (hatext['pulse_info']):
                        if ((hatext['pulse_info']['count']) == 0):
                            print(mycolors.foreground.red + "\nNo further information about the provided IP address!\n" + mycolors.reset)
                            exit(0)
                    z = 0
                    i = 0
                    for key in hatext['pulse_info']:
                        if (isinstance(hatext['pulse_info'][key], list)):
                            while i < len(hatext['pulse_info'][key]):
                                if(isinstance(hatext['pulse_info'][key][i], dict)):
                                    print(mycolors.foreground.green + "\nMalware:".ljust(13) + mycolors.reset, end='')
                                    if 'malware_families' in hatext['pulse_info'][key][i]:
                                        for z in hatext['pulse_info'][key][i]['malware_families']:
                                            print("\n".ljust(14) + z['display_name'], end='')
                                    print(mycolors.foreground.green + "\nTags:".ljust(13) + mycolors.reset, end=' ')
                                    if 'tags' in hatext['pulse_info'][key][i]:
                                        b = 0
                                        for z in hatext['pulse_info'][key][i]['tags']:
                                            b = b + 1
                                            if ((b % 5) == 0):
                                                print(mycolors.reset + z, end='\n'.ljust(14))
                                            else:
                                                print(mycolors.reset + z, end=' ')
                                            if (b == (len(hatext['pulse_info'][key][i]['tags']))):
                                                print(mycolors.reset + z, end='\n')
                                i = i + 1
                if hatext['pulse_info']:
                    if hatext['pulse_info']['pulses']:
                        i = 0
                        while (i < len(hatext['pulse_info']['pulses'])):
                            if "modified" in (hatext['pulse_info']['pulses'][i]):
                                print(mycolors.foreground.green + "\nModified:".ljust(14) + mycolors.reset + (hatext['pulse_info']['pulses'][i]['modified']), end='')
                            if "name" in (hatext['pulse_info']['pulses'][i]):
                                print(mycolors.foreground.green + "\nNews:".ljust(14) + mycolors.reset + (hatext['pulse_info']['pulses'][i]['name']), end='')
                            if "created" in (hatext['pulse_info']['pulses'][i]):
                                print(mycolors.foreground.green + "\nCreated:".ljust(14) + mycolors.reset + (hatext['pulse_info']['pulses'][i]['created']), end='')
                                break
                            else:
                                i = i + i

                        k = 0
                        print(mycolors.foreground.green + "\n\nDescription:" + "\n".ljust(14) + mycolors.reset, end='')
                        while (k < len(hatext['pulse_info']['pulses'])):
                            for key in hatext['pulse_info']['pulses'][k]:
                                if (key == 'description'):
                                    if (hatext['pulse_info']['pulses'][k]['description']):
                                        print("\n".ljust(14) + mycolors.reset + ("\n".ljust(14)).join(textwrap.wrap(hatext['pulse_info']['pulses'][k]['description'],width=100)), end='\n')
                                        break
                            k = k + 1

                if hatext['pulse_info']:
                    if hatext['pulse_info']['references']:
                        print(mycolors.foreground.green + "\n\nReferences: ".ljust(14) + mycolors.reset, end='')
                        for r in hatext['pulse_info']['references']:
                            print("\n".ljust(14) + mycolors.reset + ("\n".ljust(14)).join(textwrap.wrap(r,width=100)), end='\n')

    except ValueError as e:
        print(e)
        if (bkg == 1):
            print((mycolors.foreground.lightred + "Error while connecting to Alien Vault!\n"))
        else:
            print((mycolors.foreground.red + "Error while connecting to Alien Vault!\n"))
        print(mycolors.reset)


def alien_domain(url, arg1):

    hatext = ''
    haresponse = ''
    history = '10'
    user_agent = {'X-OTX-API-KEY': ALIENAPI}
    search_params = {'limit': history}
    myargs = arg1

    try:

        resource = url
        requestsession = requests.Session( )
        requestsession.headers.update({'Content-Type': 'application/json'})
        finalurl = '/'.join([resource,'indicators', 'domain', myargs])
        haresponse = requestsession.post(url=finalurl, headers=user_agent, params=search_params)
        hatext = json.loads(haresponse.text)

        if(bkg == 1):
            if 'indicator' in hatext:
                print(mycolors.reset)
                if hatext['alexa']:
                    print(mycolors.foreground.yellow + "Alexa:".ljust(13) + mycolors.reset + hatext['alexa'], end='\n')
                if hatext['pulse_info']:
                    if 'count' in (hatext['pulse_info']):
                        if ((hatext['pulse_info']['count']) == 0):
                            print(mycolors.foreground.red + "\nNot further information about the provided DOMAIN!\n" + mycolors.reset)
                            exit(0)
                    if hatext['pulse_info']['pulses']:
                        i = 0
                        while (i < len(hatext['pulse_info']['pulses'])):
                            if "tags" in (hatext['pulse_info']['pulses'][i]):
                                print(mycolors.foreground.yellow + "Tags:".ljust(13), end='')
                                for j in hatext['pulse_info']['pulses'][i]['tags']:
                                    print(mycolors.reset + j, end=' ')
                            if 'malware_families' in hatext['pulse_info']['pulses'][i]:
                                print(mycolors.foreground.yellow + "\nMalware:".ljust(14) + mycolors.reset, end='')
                                for z in hatext['pulse_info']['pulses'][i]['malware_families']:
                                    print(mycolors.reset + z['display_name'], end=' ')
                            if 'targeted_countries' in hatext['pulse_info']['pulses'][i]:
                                print(mycolors.foreground.yellow + "\nCountries:".ljust(14), end='')
                                for z in hatext['pulse_info']['pulses'][i]['targeted_countries']:
                                    print(mycolors.reset + z, end=' ')
                            if 'name' in hatext['pulse_info']['pulses'][i]:
                                if hatext['pulse_info']['pulses'][i]['name']:
                                    print(mycolors.foreground.yellow + "\nNews:".ljust(14) + mycolors.reset + hatext['pulse_info']['pulses'][i]['name'], end='')
                            if 'attack_ids' in hatext['pulse_info']['pulses'][i]:
                                if hatext['pulse_info']['pulses'][i]['attack_ids']:
                                    for k in hatext['pulse_info']['pulses'][i]['attack_ids']:
                                        print(mycolors.foreground.yellow + "\nAttack IDs:".ljust(14) + mycolors.reset + str(k['display_name']), end='')
                                break
                            i = i + i

                    print(mycolors.foreground.yellow + "\nDescription:", end=' ')
                    for x in hatext['pulse_info']['pulses']:
                        if (isinstance(x, dict)):
                            for y in x:
                                if 'description' in y:
                                    if (x['description']):
                                        print("\n".ljust(13),end=' ')
                                        print(mycolors.reset + ("\n".ljust(14)).join(textwrap.wrap(x['description'],width=100)), end='\n')
                if hatext['pulse_info']:
                    if hatext['pulse_info']['references']:
                        print("\n")
                        for r in hatext['pulse_info']['references']:
                            print(mycolors.foreground.yellow + "\nReferences: ".ljust(14) + mycolors.reset + ("\n".ljust(14)).join(textwrap.wrap(r,width=100)), end='')

        else:
            if 'indicator' in hatext:
                print(mycolors.reset)
                if hatext['alexa']:
                    print(mycolors.foreground.purple + "Alexa:".ljust(13) + mycolors.reset + hatext['alexa'], end='\n')
                if hatext['pulse_info']:
                    if 'count' in (hatext['pulse_info']):
                        if ((hatext['pulse_info']['count']) == 0):
                            print(mycolors.foreground.red + "\nNo further information about the provided DOMAIN!\n" + mycolors.reset)
                            exit(0)
                    if hatext['pulse_info']['pulses']:
                        i = 0
                        while (i < len(hatext['pulse_info']['pulses'])):
                            if "tags" in (hatext['pulse_info']['pulses'][i]):
                                print(mycolors.foreground.purple + "Tags:".ljust(13), end='')
                                for j in hatext['pulse_info']['pulses'][i]['tags']:
                                    print(mycolors.reset + j, end=' ')
                            if 'malware_families' in hatext['pulse_info']['pulses'][i]:
                                print(mycolors.foreground.purple + "\nMalware:".ljust(14) + mycolors.reset, end='')
                                for z in hatext['pulse_info']['pulses'][i]['malware_families']:
                                    print(mycolors.reset + z['display_name'], end=' ')
                            if 'targeted_countries' in hatext['pulse_info']['pulses'][i]:
                                print(mycolors.foreground.purple + "\nCountries:".ljust(14), end='')
                                for z in hatext['pulse_info']['pulses'][i]['targeted_countries']:
                                    print(mycolors.reset + z, end=' ')
                            if 'name' in hatext['pulse_info']['pulses'][i]:
                                if hatext['pulse_info']['pulses'][i]['name']:
                                    print(mycolors.foreground.purple + "\nNews:".ljust(14) + mycolors.reset + hatext['pulse_info']['pulses'][i]['name'], end='')
                            if 'attack_ids' in hatext['pulse_info']['pulses'][i]:
                                if hatext['pulse_info']['pulses'][i]['attack_ids']:
                                    for k in hatext['pulse_info']['pulses'][i]['attack_ids']:
                                        print(mycolors.foreground.purple + "\nAttack IDs:".ljust(14) + mycolors.reset + str(k['display_name']), end='')
                                break
                            i = i + i

                    print(mycolors.foreground.purple + "\nDescription:", end=' ')
                    for x in hatext['pulse_info']['pulses']:
                        if (isinstance(x, dict)):
                            for y in x:
                                if 'description' in y:
                                    if (x['description']):
                                        print("\n".ljust(13),end=' ')
                                        print(mycolors.reset + ("\n".ljust(14)).join(textwrap.wrap(x['description'],width=100)), end='\n')
                if hatext['pulse_info']:
                    if hatext['pulse_info']['references']:
                        print("\n")
                        for r in hatext['pulse_info']['references']:
                            print(mycolors.foreground.purple + "\nReferences: ".ljust(14) + mycolors.reset + ("\n".ljust(14)).join(textwrap.wrap(r,width=100)), end='')

    except ValueError as e:
        print(e)
        if (bkg == 1):
            print((mycolors.foreground.lightred + "Error while connecting to Alien Vault!\n"))
        else:
            print((mycolors.foreground.red + "Error while connecting to Alien Vault!\n"))
        print(mycolors.reset)


def alien_hash(url, arg1):

    hatext = ''
    haresponse = ''
    history = '10'
    user_agent = {'X-OTX-API-KEY': ALIENAPI}
    search_params = {'limit': history}
    myargs = arg1

    try:

        resource = url
        requestsession = requests.Session( )
        requestsession.headers.update({'Content-Type': 'application/json'})
        finalurl = '/'.join([resource,'indicators', 'file', myargs])
        haresponse = requestsession.post(url=finalurl, headers=user_agent, params=search_params)
        hatext = json.loads(haresponse.text)

        if(bkg == 1):
            if 'indicator' in hatext:
                print(mycolors.reset)
                if hatext['pulse_info']:
                    if 'count' in (hatext['pulse_info']):
                        if ((hatext['pulse_info']['count']) == 0):
                            print(mycolors.foreground.red + "\nNo further information about the provided HASH!\n" + mycolors.reset)
                            exit(0)
                    i = 0
                    if 'pulses' in (hatext['pulse_info']):
                        while (i < len(hatext['pulse_info']['pulses'])):
                            if "tags" in (hatext['pulse_info']['pulses'][i]):
                                if (hatext['pulse_info']['pulses'][i]['tags']):
                                    print(mycolors.foreground.lightcyan + "\nTags:".ljust(13), end='')
                                    b = 0
                                    for j in hatext['pulse_info']['pulses'][i]['tags']:
                                        b = b + 1
                                        if ((b % 5) == 0):
                                            print(mycolors.reset + j, end='\n'.ljust(13))
                                        else:
                                            print(mycolors.reset + j, end=' ')
                                        if (b == (len(hatext['pulse_info']['pulses'][i]['tags']))):
                                            print(mycolors.reset + j, end='\n')

                            if 'malware_families' in hatext['pulse_info']['pulses'][i]:
                                if hatext['pulse_info']['pulses'][i]['malware_families']:
                                    print(mycolors.foreground.lightcyan + "\nMalware:".ljust(13) + mycolors.reset, end='')
                                    for z in hatext['pulse_info']['pulses'][i]['malware_families']:
                                        print(mycolors.reset + z['display_name'], end=' ')
                            if 'created' in hatext['pulse_info']['pulses'][i]:
                                if hatext['pulse_info']['pulses'][i]['created']:
                                    print(mycolors.foreground.lightcyan + "\nCreated:".ljust(13) + mycolors.reset, end='')
                                    print(mycolors.reset + hatext['pulse_info']['pulses'][i]['created'], end=' ')
                            if 'modified' in hatext['pulse_info']['pulses'][i]:
                                if hatext['pulse_info']['pulses'][i]['modified']:
                                    print(mycolors.foreground.lightcyan + "\nModified:".ljust(13) + mycolors.reset, end='')
                                    print(mycolors.reset + hatext['pulse_info']['pulses'][i]['modified'], end=' ')
                            if 'targeted_countries' in hatext['pulse_info']['pulses'][i]:
                                if hatext['pulse_info']['pulses'][i]['targeted_countries']:
                                    print(mycolors.foreground.lightcyan + "\nCountries:".ljust(13), end='')
                                    for z in hatext['pulse_info']['pulses'][i]['targeted_countries']:
                                        print(mycolors.reset + z, end=' ')
                            if 'attack_ids' in hatext['pulse_info']['pulses'][i]:
                                if hatext['pulse_info']['pulses'][i]['attack_ids']:
                                    for k in hatext['pulse_info']['pulses'][i]['attack_ids']:
                                        print(mycolors.foreground.lightcyan + "\nAttack IDs:".ljust(13) + mycolors.reset + str(k['display_name']), end='')
                            if 'name' in hatext['pulse_info']['pulses'][i]:
                                if hatext['pulse_info']['pulses'][i]['name']:
                                    print(mycolors.foreground.lightcyan + "\nNews:".ljust(13) + mycolors.reset + hatext['pulse_info']['pulses'][i]['name'], end='')
                                break
                            i = i + 1
                    
                    print(mycolors.foreground.lightcyan + "\nDescription:", end='')
                    for x in hatext['pulse_info']['pulses']:
                        if (isinstance(x, dict)):
                            for y in x:
                                if 'description' in y:
                                    if (x['description']):
                                        print("\n".ljust(13),end='')
                                        print(mycolors.reset + ("\n".ljust(13)).join(textwrap.wrap(x['description'],width=100)), end='\n')
                    
                    if "references" in (hatext['pulse_info']):
                        for j in hatext['pulse_info']['references']:
                            print(mycolors.foreground.lightcyan + "\nReferences: ".ljust(13) + mycolors.reset + ("\n".ljust(13)).join(textwrap.wrap(j,width=100)), end='')
                    print("\n")
        else:
            if 'indicator' in hatext:
                print(mycolors.reset)
                if hatext['pulse_info']:
                    if 'count' in (hatext['pulse_info']):
                        if ((hatext['pulse_info']['count']) == 0):
                            print(mycolors.foreground.red + "\nNo further information about the provided HASH!\n" + mycolors.reset)
                            exit(0)
                    i = 0
                    if 'pulses' in (hatext['pulse_info']):
                        while (i < len(hatext['pulse_info']['pulses'])):
                            if "tags" in (hatext['pulse_info']['pulses'][i]):
                                if (hatext['pulse_info']['pulses'][i]['tags']):
                                    print(mycolors.foreground.cyan + "\nTags:".ljust(13), end='')
                                    b = 0
                                    for j in hatext['pulse_info']['pulses'][i]['tags']:
                                        b = b + 1
                                        if ((b % 5) == 0):
                                            print(mycolors.reset + j, end='\n'.ljust(13))
                                        else:
                                            print(mycolors.reset + j, end=' ')
                                        if (b == (len(hatext['pulse_info']['pulses'][i]['tags']))):
                                            print(mycolors.reset + j, end='\n')
                            if 'malware_families' in hatext['pulse_info']['pulses'][i]:
                                if hatext['pulse_info']['pulses'][i]['malware_families']:
                                    print(mycolors.foreground.cyan + "\nMalware:".ljust(13) + mycolors.reset, end='')
                                    for z in hatext['pulse_info']['pulses'][i]['malware_families']:
                                        print(mycolors.reset + z['display_name'], end=' ')
                            if 'created' in hatext['pulse_info']['pulses'][i]:
                                if hatext['pulse_info']['pulses'][i]['created']:
                                    print(mycolors.foreground.cyan + "\nCreated:".ljust(13) + mycolors.reset, end='')
                                    print(mycolors.reset + hatext['pulse_info']['pulses'][i]['created'], end=' ')
                            if 'modified' in hatext['pulse_info']['pulses'][i]:
                                if hatext['pulse_info']['pulses'][i]['modified']:
                                    print(mycolors.foreground.cyan + "\nModified:".ljust(13) + mycolors.reset, end='')
                                    print(mycolors.reset + hatext['pulse_info']['pulses'][i]['modified'], end=' ')
                            if 'targeted_countries' in hatext['pulse_info']['pulses'][i]:
                                if hatext['pulse_info']['pulses'][i]['targeted_countries']:
                                    print(mycolors.foreground.cyan + "\nCountries:".ljust(13), end='')
                                    for z in hatext['pulse_info']['pulses'][i]['targeted_countries']:
                                        print(mycolors.reset + z, end=' ')
                            if 'attack_ids' in hatext['pulse_info']['pulses'][i]:
                                if hatext['pulse_info']['pulses'][i]['attack_ids']:
                                    for k in hatext['pulse_info']['pulses'][i]['attack_ids']:
                                        print(mycolors.foreground.cyan + "\nAttack IDs:".ljust(13) + mycolors.reset + str(k['display_name']), end='')
                            if 'name' in hatext['pulse_info']['pulses'][i]:
                                if hatext['pulse_info']['pulses'][i]['name']:
                                    print(mycolors.foreground.cyan + "\nNews:".ljust(13) + mycolors.reset + hatext['pulse_info']['pulses'][i]['name'], end='')
                                break
                            i = i + 1
                    
                    print(mycolors.foreground.cyan + "\nDescription:", end='')
                    for x in hatext['pulse_info']['pulses']:
                        if (isinstance(x, dict)):
                            for y in x:
                                if 'description' in y:
                                    if (x['description']):
                                        print("\n".ljust(13),end='')
                                        print(mycolors.reset + ("\n".ljust(13)).join(textwrap.wrap(x['description'],width=100)), end='\n')
                    
                    if "references" in (hatext['pulse_info']):
                        for j in hatext['pulse_info']['references']:
                            print(mycolors.foreground.cyan + "\nReferences: ".ljust(13) + mycolors.reset + ("\n".ljust(13)).join(textwrap.wrap(j,width=100)), end='')
                    print("\n")

    except ValueError as e:
        print(e)
        if (bkg == 1):
            print((mycolors.foreground.lightred + "Error while connecting to Alien Vault!\n"))
        else:
            print((mycolors.foreground.red + "Error while connecting to Alien Vault!\n"))
        print(mycolors.reset)


def alien_url(urlx, arg1):

    hatext = ''
    haresponse = ''
    history = '10'
    user_agent = {'X-OTX-API-KEY': ALIENAPI}
    search_params = {'limit': history}
    myargs = arg1

    try:

        resource = urlx
        requestsession = requests.Session( )
        requestsession.headers.update({'Content-Type': 'application/json'})
        finalurl = '/'.join([resource,'indicators', 'url', myargs, 'general'])
        haresponse = requestsession.post(url=finalurl, headers=user_agent, params=search_params)
        hatext = json.loads(haresponse.text)

        if(bkg == 1):
            if 'indicator' in hatext:
                print(mycolors.reset)
                if hatext['pulse_info']:
                    i = 0
                    if 'count' in (hatext['pulse_info']):
                        if ((hatext['pulse_info']['count']) == 0):
                            print(mycolors.foreground.lightred + "\nURL not found!\n" + mycolors.reset)
                            exit(0)
                    if 'pulses' in (hatext['pulse_info']):
                        if 'name' in hatext['pulse_info']['pulses'][i]:
                            if hatext['pulse_info']['pulses'][i]['name']:
                                print(mycolors.foreground.lightred + "\nNews:".ljust(13) + mycolors.reset + hatext['pulse_info']['pulses'][i]['name'], end='')
                        print(mycolors.foreground.lightred + "\nDescription:", end='')
                        for x in hatext['pulse_info']['pulses']:
                            if (isinstance(x, dict)):
                                for y in x:
                                    if 'description' in y:
                                        if (x['description']):
                                            print("\n".ljust(13),end='')
                                            print(mycolors.reset + ("\n".ljust(13)).join(textwrap.wrap(x['description'],width=100)), end='\n')
                        if "references" in (hatext['pulse_info']):
                            for j in hatext['pulse_info']['references']:
                                print(mycolors.foreground.lightred + "\nReferences:".ljust(13) + mycolors.reset + ("\n".ljust(13)).join(textwrap.wrap(j,width=100)), end='')
                        while (i < len(hatext['pulse_info']['pulses'])):
                            if "tags" in (hatext['pulse_info']['pulses'][i]):
                                if hatext['pulse_info']['pulses'][i]['tags']:
                                    print(mycolors.foreground.lightred + "\nTags:".ljust(13), end='')
                                    for j in hatext['pulse_info']['pulses'][i]['tags']:
                                        print(mycolors.reset + j, end=' ')
                            if 'malware_families' in hatext['pulse_info']['pulses'][i]:
                                if hatext['pulse_info']['pulses'][i]['malware_families']:
                                    print(mycolors.foreground.lightred + "\nMalware:".ljust(13) + mycolors.reset, end='')
                                    for z in hatext['pulse_info']['pulses'][i]['malware_families']:
                                        print(mycolors.reset + z['display_name'], end=' ')
                            if 'created' in hatext['pulse_info']['pulses'][i]:
                                if hatext['pulse_info']['pulses'][i]['created']:
                                    print(mycolors.foreground.lightred + "\nCreated:".ljust(13) + mycolors.reset, end='')
                                    print(mycolors.reset + hatext['pulse_info']['pulses'][i]['created'], end=' ')
                            if 'modified' in hatext['pulse_info']['pulses'][i]:
                                if hatext['pulse_info']['pulses'][i]['modified']:
                                    print(mycolors.foreground.lightred + "\nModified:".ljust(13) + mycolors.reset, end='')
                                    print(mycolors.reset + hatext['pulse_info']['pulses'][i]['modified'], end=' ')
                            if 'targeted_countries' in hatext['pulse_info']['pulses'][i]:
                                if hatext['pulse_info']['pulses'][i]['targeted_countries']:
                                    print(mycolors.foreground.lightred + "\nCountries:".ljust(13), end='')
                                    for z in hatext['pulse_info']['pulses'][i]['targeted_countries']:
                                        print(mycolors.reset + z, end=' ')
                            if 'attack_ids' in hatext['pulse_info']['pulses'][i]:
                                if hatext['pulse_info']['pulses'][i]['attack_ids']:
                                    for k in hatext['pulse_info']['pulses'][i]['attack_ids']:
                                        print(mycolors.foreground.lightred + "\nAttack IDs:".ljust(13) + mycolors.reset + str(k['display_name']), end='')
                                break
                            i = i + 1
                        
                        j = 0
                        while (j < len(hatext['pulse_info']['pulses'])):
                            if "tags" in (hatext['pulse_info']['pulses'][i]):
                                if hatext['pulse_info']['pulses'][j]['tags']:
                                    print(mycolors.foreground.lightred + "\nTags:".ljust(13), end='')
                                    for z in hatext['pulse_info']['pulses'][j]['tags']:
                                        print(mycolors.reset + z, end=' ')
                            j = j + 1

                        t = 0
                        while (t < len(hatext['pulse_info']['pulses'])):
                            if 'malware_families' in hatext['pulse_info']['pulses'][t]:
                                if hatext['pulse_info']['pulses'][t]['malware_families']:
                                    print(mycolors.foreground.lightred + "\nMalware:".ljust(13) + mycolors.reset, end='')
                                    for w in hatext['pulse_info']['pulses'][t]['malware_families']:
                                        print(mycolors.reset + w['display_name'], end=' ')
                            t = t + 1
                if hatext['alexa']:
                    print(mycolors.foreground.lightred + "\nAlexa:".ljust(13) + mycolors.reset + hatext['alexa'], end='')

        else:
            if 'indicator' in hatext:
                print(mycolors.reset)
                if hatext['pulse_info']:
                    i = 0
                    if 'count' in (hatext['pulse_info']):
                        if ((hatext['pulse_info']['count']) == 0):
                            print(mycolors.foreground.red + "\nURL not found!\n" + mycolors.reset)
                            exit(0)
                    if 'pulses' in (hatext['pulse_info']):
                        if 'name' in hatext['pulse_info']['pulses'][i]:
                            if hatext['pulse_info']['pulses'][i]['name']:
                                print(mycolors.foreground.red + "\nNews:".ljust(13) + mycolors.reset + hatext['pulse_info']['pulses'][i]['name'], end='')
                        print(mycolors.foreground.red + "\nDescription:", end='')
                        for x in hatext['pulse_info']['pulses']:
                            if (isinstance(x, dict)):
                                for y in x:
                                    if 'description' in y:
                                        if (x['description']):
                                            print("\n".ljust(13),end='')
                                            print(mycolors.reset + ("\n".ljust(13)).join(textwrap.wrap(x['description'],width=100)), end='\n')
                        if "references" in (hatext['pulse_info']):
                            for j in hatext['pulse_info']['references']:
                                print(mycolors.foreground.red + "\nReferences:".ljust(13) + mycolors.reset + ("\n".ljust(13)).join(textwrap.wrap(j,width=100)), end='')
                        while (i < len(hatext['pulse_info']['pulses'])):
                            if "tags" in (hatext['pulse_info']['pulses'][i]):
                                if hatext['pulse_info']['pulses'][i]['tags']:
                                    print(mycolors.foreground.red + "\nTags:".ljust(13), end='')
                                    for j in hatext['pulse_info']['pulses'][i]['tags']:
                                        print(mycolors.reset + j, end=' ')
                            if 'malware_families' in hatext['pulse_info']['pulses'][i]:
                                if hatext['pulse_info']['pulses'][i]['malware_families']:
                                    print(mycolors.foreground.red + "\nMalware:".ljust(13) + mycolors.reset, end='')
                                    for z in hatext['pulse_info']['pulses'][i]['malware_families']:
                                        print(mycolors.reset + z['display_name'], end=' ')
                            if 'created' in hatext['pulse_info']['pulses'][i]:
                                if hatext['pulse_info']['pulses'][i]['created']:
                                    print(mycolors.foreground.red + "\nCreated:".ljust(13) + mycolors.reset, end='')
                                    print(mycolors.reset + hatext['pulse_info']['pulses'][i]['created'], end=' ')
                            if 'modified' in hatext['pulse_info']['pulses'][i]:
                                if hatext['pulse_info']['pulses'][i]['modified']:
                                    print(mycolors.foreground.red + "\nModified:".ljust(13) + mycolors.reset, end='')
                                    print(mycolors.reset + hatext['pulse_info']['pulses'][i]['modified'], end=' ')
                            if 'targeted_countries' in hatext['pulse_info']['pulses'][i]:
                                if hatext['pulse_info']['pulses'][i]['targeted_countries']:
                                    print(mycolors.foreground.red + "\nCountries:".ljust(13), end='')
                                    for z in hatext['pulse_info']['pulses'][i]['targeted_countries']:
                                        print(mycolors.reset + z, end=' ')
                            if 'attack_ids' in hatext['pulse_info']['pulses'][i]:
                                if hatext['pulse_info']['pulses'][i]['attack_ids']:
                                    for k in hatext['pulse_info']['pulses'][i]['attack_ids']:
                                        print(mycolors.foreground.red + "\nAttack IDs:".ljust(13) + mycolors.reset + str(k['display_name']), end='')
                                break
                            i = i + 1
                        
                        j = 0
                        while (j < len(hatext['pulse_info']['pulses'])):
                            if "tags" in (hatext['pulse_info']['pulses'][i]):
                                if hatext['pulse_info']['pulses'][j]['tags']:
                                    print(mycolors.foreground.red + "\nTags:".ljust(13), end='')
                                    for z in hatext['pulse_info']['pulses'][j]['tags']:
                                        print(mycolors.reset + z, end=' ')
                            j = j + 1

                        t = 0
                        while (t < len(hatext['pulse_info']['pulses'])):
                            if 'malware_families' in hatext['pulse_info']['pulses'][t]:
                                if hatext['pulse_info']['pulses'][t]['malware_families']:
                                    print(mycolors.foreground.red + "\nMalware:".ljust(13) + mycolors.reset, end='')
                                    for w in hatext['pulse_info']['pulses'][t]['malware_families']:
                                        print(mycolors.reset + w['display_name'], end=' ')
                            t = t + 1
                if hatext['alexa']:
                    print(mycolors.foreground.red + "\nAlexa:".ljust(13) + mycolors.reset + hatext['alexa'], end='')


    except ValueError as e:
        print(e)
        if (bkg == 1):
            print((mycolors.foreground.lightred + "Error while connecting to Alien Vault!\n"))
        else:
            print((mycolors.foreground.red + "Error while connecting to Alien Vault!\n"))
        print(mycolors.reset)


def malpedia_families(urlx, arg1):

    hatext = ''
    haresponse = ''
    myargs = arg1

    try:

        resource = urlx
        requestsession = requests.Session( )
        requestsession.headers.update({'Content-Type': 'application/json'})
        requestsession.headers.update({'Authorization': 'apitoken ' + MALPEDIAAPI  })
        finalurl = '/'.join([resource, 'get', 'families'])
        haresponse = requestsession.get(url=finalurl)
        hatext = json.loads(haresponse.text)

        if(not '200' in str(haresponse)):
           print(mycolors.foreground.red + "\nAn error has occured while accessing Malpedia.\n", mycolors.reset) 
           exit(1)

        if(bkg == 1):
            for key,value in hatext.items():
                print(mycolors.foreground.orange + "Family:".ljust(13) + mycolors.reset + key)
                print(mycolors.foreground.lightgreen + "\nUpdated:".ljust(14) + mycolors.reset + value['updated'], end=' ')
                if (value['attribution']):
                    print(mycolors.foreground.lightgreen + "\nAttribution:".ljust(13), end=' ')
                    for i in value['attribution']:
                        print(mycolors.reset + str(i), end=' ')
                if (value['alt_names']):
                    print(mycolors.foreground.lightgreen + "\nAliases:".ljust(13), end=' ')
                    for i in value['alt_names']:
                        print(mycolors.reset + i, end=' ')
                if (value['common_name']):
                    print(mycolors.foreground.lightgreen + "\nCommon Name: ".ljust(13) + mycolors.reset + value['common_name'], end=' ')
                if (value['description']):
                    print(mycolors.foreground.lightgreen + "\nDescription: ".ljust(13) + mycolors.reset + ("\n".ljust(14)).join(textwrap.wrap(value['description'],width=110)), end=' ')

                if (value['urls']):
                    j = 0
                    for i in value['urls']:
                        if (j < 10):
                            print(mycolors.foreground.lightgreen + "\nURL_%d:".ljust(15) % j + mycolors.reset + ("\n".ljust(14)).join(textwrap.wrap(i,width=110)), end=' ')
                        if (j > 9 and j < 100):
                            print(mycolors.foreground.lightgreen + "\nURL_%d:".ljust(14) % j + mycolors.reset + ("\n".ljust(14)).join(textwrap.wrap(i,width=110)), end=' ')
                        if (j > 99):
                            print(mycolors.foreground.lightgreen + "\nURL_%d:".ljust(13) % j + mycolors.reset + ("\n".ljust(14)).join(textwrap.wrap(i,width=110)), end=' ')
                        j = j + 1

                print(mycolors.reset + "\n" + "-" * 123)

        if(bkg == 0):
            for key,value in hatext.items():
                print(mycolors.foreground.red + "Family:".ljust(13) + mycolors.reset + key)
                print(mycolors.foreground.blue + "\nUpdated:".ljust(14) + mycolors.reset + value['updated'], end=' ')
                if (value['attribution']):
                    print(mycolors.foreground.blue + "\nAttribution:".ljust(13), end=' ')
                    for i in value['attribution']:
                        print(mycolors.reset + str(i), end=' ')
                if (value['alt_names']):
                    print(mycolors.foreground.blue + "\nAliases:".ljust(13), end=' ')
                    for i in value['alt_names']:
                        print(mycolors.reset + i, end=' ')
                if (value['common_name']):
                    print(mycolors.foreground.blue + "\nCommon Name: ".ljust(13) + mycolors.reset + value['common_name'], end=' ')
                if (value['description']):
                    print(mycolors.foreground.blue + "\nDescription: ".ljust(13) + mycolors.reset + ("\n".ljust(14)).join(textwrap.wrap(value['description'],width=110)), end=' ')

                if (value['urls']):
                    j = 0
                    for i in value['urls']:
                        if (j < 10):
                            print(mycolors.foreground.blue + "\nURL_%d:".ljust(15) % j + mycolors.reset + ("\n".ljust(14)).join(textwrap.wrap(i,width=110)), end=' ')
                        if (j > 9 and j < 100):
                            print(mycolors.foreground.blue + "\nURL_%d:".ljust(14) % j + mycolors.reset + ("\n".ljust(14)).join(textwrap.wrap(i,width=110)), end=' ')
                        if (j > 99):
                            print(mycolors.foreground.blue + "\nURL_%d:".ljust(13) % j + mycolors.reset + ("\n".ljust(14)).join(textwrap.wrap(i,width=110)), end=' ')
                        j = j + 1

                print(mycolors.reset + "\n" + "-" * 123)
    
    except ValueError as e:
        print(e)
        if (bkg == 1):
            print((mycolors.foreground.lightred + "Error while connecting to Malpedia!\n"))
        else:
            print((mycolors.foreground.red + "Error while connecting to Malpedia!\n"))
        print(mycolors.reset)


def malpedia_actors(urlx, arg1):

    hatext = ''
    haresponse = ''
    myargs = arg1

    try:

        resource = urlx
        requestsession = requests.Session( )
        requestsession.headers.update({'Content-Type': 'application/json'})
        requestsession.headers.update({'Authorization': 'apitoken ' + MALPEDIAAPI  })
        finalurl = '/'.join([resource, 'list', 'actors'])
        haresponse = requestsession.get(url=finalurl)
        hatext = json.loads(haresponse.text)

        if(not '200' in str(haresponse)):
           print(mycolors.foreground.red + "\nAn error has occured while accessing Malpedia.\n", mycolors.reset) 
           exit(1)

        if(bkg == 1):
            print(mycolors.foreground.lightgreen + "\nActors:".ljust(13), end='\n'.ljust(11))
            j = 1
            for i in hatext:
                if (j < 10):
                    print(mycolors.foreground.lightred + "Actor_%s:    " % j + mycolors.reset + str(i), end='\n'.ljust(11))
                if ((j > 9) and (j < 100)):
                    print(mycolors.foreground.lightred + "Actor_%s:   " % j + mycolors.reset + str(i), end='\n'.ljust(11))
                if (j > 99):
                    print(mycolors.foreground.lightred + "Actor_%s:  " % j + mycolors.reset + str(i), end='\n'.ljust(11))
                j = j + 1

        if(bkg == 0):
            print(mycolors.foreground.green + "\nActors:".ljust(13), end='\n'.ljust(11))
            j = 1
            for i in hatext:
                if (j < 10):
                    print(mycolors.foreground.red + "Actor_%s:    " % j + mycolors.reset + str(i), end='\n'.ljust(11))
                if ((j > 9) and (j < 100)):
                    print(mycolors.foreground.red + "Actor_%s:   " % j + mycolors.reset + str(i), end='\n'.ljust(11))
                if (j > 99):
                    print(mycolors.foreground.red + "Actor_%s:  " % j + mycolors.reset + str(i), end='\n'.ljust(11))
                j = j + 1

    except ValueError as e:
        print(e)
        if (bkg == 1):
            print((mycolors.foreground.lightred + "Error while connecting to Malpedia!\n"))
        else:
            print((mycolors.foreground.red + "Error while connecting to Malpedia!\n"))
        print(mycolors.reset)


def malpedia_payloads(urlx, arg1):

    hatext = ''
    haresponse = ''
    myargs = arg1

    try:

        resource = urlx
        requestsession = requests.Session( )
        requestsession.headers.update({'Content-Type': 'application/json'})
        requestsession.headers.update({'Authorization': 'apitoken ' + MALPEDIAAPI  })
        finalurl = '/'.join([resource, 'list', 'samples'])
        haresponse = requestsession.get(url=finalurl)
        hatext = json.loads(haresponse.text)

        if(not '200' in str(haresponse)):
           print(mycolors.foreground.red + "\nAn error has occured while accessing Malpedia.\n", mycolors.reset) 
           exit(1)

        if(bkg == 1):
            for key,value in hatext.items():
                print(mycolors.foreground.orange + "Family:".ljust(11) + mycolors.reset + key, end=' ')
                for i in value:
                    for j in i.items():
                        for k in i.keys():
                            if (k == 'status'):
                                if (i['status']):
                                    print(mycolors.foreground.lightgreen + "\n\nStatus:".ljust(13) + mycolors.reset + str(i['status']), end='')
                            if (k == 'sha256'):
                                if (i['sha256']):
                                    print(mycolors.foreground.lightgreen + "\nHash:".ljust(12) + mycolors.reset + str(i['sha256']), end='')
                            if (k == 'version'):
                                if (i['version']):
                                    print(mycolors.foreground.lightgreen + "\nVersion:".ljust(12) + mycolors.reset + str(i['version']), end=' ')
                print("\n" + '-' * 75)

        if(bkg == 0):
            for key,value in hatext.items():
                print(mycolors.foreground.red + "Family:".ljust(11) + mycolors.reset + key, end=' ')
                for i in value:
                    for j in i.items():
                        for k in i.keys():
                            if (k == 'status'):
                                if (i['status']):
                                    print(mycolors.foreground.green + "\n\nStatus:".ljust(13) + mycolors.reset + str(i['status']), end='')
                            if (k == 'sha256'):
                                if (i['sha256']):
                                    print(mycolors.foreground.green + "\nHash:".ljust(12) + mycolors.reset + str(i['sha256']), end='')
                            if (k == 'version'):
                                if (i['version']):
                                    print(mycolors.foreground.green + "\nVersion:".ljust(12) + mycolors.reset + str(i['version']), end=' ')
                print("\n" + '-' * 75)

    except ValueError as e:
        print(e)
        if (bkg == 1):
            print((mycolors.foreground.lightred + "Error while connecting to Malpedia!\n"))
        else:
            print((mycolors.foreground.red + "Error while connecting to Malpedia!\n"))
        print(mycolors.reset)


def malpedia_get_actor(urlx, arg1):

    hatext = ''
    haresponse = ''
    myargs = arg1
    wrapper = textwrap.TextWrapper(width=100)

    try:

        resource = urlx
        requestsession = requests.Session( )
        requestsession.headers.update({'Content-Type': 'application/json'})
        requestsession.headers.update({'Authorization': 'apitoken ' + MALPEDIAAPI  })
        finalurl = '/'.join([resource, 'get', 'actor', myargs])
        haresponse = requestsession.get(url=finalurl)
        hatext = json.loads(haresponse.text)
        
        if (bkg == 1):
            if('Not found.' in str(hatext)):
                print(mycolors.foreground.yellow + "\nInformation about this actor couldn't be found on Malpedia.\n", mycolors.reset) 
                exit(1)

        if (bkg == 0):
            if('Not found.' in str(hatext)):
                print(mycolors.foreground.cyan + "\nInformation about this actor couldn't be found on Malpedia.\n", mycolors.reset) 
                exit(1)
        
        if(not '200' in str(haresponse)):
            print(mycolors.foreground.red + "\nAn error has occured while accessing Malpedia.\n", mycolors.reset) 
            exit(1)

        if(bkg == 1):
            if (hatext['value']):
                print(mycolors.foreground.yellow + "\nActor:".ljust(11) + mycolors.reset + hatext['value'], end=' ')
            if(hatext['description']):
                print(mycolors.foreground.yellow + "\n\nOverview: ".ljust(11) + mycolors.reset + ("\n".ljust(11)).join(textwrap.wrap(str(hatext['description']),width=100)), end=' ')
            for key,value in hatext.items():
                if(key == 'meta'):
                    for key2,value2 in value.items():
                        if (key2 == 'country'):
                            if (value['country']):
                                print(mycolors.foreground.yellow + "\n\nCountry:".ljust(12) + mycolors.reset + str(value['country']), end='\n')
                        if (key2 == 'synonyms'):
                            if (value['synonyms']):
                                print(mycolors.foreground.lightgreen + "\n\nSynonyms:".ljust(11), end=' ')
                                for x in value['synonyms']:
                                    print(mycolors.reset + str(x), end=' ')
                        if (key2 == 'refs'):
                            if (value['refs']):
                                for x in value['refs']:
                                    print(mycolors.foreground.lightgreen + "\nREFs:".ljust(11) + mycolors.reset + ("\n".ljust(11)).join(wrapper.wrap(str(x))).ljust(11), end=" ")
                if(key == 'families'):
                    for key3,value3 in value.items():
                        print("\n" + '-' * 112, end='')
                        print(mycolors.foreground.yellow + "\nFamily: ".ljust(11) + mycolors.reset  + key3)
                        if 'updated' in value3.keys():
                            if(value3['updated']):
                                print(mycolors.foreground.lightgreen + "Updated: ".ljust(10) + mycolors.reset + value3['updated' ])
                        if 'attribution' in value3.keys():
                            if(len(value3['attribution']) > 0):
                                print(mycolors.foreground.lightgreen + "Attrib.: ".ljust(9), end=' ')
                                for y in value3['attribution']:
                                    print(mycolors.reset + y, end=' ')
                        if 'alt_names' in value3.keys():
                            if(len(value3['alt_names']) > 0):
                                print(mycolors.foreground.lightgreen + "\nAliases: ".ljust(10), end=' ')
                                for y in value3['alt_names']:
                                    print(mycolors.reset + y, end=' ')
                        if 'common_name' in value3.keys():
                            if(value3['common_name']):
                                print(mycolors.foreground.lightgreen + "\nCommon: ".ljust(11) + mycolors.reset + value3['common_name' ], end=' ')
                        if 'sources' in value3.keys():
                            if(len(value3['sources']) > 0):
                                print(mycolors.foreground.lightgreen + "\nSources: ".ljust(11), end=' ')
                                for y in value3['sources']:
                                    print(mycolors.reset + y, end=' ')
                        if 'description' in value3.keys():
                            if value3['description']:
                                print(mycolors.foreground.lightgreen + "\nDescr.: ".ljust(11) + mycolors.reset + ("\n".ljust(11)).join(textwrap.wrap(str(value3['description']),width=100)), end=' ')
                        if 'urls' in value3.keys():
                            if(len(value3['urls']) > 0):
                                for y in value3['urls']:
                                    print(mycolors.foreground.lightgreen + "\nURLs: ".ljust(11) + mycolors.reset + ("\n".ljust(11)).join(wrapper.wrap(str(y))).ljust(11), end=" ")

        if(bkg == 0):
            if (hatext['value']):
                print(mycolors.foreground.red + "\nActor:".ljust(11) + mycolors.reset + hatext['value'], end=' ')
            if(hatext['description']):
                print(mycolors.foreground.red + "\n\nOverview: ".ljust(11) + mycolors.reset + ("\n".ljust(11)).join(textwrap.wrap(str(hatext['description']),width=100)), end=' ')
            for key,value in hatext.items():
                if(key == 'meta'):
                    for key2,value2 in value.items():
                        if (key2 == 'country'):
                            if (value['country']):
                                print(mycolors.foreground.red + "\n\nCountry:".ljust(12) + mycolors.reset + str(value['country']), end='\n')
                        if (key2 == 'synonyms'):
                            if (value['synonyms']):
                                print(mycolors.foreground.green + "\n\nSynonyms:".ljust(11), end=' ')
                                for x in value['synonyms']:
                                    print(mycolors.reset + str(x), end=' ')
                        if (key2 == 'refs'):
                            if (value['refs']):
                                for x in value['refs']:
                                    print(mycolors.foreground.green + "\nREFs:".ljust(11) + mycolors.reset + ("\n".ljust(11)).join(wrapper.wrap(str(x))).ljust(11), end=" ")
                if(key == 'families'):
                    for key3,value3 in value.items():
                        print("\n" + '-' * 112, end='')
                        print(mycolors.foreground.red + "\nFamily: ".ljust(11) + mycolors.reset  + key3)
                        if 'updated' in value3.keys():
                            if(value3['updated']):
                                print(mycolors.foreground.green + "Updated: ".ljust(10) + mycolors.reset + value3['updated' ])
                        if 'attribution' in value3.keys():
                            if(len(value3['attribution']) > 0):
                                print(mycolors.foreground.green + "Attrib.: ".ljust(9), end=' ')
                                for y in value3['attribution']:
                                    print(mycolors.reset + y, end=' ')
                        if 'alt_names' in value3.keys():
                            if(len(value3['alt_names']) > 0):
                                print(mycolors.foreground.green + "\nAliases: ".ljust(10), end=' ')
                                for y in value3['alt_names']:
                                    print(mycolors.reset + y, end=' ')
                        if 'common_name' in value3.keys():
                            if(value3['common_name']):
                                print(mycolors.foreground.green + "\nCommon: ".ljust(11) + mycolors.reset + value3['common_name' ], end=' ')
                        if 'sources' in value3.keys():
                            if(len(value3['sources']) > 0):
                                print(mycolors.foreground.green + "\nSources: ".ljust(11), end=' ')
                                for y in value3['sources']:
                                    print(mycolors.reset + y, end=' ')
                        if 'description' in value3.keys():
                            if value3['description']:
                                print(mycolors.foreground.green + "\nDescr.: ".ljust(11) + mycolors.reset + ("\n".ljust(11)).join(textwrap.wrap(str(value3['description']),width=100)), end=' ')
                        if 'urls' in value3.keys():
                            if(len(value3['urls']) > 0):
                                for y in value3['urls']:
                                    print(mycolors.foreground.green + "\nURLs: ".ljust(11) + mycolors.reset + ("\n".ljust(11)).join(wrapper.wrap(str(y))).ljust(11), end=" ")

    except ValueError as e:
        print(e)
        if (bkg == 1):
            print((mycolors.foreground.lightred + "Error while connecting to Malpedia!\n"))
        else:
            print((mycolors.foreground.red + "Error while connecting to Malpedia!\n"))
        print(mycolors.reset)


def malpedia_families(urlx, arg1):

    hatext = ''
    haresponse = ''
    myargs = arg1
    wrapper = textwrap.TextWrapper(width=100)

    try:

        resource = urlx
        requestsession = requests.Session( )
        requestsession.headers.update({'Content-Type': 'application/json'})
        requestsession.headers.update({'Authorization': 'apitoken ' + MALPEDIAAPI  })
        finalurl = '/'.join([resource, 'list', 'families'])
        haresponse = requestsession.get(url=finalurl)
        hatext = json.loads(haresponse.text)
        
        if(not '200' in str(haresponse)):
            print(mycolors.foreground.red + "\nAn error has occured while accessing Malpedia.\n", mycolors.reset) 
            exit(1)
        
        if(bkg == 1):
            print(mycolors.foreground.yellow + "\nFamilies:".ljust(13), end='\n'.ljust(11))
            j = 1
            for i in hatext:
                if (j < 10):
                    print(mycolors.foreground.lightcyan + "Family_%s:     " % j + mycolors.reset + str(i), end='\n'.ljust(11))
                if ((j > 9) and (j < 100)):
                    print(mycolors.foreground.lightcyan + "Family_%s:    " % j + mycolors.reset + str(i), end='\n'.ljust(11))
                if ((j > 99) and (j < 1000)):
                    print(mycolors.foreground.lightcyan + "Family_%s:   " % j + mycolors.reset + str(i), end='\n'.ljust(11))
                if (j > 999):
                    print(mycolors.foreground.lightcyan + "Family_%s:  " % j + mycolors.reset + str(i), end='\n'.ljust(11))
                j = j + 1

        if(bkg == 0):
            print(mycolors.foreground.red + "\nFamilies:".ljust(13), end='\n'.ljust(11))
            j = 1
            for i in hatext:
                if (j < 10):
                    print(mycolors.foreground.cyan + "Family_%s:     " % j + mycolors.reset + str(i), end='\n'.ljust(11))
                if ((j > 9) and (j < 100)):
                    print(mycolors.foreground.cyan + "Family_%s:    " % j + mycolors.reset + str(i), end='\n'.ljust(11))
                if ((j > 99) and (j < 1000)):
                    print(mycolors.foreground.cyan + "Family_%s:   " % j + mycolors.reset + str(i), end='\n'.ljust(11))
                if (j > 999):
                    print(mycolors.foreground.cyan + "Family_%s:  " % j + mycolors.reset + str(i), end='\n'.ljust(11))
                j = j + 1

    except ValueError as e:
        print(e)
        if (bkg == 1):
            print((mycolors.foreground.lightred + "Error while connecting to Malpedia!\n"))
        else:
            print((mycolors.foreground.red + "Error while connecting to Malpedia!\n"))
        print(mycolors.reset)


def malpedia_get_family(urlx, arg1):

    hatext = ''
    haresponse = ''
    myargs = arg1
    wrapper = textwrap.TextWrapper(width=100)

    try:

        resource = urlx
        requestsession = requests.Session( )
        requestsession.headers.update({'Content-Type': 'application/json'})
        requestsession.headers.update({'Authorization': 'apitoken ' + MALPEDIAAPI  })
        finalurl = '/'.join([resource, 'get', 'family', myargs])
        haresponse = requestsession.get(url=finalurl)
        hatext = json.loads(haresponse.text)

        if (bkg == 1):
            if('Not found.' in str(hatext)):
                print(mycolors.foreground.yellow + "\nInformation about this family couldn't be found on Malpedia.\n", mycolors.reset) 
                exit(1)

        if (bkg == 0):
            if('Not found.' in str(hatext)):
                print(mycolors.foreground.cyan + "\nInformation about this family couldn't be found on Malpedia.\n", mycolors.reset) 
                exit(1)
        
        if(not '200' in str(haresponse)):
            print(mycolors.foreground.red + "\nAn error has occured while accessing Malpedia.\n", mycolors.reset) 
            exit(1)

        if(bkg == 1):
            print(mycolors.foreground.lightcyan + "\nFamily:".ljust(14) + mycolors.reset + myargs)
            print(mycolors.foreground.yellow + "\nUpdated:".ljust(14) + mycolors.reset + hatext['updated'], end=' ')
            if (hatext['attribution']):
                print(mycolors.foreground.yellow + "\nAttribution:".ljust(13), end=' ')
                for i in hatext['attribution']:
                    print(mycolors.reset + str(i), end=' ')
            if (hatext['alt_names']):
                print(mycolors.foreground.yellow + "\nAliases:".ljust(13), end=' ')
                for i in hatext['alt_names']:
                    print(mycolors.reset + i, end=' ')
            if (hatext['common_name']):
                print(mycolors.foreground.yellow + "\nCommon Name: ".ljust(13) + mycolors.reset + hatext['common_name'], end=' ')
            if (hatext['description']):
                print(mycolors.foreground.yellow + "\nDescription: ".ljust(13) + mycolors.reset + ("\n".ljust(14)).join(textwrap.wrap(hatext['description'],width=110)), end='\n')

            if (hatext['urls']):
                j = 0
                for i in hatext['urls']:
                    if (j < 10):
                        print(mycolors.foreground.yellow + "\nURL_%d:".ljust(15) % j + mycolors.reset + ("\n".ljust(14)).join(textwrap.wrap(i,width=110)), end=' ')
                    if (j > 9 and j < 100):
                        print(mycolors.foreground.yellow + "\nURL_%d:".ljust(14) % j + mycolors.reset + ("\n".ljust(14)).join(textwrap.wrap(i,width=110)), end=' ')
                    if (j > 99):
                        print(mycolors.foreground.yellow + "\nURL_%d:".ljust(13) % j + mycolors.reset + ("\n".ljust(14)).join(textwrap.wrap(i,width=110)), end=' ')
                    j = j + 1

        if(bkg == 0):
            print(mycolors.foreground.purple + "\nFamily:".ljust(14) + mycolors.reset + myargs)
            print(mycolors.foreground.cyan + "\nUpdated:".ljust(14) + mycolors.reset + hatext['updated'], end=' ')
            if (hatext['attribution']):
                print(mycolors.foreground.cyan + "\nAttribution:".ljust(13), end=' ')
                for i in hatext['attribution']:
                    print(mycolors.reset + str(i), end=' ')
            if (hatext['alt_names']):
                print(mycolors.foreground.cyan + "\nAliases:".ljust(13), end=' ')
                for i in hatext['alt_names']:
                    print(mycolors.reset + i, end=' ')
            if (hatext['common_name']):
                print(mycolors.foreground.cyan + "\nCommon Name: ".ljust(13) + mycolors.reset + hatext['common_name'], end=' ')
            if (hatext['description']):
                print(mycolors.foreground.cyan + "\nDescription: ".ljust(13) + mycolors.reset + ("\n".ljust(14)).join(textwrap.wrap(hatext['description'],width=110)), end='\n')

            if (hatext['urls']):
                j = 0
                for i in hatext['urls']:
                    if (j < 10):
                        print(mycolors.foreground.cyan + "\nURL_%d:".ljust(15) % j + mycolors.reset + ("\n".ljust(14)).join(textwrap.wrap(i,width=110)), end=' ')
                    if (j > 9 and j < 100):
                        print(mycolors.foreground.cyan + "\nURL_%d:".ljust(14) % j + mycolors.reset + ("\n".ljust(14)).join(textwrap.wrap(i,width=110)), end=' ')
                    if (j > 99):
                        print(mycolors.foreground.cyan + "\nURL_%d:".ljust(13) % j + mycolors.reset + ("\n".ljust(14)).join(textwrap.wrap(i,width=110)), end=' ')
                    j = j + 1

    except ValueError as e:
        print(e)
        if (bkg == 1):
            print((mycolors.foreground.lightred + "Error while connecting to Malpedia!\n"))
        else:
            print((mycolors.foreground.red + "Error while connecting to Malpedia!\n"))
        print(mycolors.reset)


def malpedia_get_sample(urlx, arg1):

    hatext = ''
    haresponse = ''
    myargs = arg1

    try:

        resource = urlx
        requestsession = requests.Session( )
        requestsession.headers.update({'Content-Type': 'application/json'})
        requestsession.headers.update({'Authorization': 'apitoken ' + MALPEDIAAPI  })
        finalurl = '/'.join([resource, 'get', 'sample', myargs, 'zip'])
        haresponse = requestsession.get(url=finalurl)
        hatext = json.loads(haresponse.text)

        if (bkg == 1):
            if('Not found.' in str(hatext)):
                print(mycolors.foreground.yellow + "\nThis sample couldn't be found on Malpedia.\n", mycolors.reset) 
                exit(1)

        if (bkg == 0):
            if('Not found.' in str(hatext)):
                print(mycolors.foreground.cyan + "\nThis sample couldn't be found on Malpedia.\n", mycolors.reset) 
                exit(1)
        
        if(not '200' in str(haresponse)):
            print(mycolors.foreground.red + "\nAn error has occured while accessing Malpedia.\n", mycolors.reset) 
            exit(1)

        if('200' in str(haresponse)):
            if (bkg == 1):
                open(myargs+".zip", 'wb').write(base64.b64decode(hatext['zipped']))
                print(mycolors.foreground.lightgreen + "\nSample successfuly downloaded from Malpedia!\n", mycolors.reset) 
            else:
                open(myargs+".zip", 'wb').write(base64.b64decode(hatext['zipped']))
                print(mycolors.foreground.green + "\nSample successfuly downloaded from Malpedia!\n", mycolors.reset) 
                exit(0)

    except ValueError as e:
        print(e)
        if (bkg == 1):
            print((mycolors.foreground.lightred + "Error while connecting to Malpedia!\n"))
        else:
            print((mycolors.foreground.red + "Error while connecting to Malpedia!\n"))
        print(mycolors.reset)


def malpedia_get_yara(urlx, arg1):

    hatext = ''
    haresponse = ''
    myargs = arg1

    try:
        resource = urlx
        requestsession = requests.Session( )
        requestsession.headers.update({'Content-Type': 'application/json'})
        requestsession.headers.update({'Authorization': 'apitoken ' + MALPEDIAAPI  })
        finalurl = '/'.join([resource, 'get', 'yara', myargs, 'zip'])
        haresponse = requestsession.get(url=finalurl)

        if (bkg == 1):
            if('Not found.' in str(hatext)):
                print(mycolors.foreground.yellow + "\nThe Yara rule for this family couldn't be found on Malpedia.\n", mycolors.reset) 
                exit(1)

        if (bkg == 0):
            if('Not found.' in str(hatext)):
                print(mycolors.foreground.cyan + "\nThe Yara rule for this family couldn't be found on Malpedia.\n", mycolors.reset) 
                exit(1)
        
        if(not '200' in str(haresponse)):
            print(mycolors.foreground.red + "\nAn error has occured while accessing Malpedia.\n", mycolors.reset) 
            exit(1)

        if('200' in str(haresponse)):
            if (bkg == 1):
                open(myargs+".zip", 'wb').write(haresponse.content)
                print(mycolors.foreground.lightgreen + "\nA zip file named %s.zip containing Yara rules has been SUCCESSFULLY downloaded from Malpedia!\n" % myargs, mycolors.reset) 
            else:
                open(myargs+".zip", 'wb').write(haresponse.content)
                print(mycolors.foreground.green + "\nA zip file named %s.zip containing Yara rules has been SUCCESSFULLY downloaded from Malpedia!\n" % myargs, mycolors.reset) 
                exit(0)

    except ValueError as e:
        print(e)
        if (bkg == 1):
            print((mycolors.foreground.lightred + "Error while connecting to Malpedia!\n"))
        else:
            print((mycolors.foreground.red + "Error while connecting to Malpedia!\n"))
        print(mycolors.reset)


def threatcrowd_email(urlx, arg1):

    hatext = ''
    haresponse = ''
    myargs = arg1

    try:
        resource = urlx
        requestsession = requests.Session( )
        requestsession.headers.update({'Content-Type': 'application/json'})
        finalurl = '/'.join([resource, 'email', 'report'])
        haresponse = requestsession.get(url=finalurl, params={"email":myargs})
        hatext = json.loads(haresponse.text)

        if(hatext['response_code'] == '0'):
            if (bkg == 1):
                print(mycolors.foreground.yellow + "\nThe provided e-mail address hasn't been found on ThreatCrowd.\n", mycolors.reset) 
                exit(0)
            if (bkg == 0):
                print(mycolors.foreground.purple + "\nThe provided e-mail address hasn't been found on ThreatCrowd.\n", mycolors.reset) 
                exit(0)

        if(not '200' in str(haresponse)):
            if (bkg == 1):
                print(mycolors.foreground.lightred + "\nAn error has occured while accessing ThreatCrowd.\n", mycolors.reset) 
                exit(1)
            if (bkg == 0):
                print(mycolors.foreground.red + "\nAn error has occured while accessing ThreatCrowd.\n", mycolors.reset) 
                exit(1)

        if(bkg == 1):
            print(mycolors.foreground.yellow + "\nEmail:".ljust(12) + mycolors.reset + myargs)
            if (hatext['domains']):
                print(mycolors.foreground.purple + "\nDomains:".ljust(13) + mycolors.reset, end=' ')
                print(mycolors.reset + "\n".ljust(12), end='')
                for i in sorted(hatext['domains']):
                    print(mycolors.reset + str(i).ljust(12), end='\n'.ljust(12))
            if (hatext['references']):
                print(mycolors.foreground.purple + "\nReferences:".ljust(13) + mycolors.reset, end=' ')
                print(mycolors.reset + "\n".ljust(12), end='')
                for i in hatext['references']:
                    print(mycolors.reset + str(i).ljust(12), end='\n'.ljust(12))

        if(bkg == 0):
            print(mycolors.foreground.red + "\nEmail:".ljust(12) + mycolors.reset + myargs)
            if (hatext['domains']):
                print(mycolors.foreground.blue + "\nDomains:".ljust(13) + mycolors.reset, end=' ')
                print(mycolors.reset + "\n".ljust(12), end='')
                for i in sorted(hatext['domains']):
                    print(mycolors.reset + str(i).ljust(12), end='\n'.ljust(12))
            if (hatext['references']):
                print(mycolors.foreground.blue + "\nReferences:".ljust(13) + mycolors.reset, end=' ')
                print(mycolors.reset + "\n".ljust(12), end='')
                for i in hatext['references']:
                    print(mycolors.reset + ("\n".ljust(12)).join(textwrap.wrap(str(i),width=110)).ljust(12), end="\n".ljust(12))

    except ValueError as e:
        print(e)
        if (bkg == 1):
            print((mycolors.foreground.lightred + "Error while connecting to ThreatCrowd!\n"))
        else:
            print((mycolors.foreground.red + "Error while connecting to ThreatCrowd!\n"))
        print(mycolors.reset)


def threatcrowd_ip(urlx, arg1):

    hatext = ''
    haresponse = ''
    myargs = arg1

    try:
        resource = urlx
        requestsession = requests.Session( )
        requestsession.headers.update({'Content-Type': 'application/json'})
        finalurl = '/'.join([resource, 'ip', 'report'])
        haresponse = requestsession.get(url=finalurl, params={"ip":myargs})
        hatext = json.loads(haresponse.text)

        if(hatext['response_code'] == '0'):
            if (bkg == 1):
                print(mycolors.foreground.yellow + "\nThe provided IP address hasn't been found on ThreatCrowd.\n", mycolors.reset) 
                exit(0)
            if (bkg == 0):
                print(mycolors.foreground.purple + "\nThe provided IP address hasn't been found on ThreatCrowd.\n", mycolors.reset) 
                exit(0)

        if(not '200' in str(haresponse)):
            if (bkg == 1):
                print(mycolors.foreground.lightred + "\nAn error has occured while accessing ThreatCrowd.\n", mycolors.reset) 
                exit(1)
            if (bkg == 0):
                print(mycolors.foreground.red + "\nAn error has occured while accessing ThreatCrowd.\n", mycolors.reset) 
                exit(1)

        if(bkg == 1):
            print(mycolors.foreground.yellow + "\nIP:".ljust(14) + mycolors.reset + myargs + mycolors.foreground.yellow + "  City: " + mycolors.reset + (geocoder.ip(myargs)).city)
            if (hatext['resolutions']):
                print(mycolors.foreground.lightgreen + "\nResolutions:".ljust(14) + mycolors.reset, end=' ')
                for i in sorted(hatext['resolutions'], key=itemgetter('last_resolved')):
                    print(mycolors.reset + "\n".ljust(14) + mycolors.foreground.pink + "Last Resolved: " + mycolors.reset +  i['last_resolved'], end='  ')
                    print(mycolors.reset + mycolors.foreground.pink + "Domain: " + mycolors.reset +  i['domain'], end="")
            if (hatext['hashes']):
                print(mycolors.foreground.lightgreen + "\n\nHashes:".ljust(13) + mycolors.reset, end=' ')
                print(mycolors.reset + "\n".ljust(14), end='')
                for i in hatext['hashes']:
                    print(mycolors.reset + str(i).ljust(14), end='\n'.ljust(14))

        if(bkg == 0):
            print(mycolors.foreground.red + "\nIP:".ljust(14) + mycolors.reset + myargs + mycolors.foreground.red + "  City: " + mycolors.reset + (geocoder.ip(myargs)).city)
            if (hatext['resolutions']):
                print(mycolors.foreground.green + "\nResolutions:".ljust(14) + mycolors.reset, end=' ')
                for i in sorted(hatext['resolutions'], key=itemgetter('last_resolved')):
                    print(mycolors.reset + "\n".ljust(14) + mycolors.foreground.purple + "Last Resolved: " + mycolors.reset +  i['last_resolved'], end='  ')
                    print(mycolors.reset + mycolors.foreground.purple + "Domain: " + mycolors.reset +  i['domain'], end="")
            if (hatext['hashes']):
                print(mycolors.foreground.green + "\n\nHashes:".ljust(13) + mycolors.reset, end=' ')
                print(mycolors.reset + "\n".ljust(14), end='')
                for i in hatext['hashes']:
                    print(mycolors.reset + str(i).ljust(14), end='\n'.ljust(14))

    except ValueError as e:
        print(e)
        if (bkg == 1):
            print((mycolors.foreground.lightred + "Error while connecting to ThreatCrowd!\n"))
        else:
            print((mycolors.foreground.red + "Error while connecting to ThreatCrowd!\n"))
        print(mycolors.reset)


def threatcrowd_domain(urlx, arg1):

    hatext = ''
    haresponse = ''
    myargs = arg1

    try:
        resource = urlx
        requestsession = requests.Session( )
        requestsession.headers.update({'Content-Type': 'application/json'})
        finalurl = '/'.join([resource, 'domain', 'report'])
        haresponse = requestsession.get(url=finalurl, params={"domain":myargs})
        hatext = json.loads(haresponse.text)

        if(hatext['response_code'] == '0'):
            if (bkg == 1):
                print(mycolors.foreground.yellow + "\nThe provided domain hasn't been found on ThreatCrowd.\n", mycolors.reset) 
                exit(0)
            if (bkg == 0):
                print(mycolors.foreground.purple + "\nThe provided domain hasn't been found on ThreatCrowd.\n", mycolors.reset) 
                exit(0)

        if(not '200' in str(haresponse)):
            if (bkg == 1):
                print(mycolors.foreground.lightred + "\nAn error has occured while accessing ThreatCrowd.\n", mycolors.reset) 
                exit(1)
            if (bkg == 0):
                print(mycolors.foreground.red + "\nAn error has occured while accessing ThreatCrowd.\n", mycolors.reset) 
                exit(1)
        
        if(bkg == 1):
            print(mycolors.foreground.yellow + "\nDomain:".ljust(14) + mycolors.reset + myargs)
            if (hatext['resolutions']):
                print(mycolors.foreground.lightcyan + "\nResolutions:".ljust(14) + mycolors.reset, end=' ')
                for i in sorted(hatext['resolutions'], key=itemgetter('last_resolved')):
                    print(mycolors.reset + "\n".ljust(14) + mycolors.foreground.lightgreen + "Last Resolved: " + mycolors.reset +  i['last_resolved'], end='  ')
                    print(mycolors.reset + mycolors.foreground.lightgreen + "IP Address: " + mycolors.reset +  i['ip_address'], end="")

            if (hatext['hashes']):
                print(mycolors.foreground.lightcyan + "\n\nHashes:".ljust(13) + mycolors.reset, end=' ')
                print(mycolors.reset + "\n".ljust(14), end='')
                for i in hatext['hashes']:
                    print(mycolors.reset + str(i).ljust(14), end='\n'.ljust(14))

            if (hatext['emails']):
                print(mycolors.foreground.lightcyan + "\n\nEmails:".ljust(13) + mycolors.reset, end=' ')
                print(mycolors.reset + "\n".ljust(14), end='')
                for i in sorted(hatext['emails']):
                    print(mycolors.reset + str(i).ljust(14), end='\n'.ljust(14))

            if (hatext['subdomains']):
                print(mycolors.foreground.lightcyan + "\n\nSubdomains:".ljust(13) + mycolors.reset, end=' ')
                print(mycolors.reset + "\n".ljust(14), end='')
                for i in sorted(hatext['subdomains']):
                    print(mycolors.reset + str(i).ljust(14), end='\n'.ljust(14))

            if (hatext['references']):
                print(mycolors.foreground.lightcyan + "\n\nReferences:".ljust(13) + mycolors.reset, end=' ')
                print(mycolors.reset + "\n".ljust(14), end='')
                for i in hatext['references']:
                    print(mycolors.reset + ("\n".ljust(14)).join(textwrap.wrap(str(i),width=110)).ljust(14), end="\n".ljust(14))

        if(bkg == 0):
            print(mycolors.foreground.red + "\nDomain:".ljust(14) + mycolors.reset + myargs)
            if (hatext['resolutions']):
                print(mycolors.foreground.cyan + "\nResolutions:".ljust(14) + mycolors.reset, end=' ')
                for i in sorted(hatext['resolutions'], key=itemgetter('last_resolved')):
                    print(mycolors.reset + "\n".ljust(14) + mycolors.foreground.green + "Last Resolved: " + mycolors.reset +  i['last_resolved'], end='  ')
                    print(mycolors.reset + mycolors.foreground.green + "IP Address: " + mycolors.reset +  i['ip_address'], end="")

            if (hatext['hashes']):
                print(mycolors.foreground.cyan + "\n\nHashes:".ljust(13) + mycolors.reset, end=' ')
                print(mycolors.reset + "\n".ljust(14), end='')
                for i in hatext['hashes']:
                    print(mycolors.reset + str(i).ljust(14), end='\n'.ljust(14))

            if (hatext['emails']):
                print(mycolors.foreground.cyan + "\n\nEmails:".ljust(13) + mycolors.reset, end=' ')
                print(mycolors.reset + "\n".ljust(14), end='')
                for i in sorted(hatext['emails']):
                    print(mycolors.reset + str(i).ljust(14), end='\n'.ljust(14))

            if (hatext['subdomains']):
                print(mycolors.foreground.cyan + "\n\nSubdomains:".ljust(13) + mycolors.reset, end=' ')
                print(mycolors.reset + "\n".ljust(14), end='')
                for i in sorted(hatext['subdomains']):
                    print(mycolors.reset + str(i).ljust(14), end='\n'.ljust(14))

            if (hatext['references']):
                print(mycolors.foreground.cyan + "\n\nReferences:".ljust(13) + mycolors.reset, end=' ')
                print(mycolors.reset + "\n".ljust(14), end='')
                for i in hatext['references']:
                    print(mycolors.reset + ("\n".ljust(14)).join(textwrap.wrap(str(i),width=110)).ljust(14), end="\n".ljust(14))

    except ValueError as e:
        print(e)
        if (bkg == 1):
            print((mycolors.foreground.lightred + "Error while connecting to ThreatCrowd!\n"))
        else:
            print((mycolors.foreground.red + "Error while connecting to ThreatCrowd!\n"))
        print(mycolors.reset)


def threatcrowd_hash(urlx, arg1):

    hatext = ''
    haresponse = ''
    myargs = arg1

    try:
        resource = urlx
        requestsession = requests.Session( )
        requestsession.headers.update({'Content-Type': 'application/json'})
        finalurl = '/'.join([resource, 'file', 'report'])
        haresponse = requestsession.get(url=finalurl, params={"resource":myargs})
        hatext = json.loads(haresponse.text)

        if(hatext['response_code'] == '0'):
            if (bkg == 1):
                print(mycolors.foreground.yellow + "\nThe provided hash hasn't been found on ThreatCrowd.\n", mycolors.reset) 
                exit(0)
            if (bkg == 0):
                print(mycolors.foreground.purple + "\nThe provided hash hasn't been found on ThreatCrowd.\n", mycolors.reset) 
                exit(0)

        if(not '200' in str(haresponse)):
            if (bkg == 1):
                print(mycolors.foreground.lightred + "\nAn error has occured while accessing ThreatCrowd.\n", mycolors.reset) 
                exit(1)
            if (bkg == 0):
                print(mycolors.foreground.red + "\nAn error has occured while accessing ThreatCrowd.\n", mycolors.reset) 
                exit(1)

        if(bkg == 1):
            print(mycolors.foreground.yellow + "\nHash:".ljust(14) + mycolors.reset + myargs)

            if (hatext['md5']):
                print(mycolors.foreground.lightgreen + "\nMD5:".ljust(14) + mycolors.reset + hatext['md5'], end=' ')

            if (hatext['sha1']):
                print(mycolors.foreground.lightgreen + "\nSHA1:".ljust(14) + mycolors.reset + hatext['sha1'], end=' ')
                print(mycolors.foreground.lightgreen + "\nScans:".ljust(14) + mycolors.reset)

            if (hatext['scans']):
                print(mycolors.foreground.lightgreen + "\nAntivirus:".ljust(14) + mycolors.reset, end=' ')
                for i in sorted(hatext['scans']):
                    print(mycolors.reset + "\n".ljust(14) + mycolors.foreground.lightcyan + mycolors.reset +  i, end='  ')

            if (hatext['ips']):
                print(mycolors.foreground.lightgreen + "\nIPs:".ljust(14) + mycolors.reset, end=' ')
                for i in sorted(hatext['ips']):
                    print(mycolors.reset + "\n".ljust(14) + mycolors.foreground.lightcyan + mycolors.reset +  i, end='  ')

            if (hatext['domains']):
                print(mycolors.foreground.lightgreen + "\n\nDomains:".ljust(14) + mycolors.reset, end=' ')
                for i in sorted(hatext['domains']):
                    print(mycolors.reset + "\n".ljust(14) + mycolors.foreground.lightcyan + mycolors.reset +  i, end='  ')

            if (hatext['references']):
                print(mycolors.foreground.lightgreen + "\n\nReferences:".ljust(13) + mycolors.reset, end=' ')
                print(mycolors.reset + "\n".ljust(14), end='')
                for i in hatext['references']:
                    print(mycolors.reset + ("\n".ljust(14)).join(textwrap.wrap(str(i),width=110)).ljust(14), end="\n".ljust(14))

        if(bkg == 0):
            print(mycolors.foreground.yellow + "\nHash:".ljust(14) + mycolors.reset + myargs)

            if (hatext['md5']):
                print(mycolors.foreground.green + "\nMD5:".ljust(14) + mycolors.reset + hatext['md5'], end=' ')

            if (hatext['sha1']):
                print(mycolors.foreground.green + "\nSHA1:".ljust(14) + mycolors.reset + hatext['sha1'], end=' ')
                print(mycolors.foreground.green + "\nScans:".ljust(14) + mycolors.reset)

            if (hatext['scans']):
                print(mycolors.foreground.green + "\nAntivirus:".ljust(14) + mycolors.reset, end=' ')
                for i in sorted(hatext['scans']):
                    print(mycolors.reset + "\n".ljust(14) + mycolors.foreground.cyan + mycolors.reset +  i, end='  ')

            if (hatext['ips']):
                print(mycolors.foreground.green + "\nIPs:".ljust(14) + mycolors.reset, end=' ')
                for i in sorted(hatext['ips']):
                    print(mycolors.reset + "\n".ljust(14) + mycolors.foreground.cyan + mycolors.reset +  i, end='  ')

            if (hatext['domains']):
                print(mycolors.foreground.green + "\n\nDomains:".ljust(14) + mycolors.reset, end=' ')
                for i in sorted(hatext['domains']):
                    print(mycolors.reset + "\n".ljust(14) + mycolors.foreground.cyan + mycolors.reset +  i, end='  ')

            if (hatext['references']):
                print(mycolors.foreground.green + "\n\nReferences:".ljust(13) + mycolors.reset, end=' ')
                print(mycolors.reset + "\n".ljust(14), end='')
                for i in hatext['references']:
                    print(mycolors.reset + ("\n".ljust(14)).join(textwrap.wrap(str(i),width=110)).ljust(14), end="\n".ljust(14))

        print("\n")

    except ValueError as e:
        print(e)
        if (bkg == 1):
            print((mycolors.foreground.lightred + "Error while connecting to ThreatCrowd!\n"))
        else:
            print((mycolors.foreground.red + "Error while connecting to ThreatCrowd!\n"))
        print(mycolors.reset)


def threatcrowd_antivirus(urlx, arg1):

    hatext = ''
    haresponse = ''
    myargs = arg1

    try:
        resource = urlx
        requestsession = requests.Session( )
        requestsession.headers.update({'Content-Type': 'application/json'})
        finalurl = '/'.join([resource, 'antivirus', 'report'])
        haresponse = requestsession.get(url=finalurl, params={"antivirus":myargs})
        hatext = json.loads(haresponse.text)

        if(hatext['response_code'] == '0'):
            if (bkg == 1):
                print(mycolors.foreground.yellow + "\nThis name hasn't been found on ThreatCrowd.\n", mycolors.reset) 
                exit(0)
            if (bkg == 0):
                print(mycolors.foreground.purple + "\nThis name hasn't been found on ThreatCrowd.\n", mycolors.reset) 
                exit(0)

        if(not '200' in str(haresponse)):
            if (bkg == 1):
                print(mycolors.foreground.lightred + "\nAn error has occured while accessing ThreatCrowd.\n", mycolors.reset) 
                exit(1)
            if (bkg == 0):
                print(mycolors.foreground.red + "\nAn error has occured while accessing ThreatCrowd.\n", mycolors.reset) 
                exit(1)

        if(bkg == 1):
            print(mycolors.foreground.yellow + "\nName:".ljust(14) + mycolors.reset + myargs)

            if (hatext['hashes']):
                print(mycolors.foreground.lightgreen + "\nHashes:".ljust(14) + mycolors.reset, end='\n'.ljust(14))
                for k,i in enumerate(sorted(hatext['hashes']),-1):
                    if k % 3 == 2:
                        print(mycolors.reset + "\n".ljust(14) + mycolors.foreground.lightblue + f"{k+2:03}: " + mycolors.reset + i, end='  ')
                    else:
                        print(mycolors.reset + mycolors.foreground.lightblue + f"{k+2:03}: " + mycolors.reset + i, end='  ')

            if (hatext['references']):
                print(mycolors.foreground.lightgreen + "\n\nReferences:".ljust(13) + mycolors.reset, end=' ')
                print(mycolors.reset + "\n".ljust(14), end='')
                for i in hatext['references']:
                    print(mycolors.reset + ("\n".ljust(14)).join(textwrap.wrap(str(i),width=110)).ljust(14), end="\n".ljust(14))

        if(bkg == 0):
            print(mycolors.foreground.red + "\nName:".ljust(14) + mycolors.reset + myargs)

            if (hatext['hashes']):
                print(mycolors.foreground.green + "\nHashes:".ljust(14) + mycolors.reset, end='\n'.ljust(14))
                for k,i in enumerate(sorted(hatext['hashes']),-1):
                    if k % 3 == 2:
                        print(mycolors.reset + "\n".ljust(14) + mycolors.foreground.blue + f"{k+2:03}: " + mycolors.reset + i, end='  ')
                    else:
                        print(mycolors.reset + mycolors.foreground.blue + f"{k+2:03}: " + mycolors.reset + i, end='  ')

            if (hatext['references']):
                print(mycolors.foreground.green + "\n\nReferences:".ljust(13) + mycolors.reset, end=' ')
                print(mycolors.reset + "\n".ljust(14), end='')
                for i in hatext['references']:
                    print(mycolors.reset + ("\n".ljust(14)).join(textwrap.wrap(str(i),width=110)).ljust(14), end="\n".ljust(14))
    
    except ValueError as e:
        print(e)
        if (bkg == 1):
            print((mycolors.foreground.lightred + "Error while connecting to ThreatCrowd!\n"))
        else:
            print((mycolors.foreground.red + "Error while connecting to ThreatCrowd!\n"))
        print(mycolors.reset)


def valhalla_service(argx, arg1, VALHALLAPIx):

    hatext = ''
    haresponse = ''
    myarg0 = argx
    myarg1 = arg1

    try:

        vll = ValhallaAPI(api_key=VALHALLAAPIx)

        if (argx == 1):
            vllresponse = vll.get_rules_text(search=arg1)
        elif (argx == 2):
            vllresponse = vll.get_rules_text(score=int(arg1))
        elif (argx == 3):
            vllresponse = vll.get_rules_text(product=arg1)
        elif(argx == 4):
            vllresponse = vll.get_hash_info(hash=arg1)
        elif(argx == 5):
            vllresponse = vll.get_rule_info(rulename=arg1)
        else:
            print(mycolors.foreground.red + "\n\nYou haven't provided a valid value for the Valhalla service!\n" + mycolors.reset,end="\n")
            exit(1)

        if (argx < 4):
            if "Number of Rules: 0" in (vllresponse):
                if(bkg==1):
                    print(mycolors.foreground.yellow + "\nYara rules for the provided argument haven't been found on Valhalla!\n" + mycolors.reset,end="\n")
                    exit(0)
                else:
                    print(mycolors.foreground.blue + "\nYara rules for the provided argument haven't been found on Valhalla!\n" + mycolors.reset,end="\n")
                    exit(0)

        if (argx < 4):
            with open('valhalla-rules.yar', 'w') as fh:
                fh.write(vllresponse)

        if((argx == 2) or (argx == 3)):
            with open('valhalla-rules.yar','r') as fr: 
                for x in range(28):
                    z = fr.readline()
                    y = re.search("^rule", z)
                    if (y is not None):
                        if(bkg == 1):
                            print(mycolors.foreground.lightgreen + z,end='')
                        else:
                            print(mycolors.foreground.cyan + z,end='')
                    else:
                        print(mycolors.reset + z,end='')
                
                print("\n......further content can be found in the valhalla-rules.yar file......")
            fr.close()

        if((argx == 1)):
            with open('valhalla-rules.yar','r') as fr: 
                for x in fr:
                    z = fr.readline()
                    y = re.search("^rule", z)
                    if (y is not None):
                        if(bkg == 1):
                            print(mycolors.foreground.lightgreen + z,end='')
                        else:
                            print(mycolors.foreground.cyan + z,end='')
                    else:
                        print(mycolors.reset + z,end='')

            fr.close()

        if(argx == 4):
            if (vllresponse['status'] == "empty"): 
                if(bkg == 1):
                    print(mycolors.foreground.lightred + "\n\nThere isn't any rule associated to this hash on Valhalla service.\n" + mycolors.reset, end="\n")
                else:
                    print(mycolors.foreground.red + "\n\nThere isn't any rule associated to this hash on Valhalla service.\n" + mycolors.reset, end="\n")
                exit(0)

            if (vllresponse['status'] != "empty"):
                j = 0

                if(bkg == 1):
                    while j < len(vllresponse['results']):
                        if 'rulename' in vllresponse['results'][j]:
                            print(mycolors.foreground.yellow + "\nRulename:".ljust(13) + mycolors.reset + str(vllresponse['results'][j]['rulename']))
                        if 'positives' in vllresponse['results'][j]:
                            print(mycolors.foreground.lightgreen + "Positives:".ljust(12) + mycolors.reset + str(vllresponse['results'][j]['positives']))
                        if 'timestamp' in vllresponse['results'][j]:
                            print(mycolors.foreground.lightgreen + "Timestamp:".ljust(12) + mycolors.reset + str(vllresponse['results'][j]['timestamp']))
                        if 'total' in vllresponse['results'][j]:
                            print(mycolors.foreground.lightgreen + "Total:".ljust(12) + mycolors.reset + str(vllresponse['results'][j]['total']))
                        if 'tags' in vllresponse['results'][j]:
                            print(mycolors.foreground.lightgreen + "Tags:".ljust(12), end='')
                            for i in vllresponse['results'][j]['tags']: 
                                print(mycolors.reset + i, end=' ')
                            print(mycolors.reset)

                        j = j + 1

                    print(mycolors.reset)
                    exit(0)

                if(bkg == 0):
                    while j < len(vllresponse['results']):
                        if 'rulename' in vllresponse['results'][j]:
                            print(mycolors.foreground.red + "\nRulename:".ljust(13) + mycolors.reset + str(vllresponse['results'][j]['rulename']))
                        if 'positives' in vllresponse['results'][j]:
                            print(mycolors.foreground.cyan + "Positives:".ljust(12) + mycolors.reset + str(vllresponse['results'][j]['positives']))
                        if 'timestamp' in vllresponse['results'][j]:
                            print(mycolors.foreground.cyan + "Timestamp:".ljust(12) + mycolors.reset + str(vllresponse['results'][j]['timestamp']))
                        if 'total' in vllresponse['results'][j]:
                            print(mycolors.foreground.cyan + "Total:".ljust(12) + mycolors.reset + str(vllresponse['results'][j]['total']))
                        if 'tags' in vllresponse['results'][j]:
                            print(mycolors.foreground.cyan + "Tags:".ljust(12), end='')
                            for i in vllresponse['results'][j]['tags']: 
                                print(mycolors.reset + i, end=' ')
                            print(mycolors.reset)

                        j = j + 1

                    print(mycolors.reset)
                    exit(0)

        if(argx == 5):
            if ('status' in vllresponse): 
                if (vllresponse['status'] == 'error'):
                    if(bkg == 1):
                        print(mycolors.foreground.lightred + "\n\nThere isn't any information associated to this rule name on Valhalla service.\n" + mycolors.reset, end="\n")
                    else:
                        print(mycolors.foreground.red + "\n\nThere isn't any information associated to this rule name on Valhalla service.\n" + mycolors.reset, end="\n")
                print(mycolors.reset)
                exit(0)

            if ("name" in vllresponse):
                j = 0

                if(bkg == 1):
                    if 'description' in vllresponse:
                        print(mycolors.foreground.yellow + "\nDescription:".ljust(15) + mycolors.reset + str(vllresponse['description']))
                    if 'author' in vllresponse:
                        print(mycolors.foreground.lightcyan + "Author:".ljust(14) + mycolors.reset + str(vllresponse['author']))
                    if 'date' in vllresponse:
                        print(mycolors.foreground.lightcyan + "Date:".ljust(14) + mycolors.reset + str(vllresponse['date']))
                    if 'reference' in vllresponse:
                        print(mycolors.foreground.lightcyan + "Reference:".ljust(14) + mycolors.reset + str(vllresponse['reference']))
                    if 'minimum_yara' in vllresponse:
                        print(mycolors.foreground.lightcyan + "Minimum_Yara:".ljust(14) + mycolors.reset + str(vllresponse['minimum_yara']))
                    if 'required_modules' in vllresponse:
                        print(mycolors.foreground.lightcyan + "Modules: ".ljust(14), end='')
                        for n in vllresponse['required_modules']:
                            print(mycolors.reset + n, end=' ')
                        print(mycolors.reset)
                    if 'score' in vllresponse:
                        print(mycolors.foreground.lightgreen + "Score:".ljust(14) + mycolors.reset + str(vllresponse['score']))
                    if 'tags' in vllresponse:
                        print(mycolors.foreground.lightgreen + "Tags: ".ljust(14), end='')
                        for m in vllresponse['tags']:
                            print(mycolors.reset + m, end=' ')
                        print(mycolors.reset)
                    if 'av_ratio' in vllresponse:
                        print(mycolors.foreground.lightgreen + "AV_ratio:".ljust(14) + mycolors.reset + str(vllresponse['av_ratio']))
                    if 'av_verdicts' in vllresponse:
                        print(mycolors.foreground.lightgreen + "\nAV_verdicts:".ljust(14) + mycolors.reset, end='')
                        if 'clean' in vllresponse['av_verdicts']:
                            print(mycolors.foreground.pink + "\n".ljust(15) + "clean:".ljust(14) + mycolors.reset + str(vllresponse['av_verdicts']['clean']), end='')
                        if 'malicious' in vllresponse['av_verdicts']:
                            print(mycolors.foreground.pink + "\n".ljust(15) + "malicious:".ljust(14) + mycolors.reset + str(vllresponse['av_verdicts']['malicious']), end='')
                        if 'suspicious' in vllresponse['av_verdicts']:
                            print(mycolors.foreground.pink + "\n".ljust(15) + "suspicious:".ljust(14) + mycolors.reset + str(vllresponse['av_verdicts']['suspicious']))
                    if 'rule_matches' in vllresponse:
                        print(mycolors.foreground.lightgreen + "\nRule_matches:".ljust(14) + mycolors.reset, end='')
                        k = 0
                        while k < len(vllresponse['rule_matches']):
                            if ('hash' in vllresponse['rule_matches'][k]):
                                print(mycolors.foreground.pink + "\n\n".ljust(16) + "hash:".ljust(14) + mycolors.reset + str(vllresponse['rule_matches'][k]['hash']), end='')
                            if ('positives' in vllresponse['rule_matches'][k]):
                                print(mycolors.foreground.pink + "\n".ljust(15) + "positives:".ljust(14) + mycolors.reset + str(vllresponse['rule_matches'][k]['positives']), end='')
                            if ('size' in vllresponse['rule_matches'][k]):
                                print(mycolors.foreground.pink + "\n".ljust(15) + "size:".ljust(14) + mycolors.reset + str(vllresponse['rule_matches'][k]['size']), end='')
                            if ('timestamp' in vllresponse['rule_matches'][k]):
                                print(mycolors.foreground.pink + "\n".ljust(15) + "timestamp:".ljust(14) + mycolors.reset + str(vllresponse['rule_matches'][k]['timestamp']), end='')
                            if ('total' in vllresponse['rule_matches'][k]):
                                print(mycolors.foreground.pink + "\n".ljust(15) + "total:".ljust(14) + mycolors.reset + str(vllresponse['rule_matches'][k]['total']), end='')

                            k = k + 1

                    print(mycolors.reset)
                    exit(0)

                if(bkg == 0):
                    if 'description' in vllresponse:
                        print(mycolors.foreground.red + "\nDescription:".ljust(15) + mycolors.reset + str(vllresponse['description']))
                    if 'author' in vllresponse:
                        print(mycolors.foreground.blue + "Author:".ljust(14) + mycolors.reset + str(vllresponse['author']))
                    if 'date' in vllresponse:
                        print(mycolors.foreground.blue + "Date:".ljust(14) + mycolors.reset + str(vllresponse['date']))
                    if 'reference' in vllresponse:
                        print(mycolors.foreground.blue + "Reference:".ljust(14) + mycolors.reset + str(vllresponse['reference']))
                    if 'minimum_yara' in vllresponse:
                        print(mycolors.foreground.blue + "Minimum_Yara:".ljust(14) + mycolors.reset + str(vllresponse['minimum_yara']))
                    if 'required_modules' in vllresponse:
                        print(mycolors.foreground.blue + "Modules: ".ljust(14), end='')
                        for n in vllresponse['required_modules']:
                            print(mycolors.reset + n, end=' ')
                        print(mycolors.reset)
                    if 'score' in vllresponse:
                        print(mycolors.foreground.green + "Score:".ljust(14) + mycolors.reset + str(vllresponse['score']))
                    if 'tags' in vllresponse:
                        print(mycolors.foreground.green + "Tags: ".ljust(14), end='')
                        for m in vllresponse['tags']:
                            print(mycolors.reset + m, end=' ')
                        print(mycolors.reset)
                    if 'av_ratio' in vllresponse:
                        print(mycolors.foreground.green + "AV_ratio:".ljust(14) + mycolors.reset + str(vllresponse['av_ratio']))
                    if 'av_verdicts' in vllresponse:
                        print(mycolors.foreground.green + "\nAV_verdicts:".ljust(14) + mycolors.reset, end='')
                        if 'clean' in vllresponse['av_verdicts']:
                            print(mycolors.foreground.purple + "\n".ljust(15) + "clean:".ljust(14) + mycolors.reset + str(vllresponse['av_verdicts']['clean']), end='')
                        if 'malicious' in vllresponse['av_verdicts']:
                            print(mycolors.foreground.purple + "\n".ljust(15) + "malicious:".ljust(14) + mycolors.reset + str(vllresponse['av_verdicts']['malicious']), end='')
                        if 'suspicious' in vllresponse['av_verdicts']:
                            print(mycolors.foreground.purple + "\n".ljust(15) + "suspicious:".ljust(14) + mycolors.reset + str(vllresponse['av_verdicts']['suspicious']))
                    if 'rule_matches' in vllresponse:
                        print(mycolors.foreground.green + "\nRule_matches:".ljust(14) + mycolors.reset, end='')
                        k = 0
                        while k < len(vllresponse['rule_matches']):
                            if ('hash' in vllresponse['rule_matches'][k]):
                                print(mycolors.foreground.purple + "\n\n".ljust(16) + "hash:".ljust(14) + mycolors.reset + str(vllresponse['rule_matches'][k]['hash']), end='')
                            if ('positives' in vllresponse['rule_matches'][k]):
                                print(mycolors.foreground.purple + "\n".ljust(15) + "positives:".ljust(14) + mycolors.reset + str(vllresponse['rule_matches'][k]['positives']), end='')
                            if ('size' in vllresponse['rule_matches'][k]):
                                print(mycolors.foreground.purple + "\n".ljust(15) + "size:".ljust(14) + mycolors.reset + str(vllresponse['rule_matches'][k]['size']), end='')
                            if ('timestamp' in vllresponse['rule_matches'][k]):
                                print(mycolors.foreground.purple + "\n".ljust(15) + "timestamp:".ljust(14) + mycolors.reset + str(vllresponse['rule_matches'][k]['timestamp']), end='')
                            if ('total' in vllresponse['rule_matches'][k]):
                                print(mycolors.foreground.purple + "\n".ljust(15) + "total:".ljust(14) + mycolors.reset + str(vllresponse['rule_matches'][k]['total']), end='')

                            k = k + 1

                    print(mycolors.reset)
                    exit(0)

        if(bkg==1):
            print(mycolors.foreground.yellow + "\n\nThe Yara rules have been saved into the \"valhalla-rules.yar\" file.\n" + mycolors.reset,end="\n")
            exit(0)
        else:
            print(mycolors.foreground.purple + "\n\nThe Yara rules have been saved into the \"valhalla-rules.yar\" file.\n" + mycolors.reset,end="\n")
            exit(0)


    except ValueError as e:
        print(e)
        if (bkg == 1):
            print((mycolors.foreground.lightred + "Error while connecting to Valhalla!\n"))
        else:
            print((mycolors.foreground.red + "Error while connecting to Valhalla!\n"))
        print(mycolors.reset)


def quickhashowAndroid(filehash):

    hatext = ''
    haresponse = ''
    final = 'Yes'
    verdict = '-'
    avdetect = '0'
    totalsignatures = '-'
    threatscore = '-'
    totalprocesses = '-'
    networkconnections = '-'

    try:

        resource = filehash
        requestsession = requests.Session( )
        requestsession.headers.update({'user-agent': user_agent})
        requestsession.headers.update({'api-key': HAAPI})
        requestsession.headers.update({'content-type': 'application/x-www-form-urlencoded'})
        finalurl = '/'.join([haurl,'report', 'summary'])
        resource1 = resource + ":200"
        datahash = {
                'hashes[0]': resource1
                }

        haresponse = requestsession.post(url=finalurl, data = datahash)
        hatext = json.loads(haresponse.text)

        rc = str(hatext)

        if 'message' in rc:
            final = 'Not Found'
            return (final, verdict, avdetect, totalsignatures, threatscore, totalprocesses, networkconnections)


    except ValueError as e:
        print(e)
        if (bkg == 1):
            print((mycolors.foreground.lightred + "Error while connecting to Alien Vault!\n"))
        else:
            print((mycolors.foreground.red + "Error while connecting to Alien Vault!\n"))
        print(mycolors.reset)


def quickhashowAndroid(filehash):

    hatext = ''
    haresponse = ''
    final = 'Yes'
    verdict = '-'
    avdetect = '0'
    totalsignatures = '-'
    threatscore = '-'
    totalprocesses = '-'
    networkconnections = '-'

    try:

        resource = filehash
        requestsession = requests.Session( )
        requestsession.headers.update({'user-agent': user_agent})
        requestsession.headers.update({'api-key': HAAPI})
        requestsession.headers.update({'content-type': 'application/x-www-form-urlencoded'})
        finalurl = '/'.join([haurl,'report', 'summary'])
        resource1 = resource + ":200"
        datahash = {
                'hashes[0]': resource1
                }

        haresponse = requestsession.post(url=finalurl, data = datahash)
        hatext = json.loads(haresponse.text)

        rc = str(hatext)

        if 'message' in rc:
            final = 'Not Found'
            return (final, verdict, avdetect, totalsignatures, threatscore, totalprocesses, networkconnections)

        if 'verdict' in hatext[0]:
            verdict = str(hatext[0]['verdict'])
        else:
            verdict = ''

        if 'threat_score' in hatext[0]:
            threatscore = str(hatext[0]['threat_score'])
        else:
            threatscore = ''

        if 'av_detect' in hatext[0]:
            avdetect = str(hatext[0]['av_detect'])
        else:
            avdetect = ''

        if 'total_signatures' in hatext[0]:
            totalsignatures = str(hatext[0]['total_signatures'])
        else:
            totalsignatures = ''

        if 'total_processes' in hatext[0]:
            totalprocesses = str(hatext[0]['total_processes'])
        else:
            totalprocesses = ''

        if 'total_network_connections' in hatext[0]:
            networkconnections =  str(hatext[0]['total_network_connections'])
        else:
            networkconnections = ''

        return (final, verdict, avdetect, totalsignatures, threatscore, totalprocesses, networkconnections)

    except ValueError as e:
        print(e)
        if (bkg == 1):
            print((mycolors.foreground.lightred + "Error while connecting to Hybrid-Analysis!\n"))
        else:
            print((mycolors.foreground.red + "Error while connecting to Hybrid-Analysis!\n"))
        print(mycolors.reset)


class androidVTThread(threading.Thread):

    def __init__(self, key, package):

        threading.Thread.__init__(self)
        self.key = key
        self.package = package

    def run(self):

        key1 = self.key
        package1 = self.package

        myhash = key1
        vtfinal = vtcheck(myhash, url, param)
    
        if (bkg == 1):
            print((mycolors.foreground.orange +  "%-50s" % package1), end=' ')
            print((mycolors.foreground.lightcyan +  "%-32s" % key1), end=' ')
            print((mycolors.reset + mycolors.foreground.lightgreen + "%8s" % vtfinal + mycolors.reset))
        else:
            print((mycolors.foreground.green + "%-08s" % package1), end=' ')
            print((mycolors.foreground.cyan + "%-32s" % key1), end=' ')
            print((mycolors.reset + mycolors.foreground.red + "%8s" % vtfinal + mycolors.reset))


class quickHAAndroidThread(threading.Thread):

    def __init__(self, key, package):

        threading.Thread.__init__(self)
        self.key = key
        self.package = package

    def run(self):

        key1 = self.key
        package1 = self.package

        myhash = key1
        (final, verdict, avdetect, totalsignatures, threatscore, totalprocesses, networkconnections) =  quickhashowAndroid(myhash)

        if (bkg == 1):
            print((mycolors.foreground.lightgreen + "%-50s" % package1), end=' ')
            print((mycolors.foreground.yellow + "%-34s" % key1), end=' ')
            print((mycolors.foreground.lightcyan + "%9s" % final), end='')
            if (verdict == "malicious"):
                print((mycolors.foreground.lightred + "%20s" % verdict), end='')
            else:
                print((mycolors.foreground.yellow + "%20s" % verdict), end='')
            if(avdetect == 'None'):
                print((mycolors.foreground.lightcyan + "%7s" % avdetect), end='')
            else:
                print((mycolors.foreground.lightcyan + "%6s%%" % avdetect), end='')
            print((mycolors.foreground.orange + "%7s" % totalsignatures), end='')
            if(threatscore == 'None'):
                print((mycolors.foreground.lightred + "%12s" % threatscore), end='')
            else:
                print((mycolors.foreground.lightred + "%8s/100" % threatscore), end='')
            print((mycolors.foreground.lightgreen + "%6s" % totalprocesses), end='')
            print((mycolors.foreground.lightgreen + "%6s" % networkconnections + mycolors.reset))
        else:
            print((mycolors.foreground.lightcyan + "%-50s" % key1), end=' ')
            print((mycolors.foreground.green + "%-34s" % key1), end=' ')
            print((mycolors.foreground.cyan + "%9s" % final), end='')
            if (verdict == "malicious"):
                print((mycolors.foreground.red + "%20s" % verdict), end='')
            else:
                print((mycolors.foreground.green + "%20s" % verdict), end='')
            if (avdetect == 'None'):
                print((mycolors.foreground.purple + "%7s" % avdetect), end='')
            else:
                print((mycolors.foreground.purple + "%6s%%" % avdetect), end='')
            print((mycolors.foreground.green + "%7s" % totalsignatures), end='')
            if(threatscore == 'None'):
                print((mycolors.foreground.red + "%12s" % threatscore), end='')
            else:
                print((mycolors.foreground.red + "%8s/100" % threatscore), end='')
            print((mycolors.foreground.blue + "%6s" % totalprocesses), end='')
            print((mycolors.foreground.blue + "%6s" % networkconnections + mycolors.reset))


def checkandroidha(key, package):

    if (windows == 1):
        thread = quickHAAndroidThread(key, package)
        thread.start()
        thread.join()
    else:
        thread = quickHAAndroidThread(key, package)
        thread.start()


def checkandroidvt(key, package):

    key1 = key
    vtfinal = vtcheck(key1, url, param)
    if (bkg == 1):
        print((mycolors.foreground.orange +  "%-50s" % package), end=' ')
        print((mycolors.foreground.lightcyan +  "%-32s" % key1), end=' ')
        print((mycolors.reset + mycolors.foreground.lightgreen + "%8s" % vtfinal + mycolors.reset))
    else:
        print((mycolors.foreground.green + "%-08s" % package), end=' ')
        print((mycolors.foreground.cyan + "%-32s" % key1), end=' ')
        print((mycolors.reset + mycolors.foreground.red + "%8s" % vtfinal + mycolors.reset))


def checkandroidvtx(key, package):

    if (windows == 1):
        thread = androidVTThread(key, package)
        thread.start()
        thread.join()
    else:
        thread = androidVTThread(key, package)
        thread.start()


def checkandroid(engine):

    adb_comm = "adb"
    results = list()
    results2 = list()
    final1 = list()
    final2 = list()

    localengine = engine
    tm1 = 0

    myconn = subprocess.run([adb_comm, "shell", "pm", "list", "packages", "-f", "-3"], capture_output=True)
    myconn2 = myconn.stdout.decode()

    try:
        for i in myconn2.split('\n'):
            for j in i.split('base.apk='):
                if 'package' in j:
                    key, value = j.split('package:')
                    key2, value2 = value.split('/data/app/')
                    results.append(value2[:-3])
                    valuetmp = value + "base.apk"
                    results2.append(valuetmp)

    except AttributeError:
        pass

    try:
        for h in results2:
            myconn3 = subprocess.run([adb_comm, "shell", "md5sum", h], text=True, capture_output=True)
            x = myconn3.stdout.split(" ")[0]
            final1.append(x)

    except AttributeError:
        pass

    try:
        for n in results:
            final2.append(n)

    except AttributeError:
        pass

    zipAndroid = zip(final2, final1)
    dictAndroid = dict(zipAndroid)

    if(engine == 1):

        print(mycolors.reset + "\n")
        print("Package".center(50) + "Hash".center(34) + "Found?".center(12) + "Verdict".center(23) + "AVdet".center(6) + "Sigs".center(5) + "Score".center(14) + "Procs".center(6) + "Conns".center(6))
        print((160*'-').center(80))
        for key, value in dictAndroid.items():
            checkandroidha(value, key)

    if(engine == 2):
        print(mycolors.reset + "\n")
        print("Package".center(50) +  "Hash".center(36) + "Virus Total".center(12))
        print((100*'-').center(50))
        for key, value in dictAndroid.items():
            tm1 = tm1 + 1
            if tm1 % 4 == 0:
                time.sleep(61)
            checkandroidvt(value, key)

    if(engine == 3):
        print(mycolors.reset + "\n")
        print("Package".center(50) +  "Hash".center(36) + "Virus Total".center(12))
        print((100*'-').center(50))
        for key, value in dictAndroid.items():
            checkandroidvtx(value, key)

def sendandroidha(package):

    adb_comm = "adb"
    results = list()
    results2 = list()
    final1 = list()
    final2 = list()
    newname= ''

    myconn = subprocess.run([adb_comm, "shell", "pm", "list", "packages", "-f", "-3"], capture_output=True)
    myconn2 = myconn.stdout.decode()

    try:
        for i in myconn2.split('\n'):
            for j in i.split('base.apk='):
                if 'package' in j:
                    key, value = j.split('package:')
                    key2, value2 = value.split('/data/app/')
                    results.append(value2)
                    valuetmp = value + "base.apk"
                    results2.append(valuetmp)

    except AttributeError:
        pass

    try:
        for j in results2:
            if (package in j):
                myconn3 = subprocess.run([adb_comm, "pull", j], capture_output=True)
                newname = j[10:-9]

    except AttributeError:
        pass

    try:
        targetfile = newname + ".apk"
        os.rename(r'base.apk',targetfile)
        hafilecheck(targetfile)
    
    except FileNotFoundError:
        
        if (bkg == 1):
            print((mycolors.foreground.lightred + "\nFile not found on device!\n"))
        else:
            print((mycolors.foreground.lightred + "\nFile not found on device!\n"))
        exit(1)

    finally:
        if (targetfile != ".apk"):
            os.remove(targetfile)


def sendandroidvt(package):

    adb_comm = "adb"
    results = list()
    results2 = list()
    final1 = list()
    final2 = list()
    newname= ''

    myconn = subprocess.run([adb_comm, "shell", "pm", "list", "packages", "-f", "-3"], capture_output=True)
    myconn2 = myconn.stdout.decode()

    try:
        for i in myconn2.split('\n'):
            for j in i.split('base.apk='):
                if 'package' in j:
                    key, value = j.split('package:')
                    key2, value2 = value.split('/data/app/')
                    results.append(value2)
                    valuetmp = value + "base.apk"
                    results2.append(valuetmp)

    except AttributeError:
        pass

    try:
        for j in results2:
            if (package in j):
                myconn3 = subprocess.run([adb_comm, "pull", j], capture_output=True)
                newname = j[10:-9]

    except AttributeError:
        pass

    try:
        targetfile = newname + ".apk"
        os.rename(r'base.apk',targetfile)
        vtfilecheck(targetfile, urlfilevtcheck, param)

    except FileNotFoundError:
        
        if (bkg == 1):
            print((mycolors.foreground.lightred + "\nFile not found on device!\n"))
        else:
            print((mycolors.foreground.lightred + "\nFile not found on device!\n"))
        print(mycolors.reset)
        exit(1)

    finally:
        if (targetfile != ".apk"):
            os.remove(targetfile)


def dirchecking(repo2):

    directory = repo2
    if os.path.isabs(directory) == False:
        directory = os.path.abspath('.') + "/" + directory
    os.chdir(directory)

    for filen in os.listdir(directory):
        try:

            filename = str(filen)
            if(os.path.isdir(filename) == True):
                continue
            targetfile = ftype(filename)
            if re.match(r'^PE[0-9]{2}|^MS-DOS', targetfile):
                mype = pefile.PE(filename)
                imph = mype.get_imphash()
                F.append(filename)
                H.append(imph)
            else:
                F.append(filename)
                H.append("IT IS NOT A KNOW FORMAT")

        except (AttributeError, NameError) as e:
            if (bkg == 1):
                print(mycolors.foreground.lightred + "\nThe file %s doesn't respect some PE format rules. Skipping this file..." % filename)
            else:
                print(mycolors.foreground.red + "\nThe file %s doesn't respect some PE format rules. Skipping this file..." % filename)
            print(mycolors.reset)
            pass


    d = dict(list(zip(F,H)))
    n = 30
    prev1 = 0
    prev2 = 0
    result = ""
    tm = 0

    print((mycolors.reset + "\n"))

    if(Q == 1):
        dirquick(d)
        exit(0)

    print("FileName".center(65) +  "ImpHash(PE32/PE32+) or Type".center(40) + "Packed?".center(9) + "Overlay?".center(10) + ".text_entropy".center(13) + "VT".center(8))
    print((32*'-').center(32) +  (36*'-').center(35) + (11*'-').center(10) + (10*'-').ljust(10) + (13*'-').center(13) + (42*'-').center(22))

    dirwork(d)


if __name__ == "__main__":

    windows = ''
    if platform.system() == 'Windows':
        USER_HOME_DIR = str(Path.home()) + '\\'
        init(convert = True)
        windows == 1
    else:
        USER_HOME_DIR = str(Path.home()) + '/'
        windows == 0

    backg = 1
    virustotal = 0
    fprovided = 0
    fpname = ''
    repo = ''
    ovrly = 0
    showreport = 0
    gt = 0
    ie = 0
    ha = 0
    urltemp = ''
    domaintemp = ''
    urlcheck = 0
    domaincheck = 0
    hashcheck = 0
    filecheck = 0
    filecheckha = 0
    hashtemp = ''
    filetemp = ''
    download = 0
    sysenviron = 0
    filenameha = ''
    fileha = ''
    reportha = ''
    multithread = 0
    malsharelist = 0
    malsharehash = ''
    urlhaussubmit = ''
    urlhausquery = ''
    hausbatch = 0
    hauspayloadbatch = 0
    haushash = ''
    hausdownloadpayload = ''
    filecheckpoly = 0
    polycheck = 0
    polyswarmscan = ''
    polyswarmhash = ''
    polyswarmmeta = ''
    androidha = 0
    androidsendha = ''  
    androidsendvt = ''  
    androidvtx = 0  
    androidvttx = 0  
    haustagsearch = ''
    haussigsearch = ''
    ipaddrvt = ''
    metatype = 0
    alienvault = 0
    alienvaultargs = ''
    Q = 0
    T = 0 
    malpedia = 0
    malpediax = 0
    malpediaarg = ''
    malpediaargx = ''
    threadcrowd = 0
    threatcrowdarg = 0
    valhalla = 0
    valhallaarg = ''
    VALHALLAAPIx = ''
    bazaar = 0
    bazaararg = ''

    parser = argparse.ArgumentParser(prog=None, description="Malwoverview is a first response tool for threat hunting written by Alexandre Borges. This version is 4.3.2", usage= "python malwoverview.py -c <API configuration file> -d <directory> -f <fullpath> -o <0|1> -v <0|1|2|3> -a <0|1|2|3|4|5> -x <0|1> -w <0|1> -u <url> -H <hash file> -V <filename> -D <0|1> -e <0|1|2|3|4> -A <filename> -g <job_id> -r <domain> -t <0|1> -l <1-14> -L <hash> -U <url> -S <url> -z <tags> -K <0|1|2> -j <hash> -J <hash> -P <filename> -R <PE file, IP address, domain or URL> -G <0|1|2|3|4> -y <0|1|2|3> -Y <file name> -Y <file name> -T <file name> -W <tag> -k <signature> -I <ip address> -n <1|2|3|4|5> -N <argument> -M <1-8> -m <argument> -Q <1-5> -q <argument> -E <1|2|3|4|5> -C <argument> -b <'1|2|3|4|5|6|7|8|9|10> -B <arg>")
    parser.add_argument('-c', '--config', dest='config', type=str, metavar = "CONFIG FILE", default = (USER_HOME_DIR + '.malwapi.conf'), help='Use a custom config file to specify API\'s')
    parser.add_argument('-d', '--directory', dest='direct',type=str, metavar = "DIRECTORY", help='Specifies the directory containing malware samples.')
    parser.add_argument('-f', '--filename', dest='fpname',type=str, metavar = "FILENAME", default = '', help='Specifies a full path to a malware sample. It returns general information about the file (any filetype)')
    parser.add_argument('-o', '--background', dest='backg', type=int,default = 1, metavar = "BACKGROUND", help='Adapts the output colors to a white terminal. The default is black terminal')
    parser.add_argument('-x', '--overlay', dest='over', type=int,default = 0, metavar = "OVERLAY", help='Extracts the overlay (it is used with -f option).')
    parser.add_argument('-v', '--virustotal', dest='virustotal', type=int,default = 0, metavar = "VIRUSTOTAL", help='If using "-v 1", so it queries the Virus Total database for positives and totals. If "v 2" (which can be used only together with -f option), so it shows antivirus reports from the main players. If "v 3", so the binary\'s IAT and EAT are also shown. Remember: you need to edit the .malwapi.conf and insert your VT API.')
    parser.add_argument('-a', '--hybrid', dest='hybridanalysis', type=int,default = 0, metavar = "HYBRID_ANALYSIS", help='Queries the Hybrid Analysis database for getting a general report. Possible values are: 1: Windows 7 32-bit; 2: Windows 7 32-bit (HWP Support); 3: Windows 64-bit; 4: Android; 5: Linux 64-bit. Remember: you need to edit the .malwapi.conf and insert your HA API and secret.')
    parser.add_argument('-u', '--vturl', dest='urlx', type=str, metavar = "URL_VT", help='SUBMITS a URL to the Virus Total scanning.')
    parser.add_argument('-I', '--ipaddrvt', dest='ipaddrvt', type=str, metavar = "IP_VT", help='This option checks an IP address on Virus Total.')
    parser.add_argument('-r', '--urldomain', dest='domainx', type=str, metavar = "URL_DOMAIN", help='This option gets a domain\'s report from Virus Total.')
    parser.add_argument('-H', '--hash', dest='filehash', type=str, metavar = "FILE_HASH", help='This option specifies the hash to be checked on Virus Total and Hybrid Analysis. For the Hybrid Analysis report you must use it with the -e option.')
    parser.add_argument('-V', '--vtsubmit', dest='filenamevt', type=str, metavar = "FILENAME_VT", help='Submits a file(up to 32MB) for Virus Total scanning and gets the report. Attention: use forward slash to specify the target file even on Windows systems. Furthermore, the minimum waiting time is set up in 90 seconds because the Virus Total waiting queue. If an error occurs, so wait few minutes and try to access the report by using -f option.')
    parser.add_argument('-A', '--submitha', dest='filenameha', type=str, metavar = "SUBMIT_HA", help='Submits a file(up to 32MB) to be scanned by the Hybrid Analysis engine. Use the -e option to specify the best environment to run the suspicious file.')
    parser.add_argument('-g', '--hastatus', dest='reportha', type=str, metavar = "HA_STATUS",  help='Checks the report\'s status of submitted samples to Hybrid Analysis engine by providing the job ID. Possible returned status values are: IN_QUEUE, SUCCESS, ERROR, IN_PROGRESS and PARTIAL_SUCCESS.')
    parser.add_argument('-D', '--download', dest='download', type=int,default = 0, metavar = "DOWNLOAD", help='Downloads the sample from Hybrid Analysis, Malshare and Polyswarm. Options -H or -L (Hybrid Analysis and Malshare, respectively) must be specified as well -O option for Polyswarm engine.')
    parser.add_argument('-e', '--haenv', dest='sysenviron', type=int,default = 0, metavar = "HA_ENVIRONMENT", help='This option specifies the used environment to be used to test the samlple on Hybrid Analysis: <0> Windows 7 32-bits; <1> Windows 7 32-bits (with HWP Support); <2> Windows 7 64-bits; <3> Android; <4> Linux 64-bits environment. This option is used together either -H option or the -A option.')
    parser.add_argument('-t', '--thread', dest='multithread', type=int,default = 0, metavar = "MULTITHREAD", help='(optional) This option has several different meanings according to chosen the value. Possible values: <1>: This value is used to force multithreads on Linux whether: the -d option is specified AND you have a PAID Virus Total API or you are NOT checking the VT while using the -d option. PS1: using this option causes Imphashes not to be grouped anymore; PS2: it also works on Windows, but there is not gain in performance; <2>: This value should be used with -d option in two scenarios: 1) either including the "-v 1" option (Virus Total -- you\'ll see a complete VT response whether you have the private API) for a multithread searching and reduced output; 2) or including the -a option (Hybrid Analysis) for a multithread searching to get a complete and amazing output. If you are using the -a option, so you should pickup the right number represening the testing environment to adjust the output to your sample types. PS1: certainly, if you have a directory holding many malware samples, so you will want to test this option with -a option; PS2: it also works on Windows, but there is not gain in performance; <3>: You should use this value with -v option if you have a public Virus Total API. It forces a one minute wait every 4 malware samples, but allows obtaining a complete evaluation of the malware repository.')
    parser.add_argument('-l', '--malsharelist', dest='malsharelist', type=int,default = 0, metavar = "MALSHARE_HASHES", help='This option shows hashes of a specific type from the last 24 hours from Malshare repository. Possible values are:  1: PE32 (default) ; 2: Dalvik ; 3: ELF ; 4: HTML ; 5: ASCII ; 6: PHP ; 7: Java ; 8: RAR ; 9: Zip ; 10: UTF-8 ; 11: MS-DOS ; 12: data ; 13: PDF ; 14: Composite(OLE). You need to insert your Malshare API into the .malwapi.conf file.')
    parser.add_argument('-L', '--malsharehash', dest='malsharehash', type=str, metavar = "MALSHARE_HASH_SEARCH", help='Searches for the provided hash on the  Malshare repository. You need to insert your Malshare API into the .malwapi.conf file. PS: sometimes the Malshare website is unavailable, so should check the website availability if you get some error message.')
    parser.add_argument('-K', '--haus_payloadbatch', dest='hauspayloadbatch', type=int, default = 0, metavar = "HAUS_PAYLOAD_URL", help='THis option has few possible values: <1> Retrieves a list of downloadable links of recent PAYLOADS (last 3 days, limited to 1000 entries) from URLHaus website; <2>: Retrieves a list of recent URLs (last 3 days, limited to 1000 entries) from URLHaus website. Take care: each link take you to download a passworless zip file containing a malware, so your AV can generate alerts!')
    parser.add_argument('-U', '--haus_query', dest='urlhausquery', type=str, metavar = "URL_HAUS_QUERY", help='Queries a URL on the URLHaus website.')
    parser.add_argument('-j', '--haus_hash', dest='haushash', type=str, metavar = "HAUS_HASH", help='Queries information about a provided payload\'s hash (md5 or sha256) on the URLHaus website.')
    parser.add_argument('-S', '--haus_submission', dest='urlhaussubmit', type=str, metavar = "URL_HAUS_SUB", help='Submits a URL used to distribute malware (executable, script, document) to the URLHaus website. Pay attention: Any other submission will be ignored/deleted from URLhaus. You have to register your URLHaus API into the .malwapi.conf file.')
    parser.add_argument('-z', '--haustag', dest='tag', type=str, default='', metavar = "HAUSTAG", nargs = "*", help='Associates tags (separated by spaces) to the specified URL. Please, only upper case, lower case, \'-\' and \'.\' are allowed. This parameter is optional, which could be used with the -S option.')
    parser.add_argument('-W', '--haustagsearch', dest='haustagsearch', type=str, default='', metavar = "HAUSTAGSEARCH", nargs = "*", help='This option is for searching malicious URLs by tag on URLhaus. Tags are case-senstive and only upper case, lower case, \'-\' and \'.\' are allowed.')
    parser.add_argument('-k', '--haussigsearch', dest='haussigsearch', type=str, default='', metavar = "HAUSSIGSEARCH", nargs = "*", help='This option is for searching malicious payload by tag on URLhaus. Tags are case-sensitive and only  upper case, lower case, \'-\' and \'.\' are allowed.')
    parser.add_argument('-J', '--haus_download', dest='hausdownloadpayload', type=str, metavar = "HAUS_DOWNLOAD", help='Downloads a malware sample (if it is available) from the URLHaus repository. It is necessary to provide the SHA256 hash.')
    parser.add_argument('-P', '--polyswarm_scan', dest='polyswarmscan', type=str, metavar = "POLYSWARMFILE", help='(Only for Linux) Submits a sample to Polyswarm engine and performs a file scan.')
    parser.add_argument('-O', '--polyswarm_hash', dest='polyswarmhash', type=str, metavar = "POLYSWARMHASH", help='(Only for Linux) Performs a hash scanning using the Polyswarm engine. Optionally, you can specify -D option to download the sample. Take care: Polyswarm enforces a restriction to number of downloaded samples in 20/month.')
    parser.add_argument('-R', '--polyswarm_meta', dest='polyswarmmeta', type=str, metavar = "POLYSWARMMETA", help='(Only for Linux) Provides the argument value for searches on Polyswarm engine through imphash (the PE file must be provided), ipv4, domain, URL and family. This argument must be used with -G option, so check it, please. Pay attention: you should check your metadata search limit on your Polyswarm account because once you have got the limit, so you will got an error.')
    parser.add_argument('-G', '--metatype', dest='metatype', type=int, default = 0, metavar = "METATYPE", help='(Only for Linux) This parameter specifies search type for arguments provided by -R option (above) while searching on Polyswarm engine. Thus, the following values are valid -- 0: PE Executable (look for samples with the same ImpHash); 1: IP Address ; 2: Domain ; 3. URL; 4. Family')
    parser.add_argument('-y', '--androidha', dest='androidha', type=int, default = 0, metavar = "ANDROID_HA", help='This option has multiple options: <1>: Check all third-party APK packages from the USB-connected Android device against Hybrid Analysis using multithreads. The Android device does not need to be rooted and the system does need to have the adb tool in the PATH environment variable; <2>: Check all third-party APK packages from the USB-connected Android device against VirusTotal using Public API (slower because of 60 seconds delay for each 4 hashes). The Android device does not need to be rooted and the system does need to have adb tool in the PATH environment variable; <3>: Check all third-party APK packages from the USB-connected Android device against VirusTotal using multithreads (only for Private Virus API). The Android device does not need to be rooted and the system needs to have adb tool in the PATH environment variable.')
    parser.add_argument('-Y', '--androidsendha', dest='androidsendha', type=str, metavar = "ANDROID_SEND_HA", help='Sends an third-party APK package from your USB-connected Android device to Hybrid Analysis. The Android device does not need to be rooted and the system needs to have adb tool in the PATH environment variable.')
    parser.add_argument('-T', '--androidsendvt', dest='androidsendvt', type=str, metavar = "ANDROID_SEND_VT", help='Sends an third-party APK package from your USB-connected Android device to Virus Total. The Android device does not need be rooted and the system needis to have the adb tool in the PATH environment variable.')
    parser.add_argument('-n', '--alienvault', dest='alienvault', type=int, default = 0, metavar = "ALIENVAULT", help='Checks multiple information from AlienVault. The possible values are: 1: Get the subscribed pulses ; 2: Get information about an IP address; 3: Get information about a domain; 4: Get information about a hash; 5: Get information about a URL')
    parser.add_argument('-N', '--alienvaultargs', dest='alienvaultargs', type=str, metavar = "ALIENVAULT_ARGS", help='Provides argument to AlienVault -n option.')
    parser.add_argument('-M', '--malpedia', dest='malpedia', type=int, default = 0, metavar = "MALPEDIA", help='This option is related to MALPEDIA and presents different meanings depending on the chosen value. Thus, 1: List meta information for all families ; 2: List all actors ID ; 3: List all available payloads organized by family from Malpedia; 4: Get meta information from an specific actor, so it is necessary to use the -m option. Additionally, try to confirm the correct actor ID by executing malwoverview with option -M 3; 5: List all families IDs; 6: Get meta information from an specific family, so it is neccesary to use the -m option. Additionally, try to confirm the correct family ID by executing malwoverview with option -M 5; 7: Get a malware sample from malpedia (zip format -- password: infected). It is necessary to specify the requested hash by using -m option; 8: Get a zip file containing Yara rules for a specific family (get the possible families using -M 5), which must be specified by using -m option.')
    parser.add_argument('-m', '--malpediarg', dest='malpediaarg', type=str, metavar = "MALPEDIAARG", help='This option provides an argument to the -M option, which is related to MALPEDIA.')
    parser.add_argument('-Q', '--threatcrowd', dest='threatcrowd', type=int, default = 0, metavar = "THREATCROWD", help='Checks multiple information from ThreatCrowd. The possible values are: 1: Get information about the provided e-mail ; 2: Get information about an IP address; 3: Get information about a domain; 4: Get information about a provided MD5 hash; 5: Get information about a specific malware family.')
    parser.add_argument('-q', '--threatcrowdarg', dest='threatcrowdarg', type=str, metavar = "THREATCROWDARG", help='This option provides an argument to the -Q option, which is related to THREATCROWD.')
    parser.add_argument('-E', '--valhalla', dest='valhalla', type=int, default = 0, metavar = "VALHALLA", help='This option is used for getting Yara rules from the Valhalla service given an argument (-C option below). Valid values are 1: searches for Yara rules matching the provided keyword; 2: search for Yara rules matching a minimal score (40-49: anomaly and threat hunting rules / 60-74: rules for suspicious objects / 75-100: hard malicious matches); 3: Look for Yara rules to the following products, which must be specified using the -C option: FireEyeAX, FireEyeNX, FireEyeEX, CarbonBlack, Tanium, Tenable, SymantecMAA, GRR, osquery, McAfeeATD3 and McAfeeATD4; 4: Given the hash (SHA 256) through -C option, show associated Yara rules; 5: Shows information about a specific Yara rule provided through the -C option.')
    parser.add_argument('-C', '--valhallaarg', dest='valhallaarg', type=str, metavar = "VALHALLAARG", help='This option is used for providing argument to the  Vahalla service (-E option).')
    parser.add_argument('-b', '--bazaar', dest='bazaar', type=int, default = 0, metavar = "BAZAAR", help='Checks multiple information from Malware Bazaar and ThreatFox. The possible values are: 1: (Bazaar) Query information about a malware hash sample ; 2: (Bazaar) Get information and a list of malware samples associated and according to a specific tag; 3: (Bazaar) Get a list of malware samples according to a given imphash; 4: (Bazaar) Query latest malware samples; 5: (Bazaar) Download a malware sample from Malware Bazaar by providing a SHA256 hash. The downloaded sample is zipped using the following password: infected; 6: (ThreatFox) Get current IOC dataset from last x days given by option -B; 7: (ThreatFox) Search for the specified IOC on ThreatFox given by option -B; 8: (ThreatFox) Search IOCs according to the specified tag given by option -B; 9: (ThreatFox) Search IOCs according to the specified malware family provided by option -B; 10. (ThreatFox) List all available malware families. ')
    parser.add_argument('-B', '--bazaararg', dest='bazaararg', type=str, metavar = "BAZAAR_ARG", help='Provides argument to -b Bazaar and ThreatFox option. If you specified "-b 1" then the -B\'s argument must be a hash; If you specified "-b 2" then -B\'s argument must be a malware tag; If you specified "-b 3" then the argument must be a imphash; If you specified "-b 4", so the argument must be "100 or time", where "100" lists last "100 samples" and "time" lists last samples added to Malware Bazaar in the last 60 minutes; If you specified "-b 5" then the -B\'s argument must be a SHA256 hash; If you specified "-b 6", so the -B\'s value is the number of DAYS to filter IOCs. The default (and max) is 90 (days); If you used "-b 7" so the -B\'s argument is the IOC you want to search for; If you used "-b 8", so the -B\'s argument is the TAG you want search for; If you used "-b 9", so the -B argument is the malware family you want to search for;')


    args = parser.parse_args()

    try:
    
        config_file = configparser.ConfigParser()
        config_file.read(args.config)
        VTAPI = config_file['VIRUSTOTAL']['VTAPI']
        HAAPI = config_file['HYBRID-ANALYSIS']['HAAPI']
        MALSHAREAPI = config_file['MALSHARE']['MALSHAREAPI']
        HAUSSUBMITAPI = config_file['HAUSSUBMIT']['HAUSSUBMITAPI']
        POLYAPI = config_file['POLYSWARM']['POLYAPI']
        ALIENAPI = config_file['ALIENVAULT']['ALIENAPI']
        MALPEDIAAPI = config_file['MALPEDIA']['MALPEDIAAPI']
        VALHALLAAPI = config_file['VALHALLA']['VALHALLAAPI']

    except KeyError:

        print(mycolors.foreground.red + "\nYou must create the .malwapi.conf file in your home directory (in Linux is $HOME\\.malwapi.conf and in Windows is on Users\\<username\\.malwapi.conf) and configure Virus Total, Hybrid Analysis, URLHaus, Malshare, Polyswarm, Alien Vault and Malpedia APIs according to the format shown on the Github website. It isn't necessary any API for ThreatCrowd service." + mycolors.reset + "\n")
        exit(1)

    if (POLYAPI):
        polyswarm = PolyswarmAPI(key=POLYAPI)

    optval = [0,1]
    optval1 = [0,1,2]
    optval2 = [0,1,2,3,4]
    optval3 = [0,1,2,3,4,5,6, 7, 8, 9, 10, 11, 12, 13, 14]
    optval4 = [0, 1, 2, 3]
    optval5 = [0, 1, 2, 3, 4, 5]
    optval6 = [0, 1, 2, 3, 4, 5, 6, 7, 8]
    optval7 = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10]
    repo = args.direct
    bkg = args.backg
    vt = args.virustotal
    ffpname = args.fpname
    ovrly = args.over
    ha = args.hybridanalysis
    urltemp = args.urlx
    domaintemp = args.domainx
    hashtemp = args.filehash
    filetemp = args.filenamevt
    down = args.download
    xx = args.sysenviron
    fileha = args.filenameha
    repoha = args.reportha
    T = args.multithread
    mallist = args.malsharelist
    maltype = args.malsharelist
    malhash = args.malsharehash
    maldownload = args.download
    hausfinalurl2 = args.urlhaussubmit
    hausfinalurl = args.urlhausquery
    haustag = args.tag
    haustagsearchx = args.haustagsearch
    haussigsearchx = args.haussigsearch
    hauspayloads = args.hauspayloadbatch
    hauspayloadhash = args.haushash
    hausdownload = args.hausdownloadpayload
    polyscan = args.polyswarmscan
    polyhash = args.polyswarmhash
    polymeta = args.polyswarmmeta
    androidx = args.androidha
    androidsendhax = args.androidsendha
    androidsendvtx = args.androidsendvt
    ipaddrvtx = args.ipaddrvt
    metatypex = args.metatype
    alienx = args.alienvault
    alienargsx = args.alienvaultargs
    malpediax = args.malpedia
    malpediaargx = args.malpediaarg
    threatcrowdx = args.threatcrowd
    threatcrowdargx = args.threatcrowdarg
    valhallax = args.valhalla
    valhallaargx = args.valhallaarg
    bazaarx = args.bazaar
    bazaarargx = args.bazaararg
    config = args.config

    if (vt == 2):
        showreport = 1

    if (vt == 3):
        ie = 1

    if (T == 2):
        Q = 1

    if (T == 3):
        gt = 1

    if (hauspayloads == 2):
        hausbatch = 1

    if (androidx == 2):
        androidvtx = 1

    if (androidx == 3):
        androidvttx = 1

    if ((ha != 0) and (ha < 6)):
        xx = ha - 1
        Q = 1
    
    if (os.path.isfile(ffpname)):
        fprovided = 1
    else:
        fprovided = 0

    if (args.over) not in optval:
        parser.print_help()
        print(mycolors.reset)
        exit(0)
    elif ovrly == 1:
        if fprovided == 0:
            parser.print_help()
            print(mycolors.reset)
            exit(0)

    if ie == 1:
        if fprovided == 0:
            parser.print_help()
            print(mycolors.reset)
            exit(0)

    if (args.hauspayloadbatch) not in optval1:
        parser.print_help()
        print(mycolors.reset)
        exit(0)
    
    if (args.hybridanalysis) not in optval5:
        parser.print_help()
        print(mycolors.reset)
        exit(0)
    elif ie == 1:
        if fprovided == 0:
            parser.print_help()
            print(mycolors.reset)
            exit(0)

    if (showreport == 1):
        if (fprovided == 0 or vt == 0):
            parser.print_help()
            print(mycolors.reset)
            exit(0)

    if (args.androidha) not in optval4:
        parser.print_help()
        print(mycolors.reset)
        exit(0)

    if (args.metatype) not in optval2:
        parser.print_help()
        print(mycolors.reset)
        exit(0)

    if (args.alienvault) not in optval5:
        parser.print_help()
        print(mycolors.reset)
        exit(0)

    if (args.bazaar) not in optval7:
        parser.print_help()
        print(mycolors.reset)
        exit(0)

    if (args.malpedia) not in optval6:
        parser.print_help()
        print(mycolors.reset)
        exit(0)

    if (args.threatcrowd) not in optval5:
        parser.print_help()
        print(mycolors.reset)
        exit(0)

    if (args.valhalla) not in optval5:
        parser.print_help()
        print(mycolors.reset)
        exit(0)

    if ((not args.direct) and (fprovided == 0) and (not urltemp) and (not hashtemp) and (not filetemp) and (not fileha) and (not repoha) and (not domaintemp) and (mallist == 0) and (not args.malsharehash) and (not args.urlhausquery) and (not args.urlhaussubmit) and (hausbatch == 0) and (hauspayloads == 0) and (not args.haushash) and (not args.hausdownloadpayload) and (not args.polyswarmscan) and (not args.polyswarmhash) and (not args.polyswarmmeta) and (androidx == 0) and (not androidsendhax) and (androidvtx == 0) and (androidvttx == 0) and (not androidsendvtx) and (not haustagsearchx) and (not haussigsearchx) and (not ipaddrvtx) and (metatype == 0) and (alienx == 0) and (not alienargsx) and (not malpediaargx) and (malpediax ==0) and (not args.threatcrowd) and (not args.valhalla) and (bazaarx == 0) and (not bazaarargx)):
        parser.print_help()
        print(mycolors.reset)
        exit(0)

    if (args.backg) not in optval:
        parser.print_help()
        print(mycolors.reset)
        sys.exit(0)

    if (args.download) not in optval:
        parser.print_help()
        print(mycolors.reset)
        sys.exit(0)

    if (args.malsharelist) not in optval3:
        parser.print_help()
        print(mycolors.reset)
        sys.exit(0)

    if (Q == 1):
        if ((vt == 0) and (ha == 0)):
            parser.print_help()
            print(mycolors.reset)
            sys.exit(0)
    elif (Q == 1):
        if (not repo):
            parser.print_help()
            print(mycolors.reset)
            sys.exit(0)
    if (args.multithread) not in optval4:
        parser.print_help()
        print(mycolors.reset)
        sys.exit(0)
    elif (T == 1):
        if((not args.direct) and Q == 0):
            parser.print_help()
            print(mycolors.reset)
            sys.exit(0)

    if (args.virustotal) not in optval4:
        parser.print_help()
        print(mycolors.reset)
        sys.exit(0)

    if (args.sysenviron) not in optval2:
        parser.print_help()
        print(mycolors.reset)
        sys.exit(0)

    if (windows == 1):
        init(convert = True)

    if (not urltemp):
        if (not args.direct):
            if (fprovided == 0 ):
                if (not hashtemp):
                    if (not filetemp):
                        if (not fileha):
                            if (not repoha):
                                if (not domaintemp):
                                    if (args.malsharelist == 0):
                                        if (not args.malsharehash):
                                            if (not args.urlhausquery):
                                                if (not args.urlhaussubmit):
                                                    if (args.hauspayloadbatch == 0):
                                                        if (not args.haushash):
                                                            if (not args.hausdownloadpayload):
                                                                if (not args.polyswarmscan):
                                                                    if (not args.polyswarmhash):
                                                                        if (not args.polyswarmmeta):
                                                                            if (args.androidha == 0):
                                                                                if (not args.androidsendha):
                                                                                    if (not args.androidsendvt):
                                                                                        if (not args.haustagsearch):
                                                                                            if (not args.haussigsearch):
                                                                                                if (not args.ipaddrvt):
                                                                                                    if (args.metatype == 0):
                                                                                                        if (args.alienvault == 0):
                                                                                                            if (not args.alienvaultargs):
                                                                                                                if (args.bazaar == 0):
                                                                                                                    if (not args.bazaararg):
                                                                                                                        if (not malpediaargx):
                                                                                                                            if (malpediax == 0):
                                                                                                                                if(not args.threatcrowd):
                                                                                                                                    if(not args.valhalla):
                                                                                                                                        parser.print_help()
                                                                                                                                        print(mycolors.reset)
                                                                                                                                        exit(0)

    if (urltemp):
        if (validators.url(urltemp)) == True:
            urlcheck = 1
        elif (bkg == 0): 
            print(mycolors.foreground.red + "\nYou didn't provided a valid URL.\n")
            print(mycolors.reset)
            exit(1)
        else:
            print(mycolors.foreground.yellow + "\nYou didn't provided a valid URL.\n")
            print(mycolors.reset)
            exit(1)

    if (hausfinalurl):
        if (validators.url(hausfinalurl)) == True:
            hauscheck = 1
        elif (bkg == 0): 
            print(mycolors.foreground.red + "\nYou didn't provided a valid URL.\n")
            print(mycolors.reset)
            exit(1)
        else:
            print(mycolors.foreground.yellow + "\nYou didn't provided a valid URL.\n")
            print(mycolors.reset)
            exit(1)

        if ((args.urlhausquery) and (hauscheck == 1)):
            urlhauscheck(hausfinalurl, hausq)
            print(mycolors.reset)
            exit(0)

    if(hausbatch == 1):
        hausgetbatch(hausb)
        print(mycolors.reset)

    if(hauspayloads == 1):
        hauspayloadslist(hausp)
        print(mycolors.reset)

    if (hausfinalurl2):
        if (validators.url(hausfinalurl2)) == True:
            hauscheck = 1
        elif (bkg == 0): 
            print(mycolors.foreground.red + "\nYou didn't provided a valid URL.\n")
            print(mycolors.reset)
            exit(1)
        else:
            print(mycolors.foreground.yellow + "\nYou didn't provided a valid URL.\n")
            print(mycolors.reset)
            exit(1)

        if ((args.urlhaussubmit) and (hauscheck == 1)):
            urlhauspost(hausfinalurl2, hauss, haustag)
            print(mycolors.reset)
            exit(0)

    if (domaintemp):
        if (validators.domain(domaintemp)) == True:
            domaincheck = 1
        elif (bkg == 0):
            print(mycolors.foreground.red + "\nYou didn't provided a valid domain.\n")
            print(mycolors.reset)
            exit(1)
        else:
            print(mycolors.foreground.yellow + "\nYou didn't provided a valid domain.\n")
            print(mycolors.reset)
            exit(1)

    if (filetemp):
        if (os.path.isfile(filetemp)) == True:
            filecheck = 1
        elif (bkg == 0):
            print(mycolors.foreground.red + "\nYou didn't provided a valid file.\n")
            print(mycolors.reset)
            exit(1)
        else:
            print(mycolors.foreground.yellow + "\nYou didn't provided a valid file.\n")
            print(mycolors.reset)
            exit(1)

    if (fileha):
        if (os.path.isfile(fileha)) == True:
            filecheckha = 1
        elif (bkg == 0):
            print(mycolors.foreground.red + "\nYou didn't provided a valid file.\n")
            print(mycolors.reset)
            exit(1)
        else:
            print(mycolors.foreground.yellow + "\nYou didn't provided a valid file.\n")
            print(mycolors.reset)
            exit(1)

    if (polyscan):
        if (os.path.isfile(polyscan)) == True:
            filecheckpoly = 1
        elif (bkg == 0):
            print(mycolors.foreground.red + "\nYou didn't provided a valid file.\n")
            print(mycolors.reset)
            exit(1)
        else:
            print(mycolors.foreground.yellow + "\nYou didn't provided a valid file.\n")
            print(mycolors.reset)
            exit(1)

    if (urlcheck == 1):
        vturlcheck(urltemp,param)
        print(mycolors.reset)
        exit(0)

    if (alienx == 1):
        argx = alienargsx
        alien_subscribed(urlalien,argx)
        print(mycolors.reset)
        exit(0)
    
    if (alienx == 2):
        argx = alienargsx
        alien_ipv4(urlalien,argx)
        print(mycolors.reset)
        exit(0)

    if (alienx == 3):
        argx = alienargsx
        alien_domain(urlalien,argx)
        print(mycolors.reset)
        exit(0)
    
    if (alienx == 4):
        argx = alienargsx
        alien_hash(urlalien,argx)
        print(mycolors.reset)
        exit(0)

    if (alienx == 5):
        argx = alienargsx
        alien_url(urlalien,argx)
        print(mycolors.reset)
        exit(0)

    if (bazaarx == 1):
        argx = bazaarargx
        bazaarcheck=0
        if(argx):
            if ((len(argx) == 32) or (len(argx)==64)):
                bazaarcheck=1
        if(bazaarcheck == 1):
            bazaar_hash(argx, urlbazaar)
        print(mycolors.reset)
        exit(0)

    if (bazaarx == 2):
        argx = bazaarargx
        bazaar_tag(argx, urlbazaar)
        print(mycolors.reset)
        exit(0)

    if (bazaarx == 3):
        argx = bazaarargx
        bazaar_imphash(argx, urlbazaar)
        print(mycolors.reset)
        exit(0)

    if (bazaarx == 4):
        argx = bazaarargx
        bazaar_lastsamples(argx, urlbazaar)
        print(mycolors.reset)
        exit(0)

    if (bazaarx == 5):
        argx = bazaarargx
        bazaar_download(argx, urlbazaar)
        print(mycolors.reset)
        exit(0)

    if (bazaarx == 6):
        argx = bazaarargx
        threatfox_listiocs(argx, urlthreatfox)
        print(mycolors.reset)
        exit(0)

    if (bazaarx == 7):
        argx = bazaarargx
        threatfox_searchiocs(argx, urlthreatfox)
        print(mycolors.reset)
        exit(0) 

    if (bazaarx == 8):
        argx = bazaarargx
        threatfox_searchtags(argx, urlthreatfox)
        print(mycolors.reset)
        exit(0) 

    if (bazaarx == 9):
        argx = bazaarargx
        threatfox_searchmalware(argx, urlthreatfox)
        print(mycolors.reset)
        exit(0) 
    
    if (bazaarx == 10):
        argx = bazaarargx
        threatfox_listmalware(argx, urlthreatfox)
        print(mycolors.reset)
        exit(0) 

    if (malpediax == 1):
        argx = malpediaargx
        malpedia_families(malpediaurl,argx)
        print(mycolors.reset)
        exit(0)

    if (malpediax == 2):
        argx = malpediaargx
        malpedia_actors(malpediaurl,argx)
        print(mycolors.reset)
        exit(0)
    
    if (malpediax == 3):
        argx = malpediaargx
        malpedia_payloads(malpediaurl,argx)
        print(mycolors.reset)
        exit(0)
    
    if (malpediax == 4):
        argx = malpediaargx
        malpedia_get_actor(malpediaurl,argx)
        print(mycolors.reset)
        exit(0)

    if (malpediax == 5):
        argx = malpediaargx
        malpedia_families(malpediaurl,argx)
        print(mycolors.reset)
        exit(0)

    if (malpediax == 6):
        argx = malpediaargx
        malpedia_get_family(malpediaurl,argx)
        print(mycolors.reset)
        exit(0)

    if (malpediax == 7):
        argx = malpediaargx
        if ((len(argx)==32) or (len(argx)==64)):
            malpedia_get_sample(malpediaurl,argx)
        print(mycolors.reset)
        exit(0)

    if (malpediax == 8):
        argx = malpediaargx
        malpedia_get_yara(malpediaurl,argx)
        print(mycolors.reset)
        exit(0)

    if (threatcrowdx == 1):
        argx = threatcrowdargx
        threatcrowd_email(threatcrowdurl,argx)
        print(mycolors.reset)
        exit(0)

    if (threatcrowdx == 2):
        argx = threatcrowdargx
        threatcrowd_ip(threatcrowdurl,argx)
        print(mycolors.reset)
        exit(0)

    if (threatcrowdx == 3):
        argx = threatcrowdargx
        threatcrowd_domain(threatcrowdurl,argx)
        print(mycolors.reset)
        exit(0)

    if (threatcrowdx == 4):
        argx = threatcrowdargx
        threatcrowd_hash(threatcrowdurl,argx)
        print(mycolors.reset)
        exit(0)

    if (threatcrowdx == 5):
        argx = threatcrowdargx
        threatcrowd_antivirus(threatcrowdurl,argx)
        print(mycolors.reset)
        exit(0)

    if (valhallax > 0):
        argx = valhallaargx
        valhalla_service(valhallax,argx,VALHALLAAPI)
        print(mycolors.reset)
        exit(0)

    if (polyhash):
        if (polyhash):
            if ((len(polyhash)==32) or (len(polyhash)==40) or (len(polyhash)==64)):
                polycheck = 1
        if (polycheck == 1):
            polyhashsearch(polyhash)
        print(mycolors.reset)
        exit(0)

    if (domaincheck == 1):
        vtdomaincheck(domaintemp,param)
        print(mycolors.reset)
        exit(0)

    if (filecheck == 1):
        vtfilecheck(filetemp, urlfilevtcheck, param)
        print(mycolors.reset)
        exit(0)

    if (filecheckha == 1):
        hafilecheck(fileha)
        print(mycolors.reset)
        exit(0)

    if (filecheckpoly == 1):
        polyfile(polyscan)
        print(mycolors.reset)
        exit(0)
    
    if (androidsendhax):
        xx = 3
        sendandroidha(androidsendhax)
        print(mycolors.reset)
        exit(0)

    if (androidsendvtx):
        sendandroidvt(androidsendvtx)
        print(mycolors.reset)
        exit(0)

    if (polymeta):
        polymetasearch(polymeta, metatypex)
        print(mycolors.reset)
        exit(0)

    if (hashtemp):
        if ((len(hashtemp)==32) or (len(hashtemp)==40) or (len(hashtemp)==64)):
            hashcheck = 1

        elif (bkg == 0):
            print(mycolors.foreground.red + "\nYou didn't provided a valid hash.\n")
            print(mycolors.reset)
            exit(1)
        else:
            print(mycolors.foreground.yellow + "\nYou didn't provided a valid hash.\n")
            print(mycolors.reset)
            exit(1)

    if (hashcheck == 1):
        hashchecking()
        print(mycolors.reset)
        exit(0)

    if (mallist != 0):
        malsharelastlist(maltype)
        print(mycolors.reset)
        exit(0)

    if (malhash):
        if (malhash):
            if ((len(malhash)==32) or (len(malhash)==40) or (len(malhash)==64)):
                hashcheck = 1
        if (hashcheck == 1):
            malsharehashsearch(malhash)
        print(mycolors.reset)
        exit(0)

    if (androidx == 1):
        engine = 1
        checkandroid(engine)
        print(mycolors.reset)
        exit(0)

    if (androidvtx):
        engine = 2
        checkandroid(engine)
        print(mycolors.reset)
        exit(0)
    
    if (androidvttx):
        engine = 3
        checkandroid(engine)
        print(mycolors.reset)
        exit(0)

    if (hauspayloadhash):
        if (hauspayloadhash):
            if ((len(hauspayloadhash)==32) or (len(hauspayloadhash)==64)):
                hashcheck = 1
        if (hashcheck == 1):
            haushashsearch(hauspayloadhash, hausph)
        print(mycolors.reset)
        exit(0)

    if (haustagsearchx):
        haustagsearchroutine(haustagsearchx, haust)
        print(mycolors.reset)
        exit(0)

    if (haussigsearchx):
        haussigsearchroutine(haussigsearchx, haussig)
        print(mycolors.reset)
        exit(0)

    if (ipaddrvtx):
        ipvtcheck(ipaddrvtx, ipvt)
        print(mycolors.reset)
        exit(0)

    if (hausdownload):
        if (len(hausdownload)==64):
                hashcheck = 1
        if (hashcheck == 1):
            haussample(hausdownload, hausd)
        print(mycolors.reset)
        exit(0)

    if (fprovided == 1):
        filenamecheck = ffpname
        filechecking(filenamecheck)
        print(mycolors.reset)
        exit(0)

    if (repoha):
        checkreportha(repoha)
        print(mycolors.reset)
        exit(0)

    if (repo is not None):
        repository = repo
        dirchecking(repository)
