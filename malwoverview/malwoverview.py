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

#CONTRIBUTORS

# Alexandre Borges (project owner)
# Corey Forman (https://github.com/digitalsleuth)
# Christian Clauss (https://github.com/cclauss)

# Malwoverview.py: version 5.3

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
import binascii
from operator import itemgetter
from polyswarm_api.api import PolyswarmAPI
from urllib.parse import urlparse
from colorama import init, Fore, Back, Style
from datetime import datetime
from urllib.parse import urlencode, quote_plus
from urllib.parse import quote
from requests.exceptions import RetryError
from pathlib import Path
from io import StringIO, BytesIO
from requests import Request, Session, exceptions

# On Windows systems, it is necessary to install python-magic-bin: pip install python-magic-bin

__author__ = "Alexandre Borges"
__copyright__ = "Copyright 2018-2021, Alexandre Borges"
__license__ = "GNU General Public License v3.0"
__version__ = "5.3"
__email__ = "alexandreborges at blackstormsecurity.com"

haurl = 'https://www.hybrid-analysis.com/api/v2'
urlfilevt3 = 'https://www.virustotal.com/api/v3/files'
urlurlvt3 = 'https://www.virustotal.com/api/v3/urls'
urlipvt3 = 'https://www.virustotal.com/api/v3/ip_addresses'
urldomainvt3 = 'https://www.virustotal.com/api/v3/domains'
param = 'params'
user_agent = 'Falcon Sandbox'
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
triageurl = 'https://api.tria.ge/v0/'
inquesturl = 'https://labs.inquest.net/api/dfi'
inquesturl2 = 'https://labs.inquest.net/api/iocdb'
inquesturl3 = 'https://labs.inquest.net/api/repdb'

F = []
H = []
final=''
ffpname2 = ''
repo2 = ''
global polyswarm

def requestHAAPI():

    if(HAAPI == ''):
        print(mycolors.foreground.red + "\nTo be able to get/submit information from/to Hybrid Analysis, you must create the .malwapi.conf file under your user home directory (on Linux is $HOME\\.malwapi.conf and on Windows is in C:\\Users\\[username]\\.malwapi.conf) and insert the Hybrid Analysis API according to the format shown on the Github website." + mycolors.reset + "\n")
        exit(1)


def requestMALSHAREAPI():

    if(MALSHAREAPI == ''):
        print(mycolors.foreground.red + "\nTo be able to get/submit information from/to Malshare, you must create the .malwapi.conf file under your user home directory (on Linux is $HOME\\.malwapi.conf and on Windows is in C:\\Users\\[username]\\.malwapi.conf) and insert the Malshare API according to the format shown on the Github website." + mycolors.reset + "\n")
        exit(1)

def requestHAUSSUBMITAPI():

    if(HAUSSUBMITAPI == ''):
        print(mycolors.foreground.red + "\nTo be able to get/submit information from/to URLHaus, you must create the .malwapi.conf file under your user home directory (on Linux is $HOME\\.malwapi.conf and on Windows is in C:\\Users\\[username]\\.malwapi.conf) and insert the URLHaus API according to the format shown on the Github website." + mycolors.reset + "\n")
        exit(1)

def requestPOLYAPI():

    if(POLYAPI == ''):
        print(mycolors.foreground.red + "\nTo be able to get/submit information from/to Polyswarm, you must create the .malwapi.conf file under your user home directory (on Linux is $HOME\\.malwapi.conf and on Windows is in C:\\Users\\[username]\\.malwapi.conf) and insert the Polyswarm API according to the format shown on the Github website." + mycolors.reset + "\n")
        exit(1)

def requestALIENAPI():

    if(ALIENAPI == ''):
        print(mycolors.foreground.red + "\nTo be able to get information from Alien Vault, you must create the .malwapi.conf file under your user home directory (on Linux is $HOME\\.malwapi.conf and on Windows is in C:\\Users\\[username]\\.malwapi.conf) and insert the Alien Vault API according to the format shown on the Github website." + mycolors.reset + "\n")
        exit(1)

def requestMALPEDIAAPI():

    if(MALPEDIAAPI == ''):
        print(mycolors.foreground.red + "\nTo be able to get information from Malpedia, you must create the .malwapi.conf file under your user home directory (on Linux is $HOME\\.malwapi.conf and on Windows is in C:\\Users\\[username]\\.malwapi.conf) and insert the Malpedia API according to the format shown on the Github website." + mycolors.reset + "\n")
        exit(1)

def requestTRIAGEAPI():

    if(TRIAGEAPI == ''):
        print(mycolors.foreground.red + "\nTo be able to get/submit information from/to Triage, you must create the .malwapi.conf file under your user home directory (on Linux is $HOME\\.malwapi.conf and on Windows is in C:\\Users\\[username]\\.malwapi.conf) and insert the Triage API according to the format shown on the Github website." + mycolors.reset + "\n")
        exit(1)

def requestINQUESTAPI():

    if(INQUESTAPI == ''):
        print(mycolors.foreground.red + "\nTo be able to download samples from InQuest, you must create the .malwapi.conf file under your user home directory (on Linux is $HOME\\.malwapi.conf and on Windows is in C:\\Users\\[username]\\.malwapi.conf) and insert the InQuest API according to the format shown on the Github website." + mycolors.reset + "\n")
        exit(1)



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


def list_imports_exports(targetfile):

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
            print((mycolors.foreground.pink + "%-40s" % (i)[2:-1]), end=' ')
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
            print((mycolors.foreground.lightcyan + "%-40s" % (w)[2:-1]), end=' ')
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
            print((mycolors.foreground.lightcyan + "%-40s" % (w)[2:-1]), end=' ')
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
            print((mycolors.foreground.lightcyan + "%-40s" % (t)[2:-1]))
        else:
            print((mycolors.foreground.cyan + "%-40s" % (t)[2:-1]))

    print(mycolors.reset)


def vtcheck(myhash, url, showreport):

    try:

        finalurl = ''.join([url, "/", myhash ])
        requestsession = requests.Session( )
        requestsession.headers.update({'x-apikey': VTAPI})
        requestsession.headers.update({'content-type': 'application/json'})
        response = requestsession.get(finalurl)
        vttext = json.loads(response.text)

        if (response.status_code == 404):
            final = " NOT FOUND"
        else:
            if('last_analysis_stats' in vttext['data']['attributes']):
                malicious =  vttext['data']['attributes']['last_analysis_stats']['malicious']
                undetected =  vttext['data']['attributes']['last_analysis_stats']['undetected']
                final = (str(malicious) + "/" + str(malicious + undetected))

        return final

    except ValueError:
        final = '     '
        return final


def vt_url_ip_domain_report_dark(vttext):

    print(mycolors.foreground.lightred + "\n\nAV Report:", end='')

    if('last_analysis_results' in vttext['data']['attributes']):
        ok = "CLEAN"
        if('AlienVault' in vttext['data']['attributes']['last_analysis_results']):
            result = vttext['data']['attributes']['last_analysis_results']['AlienVault']['result']
            if(result):
                print(mycolors.foreground.lightcyan + "\n".ljust(26) + "AlienVault: ".ljust(15) + mycolors.reset + result, end='')
            else:
                print(mycolors.foreground.lightcyan + "\n".ljust(26) + "AlienVault: ".ljust(15) + mycolors.reset + ok, end='')
        if('BitDefender' in vttext['data']['attributes']['last_analysis_results']):
            result = vttext['data']['attributes']['last_analysis_results']['BitDefender']['result']
            if(result):
                print(mycolors.foreground.lightcyan + "\n".ljust(26) + "BitDefender: ".ljust(15) + mycolors.reset + result, end='')
            else:
                print(mycolors.foreground.lightcyan + "\n".ljust(26) + "BitDefender: ".ljust(15) + mycolors.reset + ok, end='')
        if('Avira' in vttext['data']['attributes']['last_analysis_results']):
            result = vttext['data']['attributes']['last_analysis_results']['Avira']['result']
            if(result):
                print(mycolors.foreground.lightcyan + "\n".ljust(26) + "Avira: ".ljust(15) + mycolors.reset + result, end='')
            else:
                print(mycolors.foreground.lightcyan + "\n".ljust(26) + "Avira: ".ljust(15) + mycolors.reset + ok, end='')
        if('Comodo Valkyrie Verdict' in vttext['data']['attributes']['last_analysis_results']):
            result = vttext['data']['attributes']['last_analysis_results']['Comodo Valkyrie Verdict']['result']
            if(result):
                print(mycolors.foreground.lightcyan + "\n".ljust(26) + "Comodo: ".ljust(15) + mycolors.reset + result, end='')
            else:
                print(mycolors.foreground.lightcyan + "\n".ljust(26) + "Comodo: ".ljust(15) + mycolors.reset + ok, end='')
        if('CyRadar' in vttext['data']['attributes']['last_analysis_results']):
            result = vttext['data']['attributes']['last_analysis_results']['CyRadar']['result']
            if(result):
                print(mycolors.foreground.lightcyan + "\n".ljust(26) + "CyRadar: ".ljust(15) + mycolors.reset + result, end='')
            else:
                print(mycolors.foreground.lightcyan + "\n".ljust(26) + "CyRadar: ".ljust(15) + mycolors.reset + ok, end='')
        if('Dr.Web' in vttext['data']['attributes']['last_analysis_results']):
            result = vttext['data']['attributes']['last_analysis_results']['Dr.Web']['result']
            if(result):
                print(mycolors.foreground.lightcyan + "\n".ljust(26) + "Dr.Web: ".ljust(15) + mycolors.reset + result, end='')
            else:
                print(mycolors.foreground.lightcyan + "\n".ljust(26) + "Dr.Web: ".ljust(15) + mycolors.reset + ok, end='')
        if('Emsisoft' in vttext['data']['attributes']['last_analysis_results']):
            result = vttext['data']['attributes']['last_analysis_results']['Emsisoft']['result']
            if(result):
                print(mycolors.foreground.lightcyan + "\n".ljust(26) + "Emsisoft: ".ljust(15) + mycolors.reset + result, end='')
            else:
                print(mycolors.foreground.lightcyan + "\n".ljust(26) + "Emsisoft: ".ljust(15) + mycolors.reset + ok, end='')
        if('ESET' in vttext['data']['attributes']['last_analysis_results']):
            result = vttext['data']['attributes']['last_analysis_results']['ESET']['result']
            if(result):
                print(mycolors.foreground.lightcyan + "\n".ljust(26) + "ESET: ".ljust(15) + mycolors.reset + result, end='')
            else:
                print(mycolors.foreground.lightcyan + "\n".ljust(26) + "ESET: ".ljust(15) + mycolors.reset + ok, end='')
        if('Forcepoint ThreatSeeker' in vttext['data']['attributes']['last_analysis_results']):
            result = vttext['data']['attributes']['last_analysis_results']['Forcepoint ThreatSeeker']['result']
            if(result):
                print(mycolors.foreground.lightcyan + "\n".ljust(26) + "Forcepoint: ".ljust(15) + mycolors.reset + result, end='')
            else:
                print(mycolors.foreground.lightcyan + "\n".ljust(26) + "Forcepoint: ".ljust(15) + mycolors.reset + ok, end='')
        if('Fortinet' in vttext['data']['attributes']['last_analysis_results']):
            result = vttext['data']['attributes']['last_analysis_results']['Fortinet']['result']
            if(result):
                print(mycolors.foreground.lightcyan + "\n".ljust(26) + "Fortinet: ".ljust(15) + mycolors.reset + result, end='')
            else:
                print(mycolors.foreground.lightcyan + "\n".ljust(26) + "Fortinet: ".ljust(15) + mycolors.reset + ok, end='')
        if('G-Data' in vttext['data']['attributes']['last_analysis_results']):
            result = vttext['data']['attributes']['last_analysis_results']['G-Data']['result']
            if(result):
                print(mycolors.foreground.lightcyan + "\n".ljust(26) + "G-Data: ".ljust(15) + mycolors.reset + result, end='')
            else:
                print(mycolors.foreground.lightcyan + "\n".ljust(26) + "G-Data: ".ljust(15) + mycolors.reset + ok, end='')
        if('Google Safebrowsing' in vttext['data']['attributes']['last_analysis_results']):
            result = vttext['data']['attributes']['last_analysis_results']['Google Safebrowsing']['result']
            if(result):
                print(mycolors.foreground.lightcyan + "\n".ljust(26) + "Google: ".ljust(15) + mycolors.reset + result, end='')
            else:
                print(mycolors.foreground.lightcyan + "\n".ljust(26) + "Google: ".ljust(15) + mycolors.reset + ok, end='')
        if('Kaspersky' in vttext['data']['attributes']['last_analysis_results']):
            result = vttext['data']['attributes']['last_analysis_results']['Kaspersky']['result']
            if(result):
                print(mycolors.foreground.lightcyan + "\n".ljust(26) + "Kaspersky: ".ljust(15) + mycolors.reset + result, end='')
            else:
                print(mycolors.foreground.lightcyan + "\n".ljust(26) + "Kaspersky: ".ljust(15) + mycolors.reset + ok, end='')
        if('MalwarePatrol' in vttext['data']['attributes']['last_analysis_results']):
            result = vttext['data']['attributes']['last_analysis_results']['MalwarePatrol']['result']
            if(result):
                print(mycolors.foreground.lightcyan + "\n".ljust(26) + "MalwarePatrol: ".ljust(15) + mycolors.reset + result, end='')
            else:
                print(mycolors.foreground.lightcyan + "\n".ljust(26) + "MalwarePatrol: ".ljust(15) + mycolors.reset + ok, end='')
        if('OpenPhish' in vttext['data']['attributes']['last_analysis_results']):
            result = vttext['data']['attributes']['last_analysis_results']['OpenPhish']['result']
            if(result):
                print(mycolors.foreground.lightcyan + "\n".ljust(26) + "OpenPhish: ".ljust(15) + mycolors.reset + result, end='')
            else:
                print(mycolors.foreground.lightcyan + "\n".ljust(26) + "OpenPhish: ".ljust(15) + mycolors.reset + ok, end='')
        if('PhishLabs' in vttext['data']['attributes']['last_analysis_results']):
            result = vttext['data']['attributes']['last_analysis_results']['PhishLabs']['result']
            if(result):
                print(mycolors.foreground.lightcyan + "\n".ljust(26) + "PhishLabs: ".ljust(15) + mycolors.reset + result, end='')
            else:
                print(mycolors.foreground.lightcyan + "\n".ljust(26) + "PhishLabs: ".ljust(15) + mycolors.reset + ok, end='')
        if('Phishtank' in vttext['data']['attributes']['last_analysis_results']):
            result = vttext['data']['attributes']['last_analysis_results']['Phishtank']['result']
            if(result):
                print(mycolors.foreground.lightcyan + "\n".ljust(26) + "Phishtank: ".ljust(15) + mycolors.reset + result, end='')
            else:
                print(mycolors.foreground.lightcyan + "\n".ljust(26) + "Phishtank: ".ljust(15) + mycolors.reset + ok, end='')
        if('Spamhaus' in vttext['data']['attributes']['last_analysis_results']):
            result = vttext['data']['attributes']['last_analysis_results']['Spamhaus']['result']
            if(result):
                print(mycolors.foreground.lightcyan + "\n".ljust(26) + "Spamhaus: ".ljust(15) + mycolors.reset + result, end='')
            else:
                print(mycolors.foreground.lightcyan + "\n".ljust(26) + "Spamhaus: ".ljust(15) + mycolors.reset + ok, end='')
        if('Sophos' in vttext['data']['attributes']['last_analysis_results']):
            result = vttext['data']['attributes']['last_analysis_results']['Sophos']['result']
            if(result):
                print(mycolors.foreground.lightcyan + "\n".ljust(26) + "Sophos: ".ljust(15) + mycolors.reset + result, end='')
            else:
                print(mycolors.foreground.lightcyan + "\n".ljust(26) + "Sophos: ".ljust(15) + mycolors.reset + ok, end='')
        if('Sucuri SiteCheck' in vttext['data']['attributes']['last_analysis_results']):
            result = vttext['data']['attributes']['last_analysis_results']['Sucuri SiteCheck']['result']
            if(result):
                print(mycolors.foreground.lightcyan + "\n".ljust(26) + "Sucuri: ".ljust(15) + mycolors.reset + result, end='')
            else:
                print(mycolors.foreground.lightcyan + "\n".ljust(26) + "Sucuri: ".ljust(15) + mycolors.reset + ok, end='')
        if('Trustwave' in vttext['data']['attributes']['last_analysis_results']):
            result = vttext['data']['attributes']['last_analysis_results']['Trustwave']['result']
            if(result):
                 print(mycolors.foreground.lightcyan + "\n".ljust(26) + "Trustwave: ".ljust(15) + mycolors.reset + result, end='')
            else:
                 print(mycolors.foreground.lightcyan + "\n".ljust(26) + "Trustwave: ".ljust(15) + mycolors.reset + ok, end='')
        if('URLhaus' in vttext['data']['attributes']['last_analysis_results']):
            result = vttext['data']['attributes']['last_analysis_results']['URLhaus']['result']
            if(result):
                 print(mycolors.foreground.lightcyan + "\n".ljust(26) + "URLhaus: ".ljust(15) + mycolors.reset + result, end='')
            else:
                 print(mycolors.foreground.lightcyan + "\n".ljust(26) + "URLhaus: ".ljust(15) + mycolors.reset + ok, end='')
        if('VX Vault' in vttext['data']['attributes']['last_analysis_results']):
            result = vttext['data']['attributes']['last_analysis_results']['VX Vault']['result']
            if(result):
                 print(mycolors.foreground.lightcyan + "\n".ljust(26) + "VX Vault: ".ljust(15) + mycolors.reset + result, end='')
            else:
                 print(mycolors.foreground.lightcyan + "\n".ljust(26) + "VX Vault: ".ljust(15) + mycolors.reset + ok, end='')
        if('Webroot' in vttext['data']['attributes']['last_analysis_results']):
            result = vttext['data']['attributes']['last_analysis_results']['Webroot']['result']
            if(result):
                 print(mycolors.foreground.lightcyan + "\n".ljust(26) + "Webroot: ".ljust(15) + mycolors.reset + result, end='')
            else:
                  print(mycolors.foreground.lightcyan + "\n".ljust(26) + "Webroot: ".ljust(15) + mycolors.reset + ok, end='')


def vt_url_ip_domain_report_light(vttext):

   print(mycolors.foreground.red + "\n\nAV Report:", end='')

   if('last_analysis_results' in vttext['data']['attributes']):
       ok = "CLEAN"
       if('AlienVault' in vttext['data']['attributes']['last_analysis_results']):
           result = vttext['data']['attributes']['last_analysis_results']['AlienVault']['result']
           if(result):
               print(mycolors.foreground.cyan + "\n".ljust(26) + "AlienVault: ".ljust(15) + mycolors.reset + result, end='')
           else:
               print(mycolors.foreground.cyan + "\n".ljust(26) + "AlienVault: ".ljust(15) + mycolors.reset + ok, end='')
       if('BitDefender' in vttext['data']['attributes']['last_analysis_results']):
           result = vttext['data']['attributes']['last_analysis_results']['BitDefender']['result']
           if(result):
               print(mycolors.foreground.cyan + "\n".ljust(26) + "BitDefender: ".ljust(15) + mycolors.reset + result, end='')
           else:
               print(mycolors.foreground.cyan + "\n".ljust(26) + "BitDefender: ".ljust(15) + mycolors.reset + ok, end='')
       if('Avira' in vttext['data']['attributes']['last_analysis_results']):
           result = vttext['data']['attributes']['last_analysis_results']['Avira']['result']
           if(result):
               print(mycolors.foreground.cyan + "\n".ljust(26) + "Avira: ".ljust(15) + mycolors.reset + result, end='')
           else:
               print(mycolors.foreground.cyan + "\n".ljust(26) + "Avira: ".ljust(15) + mycolors.reset + ok, end='')
       if('Comodo Valkyrie Verdict' in vttext['data']['attributes']['last_analysis_results']):
           result = vttext['data']['attributes']['last_analysis_results']['Comodo Valkyrie Verdict']['result']
           if(result):
               print(mycolors.foreground.cyan + "\n".ljust(26) + "Comodo: ".ljust(15) + mycolors.reset + result, end='')
           else:
               print(mycolors.foreground.cyan + "\n".ljust(26) + "Comodo: ".ljust(15) + mycolors.reset + ok, end='')
       if('CyRadar' in vttext['data']['attributes']['last_analysis_results']):
           result = vttext['data']['attributes']['last_analysis_results']['CyRadar']['result']
           if(result):
               print(mycolors.foreground.cyan + "\n".ljust(26) + "CyRadar: ".ljust(15) + mycolors.reset + result, end='')
           else:
               print(mycolors.foreground.cyan + "\n".ljust(26) + "CyRadar: ".ljust(15) + mycolors.reset + ok, end='')
       if('Dr.Web' in vttext['data']['attributes']['last_analysis_results']):
           result = vttext['data']['attributes']['last_analysis_results']['Dr.Web']['result']
           if(result):
               print(mycolors.foreground.cyan + "\n".ljust(26) + "Dr.Web: ".ljust(15) + mycolors.reset + result, end='')
           else:
               print(mycolors.foreground.cyan + "\n".ljust(26) + "Dr.Web: ".ljust(15) + mycolors.reset + ok, end='')
       if('Emsisoft' in vttext['data']['attributes']['last_analysis_results']):
           result = vttext['data']['attributes']['last_analysis_results']['Emsisoft']['result']
           if(result):
               print(mycolors.foreground.cyan + "\n".ljust(26) + "Emsisoft: ".ljust(15) + mycolors.reset + result, end='')
           else:
               print(mycolors.foreground.cyan + "\n".ljust(26) + "Emsisoft: ".ljust(15) + mycolors.reset + ok, end='')
       if('ESET' in vttext['data']['attributes']['last_analysis_results']):
           result = vttext['data']['attributes']['last_analysis_results']['ESET']['result']
           if(result):
               print(mycolors.foreground.cyan + "\n".ljust(26) + "ESET: ".ljust(15) + mycolors.reset + result, end='')
           else:
               print(mycolors.foreground.cyan + "\n".ljust(26) + "ESET: ".ljust(15) + mycolors.reset + ok, end='')
       if('Forcepoint ThreatSeeker' in vttext['data']['attributes']['last_analysis_results']):
           result = vttext['data']['attributes']['last_analysis_results']['Forcepoint ThreatSeeker']['result']
           if(result):
               print(mycolors.foreground.cyan + "\n".ljust(26) + "Forcepoint: ".ljust(15) + mycolors.reset + result, end='')
           else:
               print(mycolors.foreground.cyan + "\n".ljust(26) + "Forcepoint: ".ljust(15) + mycolors.reset + ok, end='')
       if('Fortinet' in vttext['data']['attributes']['last_analysis_results']):
           result = vttext['data']['attributes']['last_analysis_results']['Fortinet']['result']
           if(result):
               print(mycolors.foreground.cyan + "\n".ljust(26) + "Fortinet: ".ljust(15) + mycolors.reset + result, end='')
           else:
               print(mycolors.foreground.cyan + "\n".ljust(26) + "Fortinet: ".ljust(15) + mycolors.reset + ok, end='')
       if('G-Data' in vttext['data']['attributes']['last_analysis_results']):
           result = vttext['data']['attributes']['last_analysis_results']['G-Data']['result']
           if(result):
               print(mycolors.foreground.cyan + "\n".ljust(26) + "G-Data: ".ljust(15) + mycolors.reset + result, end='')
           else:
               print(mycolors.foreground.cyan + "\n".ljust(26) + "G-Data: ".ljust(15) + mycolors.reset + ok, end='')
       if('Google Safebrowsing' in vttext['data']['attributes']['last_analysis_results']):
           result = vttext['data']['attributes']['last_analysis_results']['Google Safebrowsing']['result']
           if(result):
               print(mycolors.foreground.cyan + "\n".ljust(26) + "Google: ".ljust(15) + mycolors.reset + result, end='')
           else:
               print(mycolors.foreground.cyan + "\n".ljust(26) + "Google: ".ljust(15) + mycolors.reset + ok, end='')
       if('Kaspersky' in vttext['data']['attributes']['last_analysis_results']):
           result = vttext['data']['attributes']['last_analysis_results']['Kaspersky']['result']
           if(result):
               print(mycolors.foreground.cyan + "\n".ljust(26) + "Kaspersky: ".ljust(15) + mycolors.reset + result, end='')
           else:
               print(mycolors.foreground.cyan + "\n".ljust(26) + "Kaspersky: ".ljust(15) + mycolors.reset + ok, end='')
       if('MalwarePatrol' in vttext['data']['attributes']['last_analysis_results']):
           result = vttext['data']['attributes']['last_analysis_results']['MalwarePatrol']['result']
           if(result):
               print(mycolors.foreground.cyan + "\n".ljust(26) + "MalwarePatrol: ".ljust(15) + mycolors.reset + result, end='')
           else:
               print(mycolors.foreground.cyan + "\n".ljust(26) + "MalwarePatrol: ".ljust(15) + mycolors.reset + ok, end='')
       if('OpenPhish' in vttext['data']['attributes']['last_analysis_results']):
           result = vttext['data']['attributes']['last_analysis_results']['OpenPhish']['result']
           if(result):
               print(mycolors.foreground.cyan + "\n".ljust(26) + "OpenPhish: ".ljust(15) + mycolors.reset + result, end='')
           else:
               print(mycolors.foreground.cyan + "\n".ljust(26) + "OpenPhish: ".ljust(15) + mycolors.reset + ok, end='')
       if('PhishLabs' in vttext['data']['attributes']['last_analysis_results']):
           result = vttext['data']['attributes']['last_analysis_results']['PhishLabs']['result']
           if(result):
               print(mycolors.foreground.cyan + "\n".ljust(26) + "PhishLabs: ".ljust(15) + mycolors.reset + result, end='')
           else:
               print(mycolors.foreground.cyan + "\n".ljust(26) + "PhishLabs: ".ljust(15) + mycolors.reset + ok, end='')
       if('Phishtank' in vttext['data']['attributes']['last_analysis_results']):
           result = vttext['data']['attributes']['last_analysis_results']['Phishtank']['result']
           if(result):
               print(mycolors.foreground.cyan + "\n".ljust(26) + "Phishtank: ".ljust(15) + mycolors.reset + result, end='')
           else:
               print(mycolors.foreground.cyan + "\n".ljust(26) + "Phishtank: ".ljust(15) + mycolors.reset + ok, end='')
       if('Spamhaus' in vttext['data']['attributes']['last_analysis_results']):
           result = vttext['data']['attributes']['last_analysis_results']['Spamhaus']['result']
           if(result):
               print(mycolors.foreground.cyan + "\n".ljust(26) + "Spamhaus: ".ljust(15) + mycolors.reset + result, end='')
           else:
               print(mycolors.foreground.cyan + "\n".ljust(26) + "Spamhaus: ".ljust(15) + mycolors.reset + ok, end='')
       if('Sophos' in vttext['data']['attributes']['last_analysis_results']):
           result = vttext['data']['attributes']['last_analysis_results']['Sophos']['result']
           if(result):
               print(mycolors.foreground.cyan + "\n".ljust(26) + "Sophos: ".ljust(15) + mycolors.reset + result, end='')
           else:
               print(mycolors.foreground.cyan + "\n".ljust(26) + "Sophos: ".ljust(15) + mycolors.reset + ok, end='')
       if('Sucuri SiteCheck' in vttext['data']['attributes']['last_analysis_results']):
           result = vttext['data']['attributes']['last_analysis_results']['Sucuri SiteCheck']['result']
           if(result):
               print(mycolors.foreground.cyan + "\n".ljust(26) + "Sucuri: ".ljust(15) + mycolors.reset + result, end='')
           else:
               print(mycolors.foreground.cyan + "\n".ljust(26) + "Sucuri: ".ljust(15) + mycolors.reset + ok, end='')
       if('Trustwave' in vttext['data']['attributes']['last_analysis_results']):
           result = vttext['data']['attributes']['last_analysis_results']['Trustwave']['result']
           if(result):
               print(mycolors.foreground.cyan + "\n".ljust(26) + "Trustwave: ".ljust(15) + mycolors.reset + result, end='')
           else:
               print(mycolors.foreground.cyan + "\n".ljust(26) + "Trustwave: ".ljust(15) + mycolors.reset + ok, end='')
       if('URLhaus' in vttext['data']['attributes']['last_analysis_results']):
           result = vttext['data']['attributes']['last_analysis_results']['URLhaus']['result']
           if(result):
               print(mycolors.foreground.cyan + "\n".ljust(26) + "URLhaus: ".ljust(15) + mycolors.reset + result, end='')
           else:
               print(mycolors.foreground.cyan + "\n".ljust(26) + "URLhaus: ".ljust(15) + mycolors.reset + ok, end='')
       if('VX Vault' in vttext['data']['attributes']['last_analysis_results']):
           result = vttext['data']['attributes']['last_analysis_results']['VX Vault']['result']
           if(result):
               print(mycolors.foreground.cyan + "\n".ljust(26) + "VX Vault: ".ljust(15) + mycolors.reset + result, end='')
           else:
               print(mycolors.foreground.cyan + "\n".ljust(26) + "VX Vault: ".ljust(15) + mycolors.reset + ok, end='')
       if('Webroot' in vttext['data']['attributes']['last_analysis_results']):
           result = vttext['data']['attributes']['last_analysis_results']['Webroot']['result']
           if(result):
               print(mycolors.foreground.cyan + "\n".ljust(26) + "Webroot: ".ljust(15) + mycolors.reset + result, end='')
           else:
               print(mycolors.foreground.cyan + "\n".ljust(26) + "Webroot: ".ljust(15) + mycolors.reset + ok, end='')


def vtdomainwork(mydomain, url):

    try:

        finalurl = ''.join([url, "/", mydomain ])
        requestsession = requests.Session( )
        requestsession.headers.update({'x-apikey': VTAPI})
        requestsession.headers.update({'content-type': 'application/json'})
        response = requestsession.get(finalurl)
        vttext = json.loads(response.text)

        if (response.status_code == 404):
            if (bkg == 1):
                print(mycolors.foreground.yellow + "\nDOMAIN NOT FOUND!")
            if (bkg == 0):
                print(mycolors.foreground.red + "\nDOMAIN NOT FOUND!")
        else:
            if(bkg == 1):
                if('creation_date' in vttext['data']['attributes']):
                    create_date = vttext['data']['attributes']['creation_date']
                    print(mycolors.foreground.yellow + "\nCreation Date: ".ljust(26) + mycolors.reset + str(datetime.fromtimestamp(create_date)), end='')
                if('last_update_date' in vttext['data']['attributes']):
                    last_update_date = vttext['data']['attributes']['last_update_date']
                    print(mycolors.foreground.yellow + "\nLast Update Date: ".ljust(26) + mycolors.reset + str(datetime.fromtimestamp(last_update_date)), end='')
                if('registrar' in vttext['data']['attributes']):
                    registrar = vttext['data']['attributes']['registrar']
                    print(mycolors.foreground.yellow + "\nRegistrar: ".ljust(26) + mycolors.reset + registrar, end='')
                if('reputation' in vttext['data']['attributes']):
                    reputation = vttext['data']['attributes']['reputation']
                    print(mycolors.foreground.yellow + "\nReputation: ".ljust(26) + mycolors.reset + str(reputation), end='')
                if('whois' in vttext['data']['attributes']):
                    whois = vttext['data']['attributes']['whois']
                    print(mycolors.foreground.yellow + "\nWhois: ".ljust(26) + mycolors.reset + (mycolors.reset + "\n".ljust(26)).join(textwrap.wrap(" ".join(whois.split()),width=80)),end=' ')
                if('whois_date' in vttext['data']['attributes']):
                    whois_date = vttext['data']['attributes']['whois_date']
                    print(mycolors.foreground.yellow + "\nWhois Date: ".ljust(26) + mycolors.reset + str(datetime.fromtimestamp(whois_date)), end='')
                if('jarm' in vttext['data']['attributes']):
                    jarm = vttext['data']['attributes']['jarm']
                    print(mycolors.foreground.lightred + "\n\nJarm: ".ljust(27) + mycolors.reset + str(jarm), end='')
                if('last_analysis_stats' in vttext['data']['attributes']):
                    if('harmless' in vttext['data']['attributes']['last_analysis_stats']):
                        harmless = vttext['data']['attributes']['last_analysis_stats']['harmless']
                        print(mycolors.foreground.lightred + "\nHarmless: ".ljust(26) + mycolors.reset + str(harmless), end='')
                if('last_analysis_stats' in vttext['data']['attributes']):
                    if('malicious' in vttext['data']['attributes']['last_analysis_stats']):
                        malicious = vttext['data']['attributes']['last_analysis_stats']['malicious']
                        print(mycolors.foreground.lightred + "\nMalicious: ".ljust(26) + mycolors.reset + str(malicious), end='')
                if('last_analysis_stats' in vttext['data']['attributes']):
                    if('undetected' in vttext['data']['attributes']['last_analysis_stats']):
                        undetected = vttext['data']['attributes']['last_analysis_stats']['undetected']
                        print(mycolors.foreground.lightred + "\nUndetected: ".ljust(26) + mycolors.reset + str(undetected), end='')
                if('last_analysis_stats' in vttext['data']['attributes']):
                    if('suspicious' in vttext['data']['attributes']['last_analysis_stats']):
                        suspicious = vttext['data']['attributes']['last_analysis_stats']['suspicious']
                        print(mycolors.foreground.lightred + "\nSuspicious: ".ljust(26) + mycolors.reset + str(suspicious), end='')

                vt_url_ip_domain_report_dark(vttext)


            if(bkg == 0):
                if('creation_date' in vttext['data']['attributes']):
                    create_date = vttext['data']['attributes']['creation_date']
                    print(mycolors.foreground.green + "\nCreation Date: ".ljust(26) + mycolors.reset + str(datetime.fromtimestamp(create_date)), end='')
                if('last_update_date' in vttext['data']['attributes']):
                    last_update_date = vttext['data']['attributes']['last_update_date']
                    print(mycolors.foreground.green + "\nLast Update Date: ".ljust(26) + mycolors.reset + str(datetime.fromtimestamp(last_update_date)), end='')
                if('registrar' in vttext['data']['attributes']):
                    registrar = vttext['data']['attributes']['registrar']
                    print(mycolors.foreground.green + "\nRegistrar: ".ljust(26) + mycolors.reset + registrar, end='')
                if('reputation' in vttext['data']['attributes']):
                    reputation = vttext['data']['attributes']['reputation']
                    print(mycolors.foreground.green + "\nReputation: ".ljust(26) + mycolors.reset + str(reputation), end='')
                if('whois' in vttext['data']['attributes']):
                    whois = vttext['data']['attributes']['whois']
                    print(mycolors.foreground.green + "\nWhois: ".ljust(26) + mycolors.reset + (mycolors.reset + "\n".ljust(26)).join(textwrap.wrap(" ".join(whois.split()),width=80)),end=' ')
                if('whois_date' in vttext['data']['attributes']):
                    whois_date = vttext['data']['attributes']['whois_date']
                    print(mycolors.foreground.green + "\nWhois Date: ".ljust(26) + mycolors.reset + str(datetime.fromtimestamp(whois_date)), end='')
                if('jarm' in vttext['data']['attributes']):
                    jarm = vttext['data']['attributes']['jarm']
                    print(mycolors.foreground.red + "\n\nJarm: ".ljust(27) + mycolors.reset + str(jarm), end='')
                if('last_analysis_stats' in vttext['data']['attributes']):
                    if('harmless' in vttext['data']['attributes']['last_analysis_stats']):
                        harmless = vttext['data']['attributes']['last_analysis_stats']['harmless']
                        print(mycolors.foreground.red + "\nHarmless: ".ljust(26) + mycolors.reset + str(harmless), end='')
                if('last_analysis_stats' in vttext['data']['attributes']):
                    if('malicious' in vttext['data']['attributes']['last_analysis_stats']):
                        malicious = vttext['data']['attributes']['last_analysis_stats']['malicious']
                        print(mycolors.foreground.red + "\nMalicious: ".ljust(26) + mycolors.reset + str(malicious), end='')
                if('last_analysis_stats' in vttext['data']['attributes']):
                    if('undetected' in vttext['data']['attributes']['last_analysis_stats']):
                        undetected = vttext['data']['attributes']['last_analysis_stats']['undetected']
                        print(mycolors.foreground.red + "\nUndetected: ".ljust(26) + mycolors.reset + str(undetected), end='')
                if('last_analysis_stats' in vttext['data']['attributes']):
                    if('suspicious' in vttext['data']['attributes']['last_analysis_stats']):
                        suspicious = vttext['data']['attributes']['last_analysis_stats']['suspicious']
                        print(mycolors.foreground.red + "\nSuspicious: ".ljust(26) + mycolors.reset + str(suspicious), end='')

                vt_url_ip_domain_report_light(vttext)


    except ValueError:
        if(bkg == 1):
            print((mycolors.foreground.lightred + "Error while connecting to Virus Total!\n"))
        else:
            print((mycolors.foreground.red + "Error while connecting to Virus Total!\n"))
        print(mycolors.reset)
        exit(3)


def vtipwork(myip, url):

    try:

        finalurl = ''.join([url, "/", myip ])
        requestsession = requests.Session( )
        requestsession.headers.update({'x-apikey': VTAPI})
        requestsession.headers.update({'content-type': 'application/json'})
        response = requestsession.get(finalurl)
        vttext = json.loads(response.text)

        if (response.status_code == 404):
            if (bkg == 1):
                print(mycolors.foreground.yellow + "\nIP ADDRESS NOT FOUND!")
            if (bkg == 0):
                print(mycolors.foreground.red + "\nIP ADDRESS NOT FOUND!")
        else:
            if(bkg == 1):
                if('as_owner' in vttext['data']['attributes']):
                    as_owner = vttext['data']['attributes']['as_owner']
                    print(mycolors.foreground.yellow + "\nAS Owner: ".ljust(26) + mycolors.reset + as_owner, end='')
                if('asn' in vttext['data']['attributes']):
                    asn = vttext['data']['attributes']['asn']
                    print(mycolors.foreground.yellow + "\nASN: ".ljust(26) + mycolors.reset + str(asn), end='')
                if('whois_date' in vttext['data']['attributes']):
                    whois_date = vttext['data']['attributes']['whois_date']
                    print(mycolors.foreground.yellow + "\nWhois Date: ".ljust(26) + mycolors.reset + str(datetime.fromtimestamp(whois_date)), end='')
                if('whois' in vttext['data']['attributes']):
                    whois = vttext['data']['attributes']['whois']
                    print(mycolors.foreground.yellow + "\nWhois: ".ljust(26) + mycolors.reset + (mycolors.reset + "\n".ljust(26)).join(textwrap.wrap(" ".join(whois.split()),width=80)),end=' ')
                if('country' in vttext['data']['attributes']):
                    country = vttext['data']['attributes']['country']
                    print(mycolors.foreground.lightcyan + "\n\nCountry: ".ljust(27) + mycolors.reset + country, end='')
                if('jarm' in vttext['data']['attributes']):
                    jarm = vttext['data']['attributes']['jarm']
                    print(mycolors.foreground.lightcyan + "\nJARM: ".ljust(26) + mycolors.reset + str(jarm), end='')
                if('network' in vttext['data']['attributes']):
                    network = vttext['data']['attributes']['network']
                    print(mycolors.foreground.lightcyan + "\nNetwork: ".ljust(26) + mycolors.reset + str(network), end='')
                if('regional_internet_registry' in vttext['data']['attributes']):
                    rir = vttext['data']['attributes']['regional_internet_registry']
                    print(mycolors.foreground.lightcyan + "\nR.I.R: ".ljust(26) + mycolors.reset + str(rir), end='')
                if('reputation' in vttext['data']['attributes']):
                    reputation = vttext['data']['attributes']['reputation']
                    print(mycolors.foreground.lightred + "\n\nReputation: ".ljust(27) + mycolors.reset + str(reputation), end='')
                if('last_analysis_stats' in vttext['data']['attributes']):
                    if('harmless' in vttext['data']['attributes']['last_analysis_stats']):
                        harmless = vttext['data']['attributes']['last_analysis_stats']['harmless']
                        print(mycolors.foreground.lightred + "\nHarmless: ".ljust(26) + mycolors.reset + str(harmless), end='')
                if('last_analysis_stats' in vttext['data']['attributes']):
                    if('malicious' in vttext['data']['attributes']['last_analysis_stats']):
                        malicious = vttext['data']['attributes']['last_analysis_stats']['malicious']
                        print(mycolors.foreground.lightred + "\nMalicious: ".ljust(26) + mycolors.reset + str(malicious), end='')
                if('last_analysis_stats' in vttext['data']['attributes']):
                    if('undetected' in vttext['data']['attributes']['last_analysis_stats']):
                        undetected = vttext['data']['attributes']['last_analysis_stats']['undetected']
                        print(mycolors.foreground.lightred + "\nUndetected: ".ljust(26) + mycolors.reset + str(undetected), end='')
                if('last_analysis_stats' in vttext['data']['attributes']):
                    if('suspicious' in vttext['data']['attributes']['last_analysis_stats']):
                        suspicious = vttext['data']['attributes']['last_analysis_stats']['suspicious']
                        print(mycolors.foreground.lightred + "\nSuspicious: ".ljust(26) + mycolors.reset + str(suspicious), end='')
                print(mycolors.foreground.lightred + "\nCity: ".ljust(26) + mycolors.reset + str(geocoder.ip(myip).city), end='')

                vt_url_ip_domain_report_dark(vttext)

            if(bkg == 0):
                if('as_owner' in vttext['data']['attributes']):
                    as_owner = vttext['data']['attributes']['as_owner']
                    print(mycolors.foreground.yellow + "\nAS Owner: ".ljust(26) + mycolors.reset + as_owner, end='')
                if('asn' in vttext['data']['attributes']):
                    asn = vttext['data']['attributes']['asn']
                    print(mycolors.foreground.yellow + "\nASN: ".ljust(26) + mycolors.reset + str(asn), end='')
                if('whois_date' in vttext['data']['attributes']):
                    whois_date = vttext['data']['attributes']['whois_date']
                    print(mycolors.foreground.yellow + "\nWhois Date: ".ljust(26) + mycolors.reset + str(datetime.fromtimestamp(whois_date)), end='')
                if('whois' in vttext['data']['attributes']):
                    whois = vttext['data']['attributes']['whois']
                    print(mycolors.foreground.yellow + "\nWhois: ".ljust(26) + mycolors.reset + (mycolors.reset + "\n".ljust(26)).join(textwrap.wrap(" ".join(whois.split()),width=80)),end=' ')
                if('country' in vttext['data']['attributes']):
                    country = vttext['data']['attributes']['country']
                    print(mycolors.foreground.green + "\n\nCountry: ".ljust(27) + mycolors.reset + country, end='')
                if('jarm' in vttext['data']['attributes']):
                    jarm = vttext['data']['attributes']['jarm']
                    print(mycolors.foreground.green + "\nJARM: ".ljust(26) + mycolors.reset + str(jarm), end='')
                if('network' in vttext['data']['attributes']):
                    network = vttext['data']['attributes']['network']
                    print(mycolors.foreground.green + "\nNetwork: ".ljust(26) + mycolors.reset + str(network), end='')
                if('regional_internet_registry' in vttext['data']['attributes']):
                    rir = vttext['data']['attributes']['regional_internet_registry']
                    print(mycolors.foreground.green + "\nR.I.R: ".ljust(26) + mycolors.reset + str(rir), end='')
                if('reputation' in vttext['data']['attributes']):
                    reputation = vttext['data']['attributes']['reputation']
                    print(mycolors.foreground.red + "\n\nReputation: ".ljust(27) + mycolors.reset + str(reputation), end='')
                if('last_analysis_stats' in vttext['data']['attributes']):
                    if('harmless' in vttext['data']['attributes']['last_analysis_stats']):
                        harmless = vttext['data']['attributes']['last_analysis_stats']['harmless']
                        print(mycolors.foreground.red + "\nHarmless: ".ljust(26) + mycolors.reset + str(harmless), end='')
                if('last_analysis_stats' in vttext['data']['attributes']):
                    if('malicious' in vttext['data']['attributes']['last_analysis_stats']):
                        malicious = vttext['data']['attributes']['last_analysis_stats']['malicious']
                        print(mycolors.foreground.red + "\nMalicious: ".ljust(26) + mycolors.reset + str(malicious), end='')
                if('last_analysis_stats' in vttext['data']['attributes']):
                    if('undetected' in vttext['data']['attributes']['last_analysis_stats']):
                        undetected = vttext['data']['attributes']['last_analysis_stats']['undetected']
                        print(mycolors.foreground.red + "\nUndetected: ".ljust(26) + mycolors.reset + str(undetected), end='')
                if('last_analysis_stats' in vttext['data']['attributes']):
                    if('suspicious' in vttext['data']['attributes']['last_analysis_stats']):
                        suspicious = vttext['data']['attributes']['last_analysis_stats']['suspicious']
                print(mycolors.foreground.red + "\nCity: ".ljust(26) + mycolors.reset + str(geocoder.ip(myip).city), end='')

                vt_url_ip_domain_report_light(vttext)

            print("\n")

    except ValueError:
        if(bkg == 1):
            print((mycolors.foreground.lightred + "Error while connecting to Virus Total!\n"))
        else:
            print((mycolors.foreground.red + "Error while connecting to Virus Total!\n"))
        print(mycolors.reset)
        exit(3)


def vturlwork(myurl, url):

    try:

        urlid = base64.urlsafe_b64encode(myurl.encode()).decode().strip("=")
        finalurl = ''.join([url, "/", urlid ])
        requestsession = requests.Session( )
        requestsession.headers.update({'x-apikey': VTAPI})
        requestsession.headers.update({'content-type': 'application/json'})
        response = requestsession.get(finalurl)
        vttext = json.loads(response.text)

        if (response.status_code == 404):
            if (bkg == 1):
                print(mycolors.foreground.yellow + "\nURL NOT FOUND!")
            if (bkg == 0):
                print(mycolors.foreground.red + "\nURL NOT FOUND!")
        else:
            ok = "CLEAN"
            if(bkg == 1):
                if('last_final_url' in vttext['data']['attributes']):
                    last_final_url = vttext['data']['attributes']['last_final_url']
                    print(mycolors.foreground.lightred + "\nLast Final URL: ".ljust(26) + mycolors.reset + str(last_final_url), end='')
                if('last_analysis_stats' in vttext['data']['attributes']):
                    if('harmless' in vttext['data']['attributes']['last_analysis_stats']):
                        harmless = vttext['data']['attributes']['last_analysis_stats']['harmless']
                        print(mycolors.foreground.lightred + "\nHarmless: ".ljust(26) + mycolors.reset + str(harmless), end='')
                if('last_analysis_stats' in vttext['data']['attributes']):
                    if('malicious' in vttext['data']['attributes']['last_analysis_stats']):
                        malicious = vttext['data']['attributes']['last_analysis_stats']['malicious']
                        print(mycolors.foreground.lightred + "\nMalicious: ".ljust(26) + mycolors.reset + str(malicious), end='')
                if('last_analysis_stats' in vttext['data']['attributes']):
                    if('undetected' in vttext['data']['attributes']['last_analysis_stats']):
                        undetected = vttext['data']['attributes']['last_analysis_stats']['undetected']
                        print(mycolors.foreground.lightred + "\nUndetected: ".ljust(26) + mycolors.reset + str(undetected), end='')
                if('last_analysis_stats' in vttext['data']['attributes']):
                    if('suspicious' in vttext['data']['attributes']['last_analysis_stats']):
                        suspicious = vttext['data']['attributes']['last_analysis_stats']['suspicious']
                        print(mycolors.foreground.lightred + "\nSuspicious: ".ljust(26) + mycolors.reset + str(suspicious), end='')
                if('last_http_response_content_sha256' in vttext['data']['attributes']):
                    last_http_sha256 = vttext['data']['attributes']['last_http_response_content_sha256']
                    print(mycolors.foreground.yellow + "\n\nLast SHA256 Content: ".ljust(27) + mycolors.reset + last_http_sha256, end='')
                if('last_http_response_code' in vttext['data']['attributes']):
                    last_http_response = vttext['data']['attributes']['last_http_response_code']
                    print(mycolors.foreground.yellow + "\nLast HTTP Response Code: ".ljust(26) + mycolors.reset + str(last_http_response), end='')
                if('last_analysis_date' in vttext['data']['attributes']):
                    last_analysis_date = vttext['data']['attributes']['last_analysis_date']
                    print(mycolors.foreground.yellow + "\nLast Analysis Date: ".ljust(26) + mycolors.reset + str(datetime.fromtimestamp(last_analysis_date)), end='')
                if('times_submitted' in vttext['data']['attributes']):
                    times_submitted = vttext['data']['attributes']['times_submitted']
                    print(mycolors.foreground.yellow + "\nTimes Submitted: ".ljust(26) + mycolors.reset + str(times_submitted), end='')
                if('reputation' in vttext['data']['attributes']):
                    reputation = vttext['data']['attributes']['reputation']
                    print(mycolors.foreground.yellow + "\nReputation: ".ljust(26) + mycolors.reset + str(reputation), end='')
                if('threat_names' in vttext['data']['attributes']):
                    print(mycolors.foreground.lightcyan + "\n\nThreat Names: ", end='')
                    for name in vttext['data']['attributes']['threat_names']:
                        print(mycolors.reset + "\n".ljust(26) + str(name),end='')
                if('redirection_chain' in vttext['data']['attributes']):
                    print(mycolors.foreground.lightcyan + "\n\nRedirection Chain: ", end='')
                    for chain in vttext['data']['attributes']['redirection_chain']:
                        print(mycolors.reset + "\n".ljust(26) + str(chain),end='')

                vt_url_ip_domain_report_dark(vttext)


            if(bkg == 0):
                if('last_final_url' in vttext['data']['attributes']):
                    last_final_url = vttext['data']['attributes']['last_final_url']
                    print(mycolors.foreground.red + "\nLast Final URL: ".ljust(26) + mycolors.reset + str(last_final_url), end='')
                if('last_analysis_stats' in vttext['data']['attributes']):
                    if('harmless' in vttext['data']['attributes']['last_analysis_stats']):
                        harmless = vttext['data']['attributes']['last_analysis_stats']['harmless']
                        print(mycolors.foreground.red + "\nHarmless: ".ljust(26) + mycolors.reset + str(harmless), end='')
                if('last_analysis_stats' in vttext['data']['attributes']):
                    if('malicious' in vttext['data']['attributes']['last_analysis_stats']):
                        malicious = vttext['data']['attributes']['last_analysis_stats']['malicious']
                        print(mycolors.foreground.red + "\nMalicious: ".ljust(26) + mycolors.reset + str(malicious), end='')
                if('last_analysis_stats' in vttext['data']['attributes']):
                    if('undetected' in vttext['data']['attributes']['last_analysis_stats']):
                        undetected = vttext['data']['attributes']['last_analysis_stats']['undetected']
                        print(mycolors.foreground.red + "\nUndetected: ".ljust(26) + mycolors.reset + str(undetected), end='')
                if('last_analysis_stats' in vttext['data']['attributes']):
                    if('suspicious' in vttext['data']['attributes']['last_analysis_stats']):
                        suspicious = vttext['data']['attributes']['last_analysis_stats']['suspicious']
                        print(mycolors.foreground.red + "\nSuspicious: ".ljust(26) + mycolors.reset + str(suspicious), end='')
                if('last_http_response_content_sha256' in vttext['data']['attributes']):
                    last_http_sha256 = vttext['data']['attributes']['last_http_response_content_sha256']
                    print(mycolors.foreground.purple + "\n\nLast SHA256 Content: ".ljust(27) + mycolors.reset + last_http_sha256, end='')
                if('last_http_response_code' in vttext['data']['attributes']):
                    last_http_response = vttext['data']['attributes']['last_http_response_code']
                    print(mycolors.foreground.purple + "\nLast HTTP Response Code: ".ljust(26) + mycolors.reset + str(last_http_response), end='')
                if('last_analysis_date' in vttext['data']['attributes']):
                    last_analysis_date = vttext['data']['attributes']['last_analysis_date']
                    print(mycolors.foreground.purple + "\nLast Analysis Date: ".ljust(26) + mycolors.reset + str(datetime.fromtimestamp(last_analysis_date)), end='')
                if('times_submitted' in vttext['data']['attributes']):
                    times_submitted = vttext['data']['attributes']['times_submitted']
                    print(mycolors.foreground.purple + "\nTimes Submitted: ".ljust(26) + mycolors.reset + str(times_submitted), end='')
                if('reputation' in vttext['data']['attributes']):
                    reputation = vttext['data']['attributes']['reputation']
                    print(mycolors.foreground.purple + "\nReputation: ".ljust(26) + mycolors.reset + str(reputation), end='')
                if('threat_names' in vttext['data']['attributes']):
                    print(mycolors.foreground.green + "\n\nThreat Names: ", end='')
                    for name in vttext['data']['attributes']['threat_names']:
                        print(mycolors.reset + "\n".ljust(26) + str(name),end='')
                if('redirection_chain' in vttext['data']['attributes']):
                    print(mycolors.foreground.green + "\n\nRedirection Chain: ", end='')
                    for chain in vttext['data']['attributes']['redirection_chain']:
                        print(mycolors.reset + "\n".ljust(26) + str(chain),end='')

                vt_url_ip_domain_report_light(vttext)

            print("\n")

    except ValueError:
        if(bkg == 1):
            print((mycolors.foreground.lightred + "Error while connecting to Virus Total!\n"))
        else:
            print((mycolors.foreground.red + "Error while connecting to Virus Total!\n"))
        print(mycolors.reset)
        exit(3)


def vtuploadfile(file_item, url):

    try:

        finalurl = url
        requestsession = requests.Session( )
        requestsession.headers.update({'x-apikey': VTAPI})
        files = {'file': (file_item, open(file_item, 'rb'))}
        response = requestsession.post(finalurl, files=files)
        vttext = json.loads(response.text)

        if (response.status_code == 400):
            if (bkg == 1):
                print(mycolors.foreground.yellow + "\tThere was an issue while uploading the file.")
            if (bkg == 0):
                print(mycolors.foreground.blue + "\tThere was an issue while uploading the file.")
        else:

            if (bkg == 1):
                print(mycolors.foreground.lightcyan + "\n\tFile Submitted!" + mycolors.reset)
                print(mycolors.foreground.lightcyan + "\n\tid: " + mycolors.reset + vttext['data']['id'])
                print(mycolors.foreground.yellow + "\n\tWait for 120 seconds (at least) before requesting the report using -v 1 or -v 8 options!" + mycolors.reset)
            if (bkg == 0):
                print(mycolors.foreground.green + "\n\tFile Submitted!" + mycolors.reset)
                print(mycolors.foreground.green + "\n\tid: " + mycolors.reset + vttext['data']['id'])
                print(mycolors.foreground.purple + "\n\tWait for 120 seconds (at least) before requesting the report using -v 1 or -v 8 options!" + mycolors.reset)

    except ValueError as e:
        if(bkg == 1):
            print((mycolors.foreground.lightred + "Error while connecting to Virus Total!\n"))
        else:
            print((mycolors.foreground.red + "Error while connecting to Virus Total!\n"))
        print(mycolors.reset)
        exit(3)


def vtreportwork(myhash, url, prolog):

    try:

        finalurl = ''.join([url, "/", myhash ])
        requestsession = requests.Session( )
        requestsession.headers.update({'x-apikey': VTAPI})
        requestsession.headers.update({'content-type': 'application/json'})
        response = requestsession.get(finalurl)
        vttext = json.loads(response.text)

        if (response.status_code == 404):
            if (bkg == 1):
                print(mycolors.foreground.yellow + "\nSAMPLE NOT FOUND!")
            if (bkg == 0):
                print(mycolors.foreground.red + "\nSAMPLE NOT FOUND!")
        else:
            if(bkg == 1):
                if (prolog == 1):
                    if('md5' in vttext['data']['attributes']):
                        md5hash = vttext['data']['attributes']['md5']
                        print(mycolors.foreground.lightcyan + "\nMD5 hash: ".ljust(22) + mycolors.reset + md5hash, end='')
                    if('sha1' in vttext['data']['attributes']):
                        sha1hash = vttext['data']['attributes']['sha1']
                        print(mycolors.foreground.lightcyan + "\nSHA1 hash: ".ljust(22) + mycolors.reset + sha1hash, end='')
                    if('sha256' in vttext['data']['attributes']):
                        sha256hash = vttext['data']['attributes']['sha256']
                        print(mycolors.foreground.lightcyan + "\nSHA256 hash: ".ljust(22) + mycolors.reset + sha256hash, end='')
                    if('last_analysis_stats' in vttext['data']['attributes']):
                        malicious =  vttext['data']['attributes']['last_analysis_stats']['malicious']
                        undetected =  vttext['data']['attributes']['last_analysis_stats']['undetected']
                        print(mycolors.foreground.lightred + "\n\nMalicious: ".ljust(23) + mycolors.reset + str(malicious), end='')
                        print(mycolors.foreground.lightred + "\nUndetected: ".ljust(22) + mycolors.reset + str(undetected), end='\n')

                print(mycolors.foreground.lightred + "\nAV Report:", end='')
                if('last_analysis_results' in vttext['data']['attributes']):
                    ok = "CLEAN"
                    if('Avast' in vttext['data']['attributes']['last_analysis_results']):
                        result = vttext['data']['attributes']['last_analysis_results']['Avast']['result']
                        if(result):
                            print(mycolors.foreground.lightcyan + "\n".ljust(22) + "Avast: ".ljust(15) + mycolors.reset + result, end='')
                        else:
                            print(mycolors.foreground.lightcyan + "\n".ljust(22) + "Avast: ".ljust(15) + mycolors.reset + ok , end='')
                if('last_analysis_results' in vttext['data']['attributes']):
                    if('Avira' in vttext['data']['attributes']['last_analysis_results']):
                        result = vttext['data']['attributes']['last_analysis_results']['Avira']['result']
                        if(result):
                            print(mycolors.foreground.lightcyan + "\n".ljust(22) + "Avira: ".ljust(15) + mycolors.reset + result, end='')
                        else:
                            print(mycolors.foreground.lightcyan + "\n".ljust(22) + "Avira: ".ljust(15) + mycolors.reset + ok, end='')
                if('last_analysis_results' in vttext['data']['attributes']):
                    if('BitDefender' in vttext['data']['attributes']['last_analysis_results']):
                        result = vttext['data']['attributes']['last_analysis_results']['BitDefender']['result']
                        if(result):
                            print(mycolors.foreground.lightcyan + "\n".ljust(22) + "BitDefender: ".ljust(15) + mycolors.reset + result, end='')
                        else:
                            print(mycolors.foreground.lightcyan + "\n".ljust(22) + "BitDefender: ".ljust(15) + mycolors.reset + ok, end='')
                if('last_analysis_results' in vttext['data']['attributes']):
                    if('DrWeb' in vttext['data']['attributes']['last_analysis_results']):
                        result = vttext['data']['attributes']['last_analysis_results']['DrWeb']['result']
                        if(result):
                            print(mycolors.foreground.lightcyan + "\n".ljust(22) + "DrWeb: ".ljust(15) + mycolors.reset + result, end='')
                        else:
                            print(mycolors.foreground.lightcyan + "\n".ljust(22) + "DrWeb: ".ljust(15) + mycolors.reset + ok, end='')
                if('last_analysis_results' in vttext['data']['attributes']):
                    if('Emsisoft' in vttext['data']['attributes']['last_analysis_results']):
                        result = vttext['data']['attributes']['last_analysis_results']['Emsisoft']['result']
                        if(result):
                            print(mycolors.foreground.lightcyan + "\n".ljust(22) + "Emsisoft: ".ljust(15) + mycolors.reset + result, end='')
                        else:
                            print(mycolors.foreground.lightcyan + "\n".ljust(22) + "Emsisoft: ".ljust(15) + mycolors.reset + ok, end='')
                if('last_analysis_results' in vttext['data']['attributes']):
                    if('ESET-NOD32' in vttext['data']['attributes']['last_analysis_results']):
                        result = vttext['data']['attributes']['last_analysis_results']['ESET-NOD32']['result']
                        if(result):
                            print(mycolors.foreground.lightcyan + "\n".ljust(22) + "ESET-NOD32: ".ljust(15) + mycolors.reset + result, end='')
                        else:
                            print(mycolors.foreground.lightcyan + "\n".ljust(22) + "ESET-NOD32: ".ljust(15) + mycolors.reset + ok, end='')
                if('last_analysis_results' in vttext['data']['attributes']):
                    if('F-Secure' in vttext['data']['attributes']['last_analysis_results']):
                        result = vttext['data']['attributes']['last_analysis_results']['F-Secure']['result']
                        if(result):
                            print(mycolors.foreground.lightcyan + "\n".ljust(22) + "F-Secure: ".ljust(15) + mycolors.reset + result, end='')
                        else:
                            print(mycolors.foreground.lightcyan + "\n".ljust(22) + "F-Secure: ".ljust(15) + mycolors.reset + ok, end='')
                if('last_analysis_results' in vttext['data']['attributes']):
                    if('FireEye' in vttext['data']['attributes']['last_analysis_results']):
                        result = vttext['data']['attributes']['last_analysis_results']['FireEye']['result']
                        if(result):
                            print(mycolors.foreground.lightcyan + "\n".ljust(22) + "FireEye: ".ljust(15) + mycolors.reset + result, end='')
                        else:
                            print(mycolors.foreground.lightcyan + "\n".ljust(22) + "FireEye: ".ljust(15) + mycolors.reset + ok, end='')
                if('last_analysis_results' in vttext['data']['attributes']):
                    if('Fortinet' in vttext['data']['attributes']['last_analysis_results']):
                        result = vttext['data']['attributes']['last_analysis_results']['Fortinet']['result']
                        if(result):
                            print(mycolors.foreground.lightcyan + "\n".ljust(22) + "Fortinet: ".ljust(15) + mycolors.reset + result, end='')
                        else:
                            print(mycolors.foreground.lightcyan + "\n".ljust(22) + "Fortinet: ".ljust(15) + mycolors.reset + ok, end='')
                if('last_analysis_results' in vttext['data']['attributes']):
                    if('Kaspersky' in vttext['data']['attributes']['last_analysis_results']):
                        result = vttext['data']['attributes']['last_analysis_results']['Kaspersky']['result']
                        if(result):
                            print(mycolors.foreground.lightcyan + "\n".ljust(22) + "Kaspersky: ".ljust(15) + mycolors.reset + result, end='')
                        else:
                            print(mycolors.foreground.lightcyan + "\n".ljust(22) + "Kaspersky: ".ljust(15) + mycolors.reset + ok, end='')
                if('last_analysis_results' in vttext['data']['attributes']):
                    if('McAfee' in vttext['data']['attributes']['last_analysis_results']):
                        result = vttext['data']['attributes']['last_analysis_results']['McAfee']['result']
                        if(result):
                            print(mycolors.foreground.lightcyan + "\n".ljust(22) + "McAfee: ".ljust(15) + mycolors.reset + result, end='')
                        else:
                            print(mycolors.foreground.lightcyan + "\n".ljust(22) + "McAfee: ".ljust(15) + mycolors.reset + ok, end='')
                if('last_analysis_results' in vttext['data']['attributes']):
                    if('Microsoft' in vttext['data']['attributes']['last_analysis_results']):
                        result = vttext['data']['attributes']['last_analysis_results']['Microsoft']['result']
                        if(result):
                            print(mycolors.foreground.lightcyan + "\n".ljust(22) + "Microsoft: ".ljust(15) + mycolors.reset + result, end='')
                        else:
                            print(mycolors.foreground.lightcyan + "\n".ljust(22) + "Microsoft: ".ljust(15) + mycolors.reset + ok, end='')
                if('last_analysis_results' in vttext['data']['attributes']):
                    if('Panda' in vttext['data']['attributes']['last_analysis_results']):
                        result = vttext['data']['attributes']['last_analysis_results']['Panda']['result']
                        if(result):
                            print(mycolors.foreground.lightcyan + "\n".ljust(22) + "Panda: ".ljust(15) + mycolors.reset + result, end='')
                        else:
                            print(mycolors.foreground.lightcyan + "\n".ljust(22) + "Panda: ".ljust(15) + mycolors.reset + ok, end='')
                if('last_analysis_results' in vttext['data']['attributes']):
                    if('Sophos' in vttext['data']['attributes']['last_analysis_results']):
                        result = vttext['data']['attributes']['last_analysis_results']['Sophos']['result']
                        if(result):
                            print(mycolors.foreground.lightcyan + "\n".ljust(22) + "Sophos: ".ljust(15) + mycolors.reset + result, end='')
                        else:
                            print(mycolors.foreground.lightcyan + "\n".ljust(22) + "Sophos: ".ljust(15) + mycolors.reset + ok, end='')
                if('last_analysis_results' in vttext['data']['attributes']):
                    if('Symantec' in vttext['data']['attributes']['last_analysis_results']):
                        result = vttext['data']['attributes']['last_analysis_results']['Symantec']['result']
                        if(result):
                            print(mycolors.foreground.lightcyan + "\n".ljust(22) + "Symantec: ".ljust(15) + mycolors.reset + result, end='')
                        else:
                            print(mycolors.foreground.lightcyan + "\n".ljust(22) + "Symantec: ".ljust(15) + mycolors.reset + ok, end='')
                if('last_analysis_results' in vttext['data']['attributes']):
                    if('TrendMicro' in vttext['data']['attributes']['last_analysis_results']):
                        result = vttext['data']['attributes']['last_analysis_results']['TrendMicro']['result']
                        if(result):
                            print(mycolors.foreground.lightcyan + "\n".ljust(22) + "TrendMicro: ".ljust(15) + mycolors.reset + result, end='')
                        else:
                            print(mycolors.foreground.lightcyan + "\n".ljust(22) + "TrendMicro: ".ljust(15) + mycolors.reset + ok, end='')
                if('last_analysis_results' in vttext['data']['attributes']):
                    if('ZoneAlarm' in vttext['data']['attributes']['last_analysis_results']):
                        result = vttext['data']['attributes']['last_analysis_results']['ZoneAlarm']['result']
                        if(result):
                            print(mycolors.foreground.lightcyan + "\n".ljust(22) + "ZoneAlarm: ".ljust(15) + mycolors.reset + result, end='')
                        else:
                            print(mycolors.foreground.lightcyan + "\n".ljust(22) + "ZoneAlarm: ".ljust(15) + mycolors.reset + ok, end='')

            if(bkg == 0):
                if (prolog == 1):
                    if('md5' in vttext['data']['attributes']):
                        md5hash = vttext['data']['attributes']['md5']
                        print(mycolors.foreground.cyan + "\nMD5 hash: ".ljust(22) + mycolors.reset + md5hash, end='')
                    if('sha1' in vttext['data']['attributes']):
                        sha1hash = vttext['data']['attributes']['sha1']
                        print(mycolors.foreground.cyan + "\nSHA1 hash: ".ljust(22) + mycolors.reset + sha1hash, end='')
                    if('sha256' in vttext['data']['attributes']):
                        sha256hash = vttext['data']['attributes']['sha256']
                        print(mycolors.foreground.cyan + "\nSHA256 hash: ".ljust(22) + mycolors.reset + sha256hash, end='')
                    if('last_analysis_stats' in vttext['data']['attributes']):
                        malicious =  vttext['data']['attributes']['last_analysis_stats']['malicious']
                        undetected =  vttext['data']['attributes']['last_analysis_stats']['undetected']
                        print(mycolors.foreground.red + "\n\nMalicious: ".ljust(23) + mycolors.reset + str(malicious), end='')
                        print(mycolors.foreground.red + "\nUndetected: ".ljust(22) + mycolors.reset + str(undetected), end='\n')

                print(mycolors.foreground.red + "\nAV Report:", end='')
                ok = "CLEAN"
                if('last_analysis_results' in vttext['data']['attributes']):
                    if('Avast' in vttext['data']['attributes']['last_analysis_results']):
                        result = vttext['data']['attributes']['last_analysis_results']['Avast']['result']
                        if(result):
                            print(mycolors.foreground.cyan + "\n".ljust(22) + "Avast: ".ljust(15) + mycolors.reset + result, end='')
                        else:
                            print(mycolors.foreground.cyan + "\n".ljust(22) + "Avast: ".ljust(15) + mycolors.reset + ok, end='')
                if('last_analysis_results' in vttext['data']['attributes']):
                    if('Avira' in vttext['data']['attributes']['last_analysis_results']):
                        result = vttext['data']['attributes']['last_analysis_results']['Avira']['result']
                        if(result):
                            print(mycolors.foreground.cyan + "\n".ljust(22) + "Avira: ".ljust(15) + mycolors.reset + result, end='')
                        else:
                            print(mycolors.foreground.cyan + "\n".ljust(22) + "Avira: ".ljust(15) + mycolors.reset + ok, end='')
                if('last_analysis_results' in vttext['data']['attributes']):
                    if('BitDefender' in vttext['data']['attributes']['last_analysis_results']):
                        result = vttext['data']['attributes']['last_analysis_results']['BitDefender']['result']
                        if(result):
                            print(mycolors.foreground.cyan + "\n".ljust(22) + "BitDefender: ".ljust(15) + mycolors.reset + result, end='')
                        else:
                            print(mycolors.foreground.cyan + "\n".ljust(22) + "BitDefender: ".ljust(15) + mycolors.reset + ok, end='')
                if('last_analysis_results' in vttext['data']['attributes']):
                    if('DrWeb' in vttext['data']['attributes']['last_analysis_results']):
                        result = vttext['data']['attributes']['last_analysis_results']['DrWeb']['result']
                        if(result):
                            print(mycolors.foreground.cyan + "\n".ljust(22) + "DrWeb: ".ljust(15) + mycolors.reset + result, end='')
                        else:
                            print(mycolors.foreground.cyan + "\n".ljust(22) + "DrWeb: ".ljust(15) + mycolors.reset + ok, end='')
                if('last_analysis_results' in vttext['data']['attributes']):
                    if('Emsisoft' in vttext['data']['attributes']['last_analysis_results']):
                        result = vttext['data']['attributes']['last_analysis_results']['Emsisoft']['result']
                        if(result):
                            print(mycolors.foreground.cyan + "\n".ljust(22) + "Emsisoft: ".ljust(15) + mycolors.reset + result, end='')
                        else:
                            print(mycolors.foreground.cyan + "\n".ljust(22) + "Emsisoft: ".ljust(15) + mycolors.reset + ok, end='')
                if('last_analysis_results' in vttext['data']['attributes']):
                    if('ESET-NOD32' in vttext['data']['attributes']['last_analysis_results']):
                        result = vttext['data']['attributes']['last_analysis_results']['ESET-NOD32']['result']
                        if(result):
                            print(mycolors.foreground.cyan + "\n".ljust(22) + "ESET-NOD32: ".ljust(15) + mycolors.reset + result, end='')
                        else:
                            print(mycolors.foreground.cyan + "\n".ljust(22) + "ESET-NOD32: ".ljust(15) + mycolors.reset + ok, end='')
                if('last_analysis_results' in vttext['data']['attributes']):
                    if('F-Secure' in vttext['data']['attributes']['last_analysis_results']):
                        result = vttext['data']['attributes']['last_analysis_results']['F-Secure']['result']
                        if(result):
                            print(mycolors.foreground.cyan + "\n".ljust(22) + "F-Secure: ".ljust(15) + mycolors.reset + result, end='')
                        else:
                            print(mycolors.foreground.cyan + "\n".ljust(22) + "F-Secure: ".ljust(15) + mycolors.reset + ok, end='')
                if('last_analysis_results' in vttext['data']['attributes']):
                    if('FireEye' in vttext['data']['attributes']['last_analysis_results']):
                        result = vttext['data']['attributes']['last_analysis_results']['FireEye']['result']
                        if(result):
                            print(mycolors.foreground.cyan + "\n".ljust(22) + "FireEye: ".ljust(15) + mycolors.reset + result, end='')
                        else:
                            print(mycolors.foreground.cyan + "\n".ljust(22) + "FireEye: ".ljust(15) + mycolors.reset + ok, end='')
                if('last_analysis_results' in vttext['data']['attributes']):
                    if('Fortinet' in vttext['data']['attributes']['last_analysis_results']):
                        result = vttext['data']['attributes']['last_analysis_results']['Fortinet']['result']
                        if(result):
                            print(mycolors.foreground.cyan + "\n".ljust(22) + "Fortinet: ".ljust(15) + mycolors.reset + result, end='')
                        else:
                            print(mycolors.foreground.cyan + "\n".ljust(22) + "Fortinet: ".ljust(15) + mycolors.reset + ok, end='')
                if('last_analysis_results' in vttext['data']['attributes']):
                    if('Kaspersky' in vttext['data']['attributes']['last_analysis_results']):
                        result = vttext['data']['attributes']['last_analysis_results']['Kaspersky']['result']
                        if(result):
                            print(mycolors.foreground.cyan + "\n".ljust(22) + "Kaspersky: ".ljust(15) + mycolors.reset + result, end='')
                        else:
                            print(mycolors.foreground.cyan + "\n".ljust(22) + "Kaspersky: ".ljust(15) + mycolors.reset + ok, end='')
                if('last_analysis_results' in vttext['data']['attributes']):
                    if('McAfee' in vttext['data']['attributes']['last_analysis_results']):
                        result = vttext['data']['attributes']['last_analysis_results']['McAfee']['result']
                        if(result):
                            print(mycolors.foreground.cyan + "\n".ljust(22) + "McAfee: ".ljust(15) + mycolors.reset + result, end='')
                        else:
                            print(mycolors.foreground.cyan + "\n".ljust(22) + "McAfee: ".ljust(15) + mycolors.reset + ok, end='')
                if('last_analysis_results' in vttext['data']['attributes']):
                    if('Microsoft' in vttext['data']['attributes']['last_analysis_results']):
                        result = vttext['data']['attributes']['last_analysis_results']['Microsoft']['result']
                        if(result):
                            print(mycolors.foreground.cyan + "\n".ljust(22) + "Microsoft: ".ljust(15) + mycolors.reset + result, end='')
                        else:
                            print(mycolors.foreground.cyan + "\n".ljust(22) + "Microsoft: ".ljust(15) + mycolors.reset + ok, end='')
                if('last_analysis_results' in vttext['data']['attributes']):
                    if('Panda' in vttext['data']['attributes']['last_analysis_results']):
                        result = vttext['data']['attributes']['last_analysis_results']['Panda']['result']
                        if(result):
                            print(mycolors.foreground.cyan + "\n".ljust(22) + "Panda: ".ljust(15) + mycolors.reset + result, end='')
                        else:
                            print(mycolors.foreground.cyan + "\n".ljust(22) + "Panda: ".ljust(15) + mycolors.reset + ok, end='')
                if('last_analysis_results' in vttext['data']['attributes']):
                    if('Sophos' in vttext['data']['attributes']['last_analysis_results']):
                        result = vttext['data']['attributes']['last_analysis_results']['Sophos']['result']
                        if(result):
                            print(mycolors.foreground.cyan + "\n".ljust(22) + "Sophos: ".ljust(15) + mycolors.reset + result, end='')
                        else:
                            print(mycolors.foreground.cyan + "\n".ljust(22) + "Sophos: ".ljust(15) + mycolors.reset + ok, end='')
                if('last_analysis_results' in vttext['data']['attributes']):
                    if('Symantec' in vttext['data']['attributes']['last_analysis_results']):
                        result = vttext['data']['attributes']['last_analysis_results']['Symantec']['result']
                        if(result):
                            print(mycolors.foreground.cyan + "\n".ljust(22) + "Symantec: ".ljust(15) + mycolors.reset + result, end='')
                        else:
                            print(mycolors.foreground.cyan + "\n".ljust(22) + "Symantec: ".ljust(15) + mycolors.reset + ok, end='')
                if('last_analysis_results' in vttext['data']['attributes']):
                    if('TrendMicro' in vttext['data']['attributes']['last_analysis_results']):
                        result = vttext['data']['attributes']['last_analysis_results']['TrendMicro']['result']
                        if(result):
                            print(mycolors.foreground.cyan + "\n".ljust(22) + "TrendMicro: ".ljust(15) + mycolors.reset + result, end='')
                        else:
                            print(mycolors.foreground.cyan + "\n".ljust(22) + "TrendMicro: ".ljust(15) + mycolors.reset + ok, end='')
                if('last_analysis_results' in vttext['data']['attributes']):
                    if('ZoneAlarm' in vttext['data']['attributes']['last_analysis_results']):
                        result = vttext['data']['attributes']['last_analysis_results']['ZoneAlarm']['result']
                        if(result):
                            print(mycolors.foreground.cyan + "\n".ljust(22) + "ZoneAlarm: ".ljust(15) + mycolors.reset + result, end='')
                        else:
                            print(mycolors.foreground.cyan + "\n".ljust(22) + "ZoneAlarm: ".ljust(15) + mycolors.reset + ok, end='')

            print("\n")

    except ValueError as e:
        if(bkg == 1):
            print((mycolors.foreground.lightred + "Error while connecting to Virus Total!\n"))
        else:
            print((mycolors.foreground.red + "Error while connecting to Virus Total!\n"))
        print(mycolors.reset)
        exit(3)


def vthashwork(myhash, url, showreport):

    try:

        finalurl = ''.join([url, "/", myhash ])
        requestsession = requests.Session( )
        requestsession.headers.update({'x-apikey': VTAPI})
        requestsession.headers.update({'content-type': 'application/json'})
        response = requestsession.get(finalurl)
        vttext = json.loads(response.text)

        if (response.status_code == 404):
            if (bkg == 1):
                print(mycolors.foreground.yellow + "\nSAMPLE NOT FOUND!")
            if (bkg == 0):
                print(mycolors.foreground.red + "\nSAMPLE NOT FOUND!")
        else:
            if(bkg == 1):
                if('md5' in vttext['data']['attributes']):
                    md5hash = vttext['data']['attributes']['md5']
                    print(mycolors.foreground.lightcyan + "\nMD5 hash: ".ljust(22) + mycolors.reset + md5hash, end='')
                if('sha1' in vttext['data']['attributes']):
                    sha1hash = vttext['data']['attributes']['sha1']
                    print(mycolors.foreground.lightcyan + "\nSHA1 hash: ".ljust(22) + mycolors.reset + sha1hash, end='')
                if('sha256' in vttext['data']['attributes']):
                    sha256hash = vttext['data']['attributes']['sha256']
                    print(mycolors.foreground.lightcyan + "\nSHA256 hash: ".ljust(22) + mycolors.reset + sha256hash, end='')
                if('last_analysis_stats' in vttext['data']['attributes']):
                    malicious =  vttext['data']['attributes']['last_analysis_stats']['malicious']
                    undetected =  vttext['data']['attributes']['last_analysis_stats']['undetected']
                    print(mycolors.foreground.lightred + "\n\nMalicious: ".ljust(23) + mycolors.reset + str(malicious), end='')
                    print(mycolors.foreground.lightred + "\nUndetected: ".ljust(22) + mycolors.reset + str(undetected), end='\n')
                if('type_description' in vttext['data']['attributes']):
                    type_description = vttext['data']['attributes']['type_description']
                    print(mycolors.foreground.yellow + "\nType Description: ".ljust(22) + mycolors.reset + type_description, end='')
                if('size' in vttext['data']['attributes']):
                    size = vttext['data']['attributes']['size']
                    print(mycolors.foreground.yellow + "\nSize: ".ljust(22) + mycolors.reset + str(size), end='')
                if('last_analysis_date' in vttext['data']['attributes']):
                    last_analysis_date = vttext['data']['attributes']['last_analysis_date']
                    print(mycolors.foreground.yellow + "\nLast Analysis Date: ".ljust(22) + mycolors.reset + str(datetime.fromtimestamp(last_analysis_date)), end='')
                if('type_tag' in vttext['data']['attributes']):
                    type_tag = vttext['data']['attributes']['type_tag']
                    print(mycolors.foreground.yellow + "\nType Tag: ".ljust(22) + mycolors.reset + type_tag, end='')
                if('times_submitted' in vttext['data']['attributes']):
                    times_submitted = vttext['data']['attributes']['times_submitted']
                    print(mycolors.foreground.yellow + "\nTimes Submitted: ".ljust(22) + mycolors.reset + str(times_submitted), end='')
                if('popular_threat_classification' in vttext['data']['attributes']):
                    print(mycolors.foreground.lightred + "\n\nThreat Label: ".ljust(23), end='')
                    if('suggested_threat_label' in vttext['data']['attributes']['popular_threat_classification']):
                        threat_label = vttext['data']['attributes']['popular_threat_classification']['suggested_threat_label']
                    else:
                        threat_label = 'NO GIVEN NAME'
                    print(mycolors.reset + str(threat_label),end='')
                    if('popular_threat_category' in vttext['data']['attributes']['popular_threat_classification']):
                        print(mycolors.foreground.lightred + "\nClassification: ", end='')
                        for popular in vttext['data']['attributes']['popular_threat_classification']['popular_threat_category']:
                            count = popular['count']
                            value = popular['value'] 
                            print(mycolors.reset + "\n".ljust(22) + "popular count: ".ljust(15) + str(count),end='')
                            print(mycolors.reset + "\n".ljust(22) + "label: ".ljust(15) + str(value),end='\n')
                if('trid' in vttext['data']['attributes']):
                    print(mycolors.foreground.lightcyan + "\nTrid: ", end='')
                    for trid in vttext['data']['attributes']['trid']:
                        file_type = trid['file_type']
                        probability = trid['probability'] 
                        print(mycolors.reset + "\n".ljust(22) + "file_type: ".ljust(15) + str(file_type),end='')
                        print(mycolors.reset + "\n".ljust(22) + "probability: ".ljust(15) + str(probability),end='\n')
                if('names' in vttext['data']['attributes']):
                    print(mycolors.foreground.lightcyan + "\nNames: ", end='')
                    for name in vttext['data']['attributes']['names']:
                        print(mycolors.reset + ("\n".ljust(22) + (mycolors.reset + "\n".ljust(22)).join(textwrap.wrap(" ".join(name.split()),width=80))),end=' ')
                if('pe_info' in vttext['data']['attributes']):
                    print(mycolors.foreground.lightred + "\n\nPE Info: ", end='')
                    if('imphash' in vttext['data']['attributes']['pe_info']):
                        imphash = vttext['data']['attributes']['pe_info']['imphash']
                        print(mycolors.foreground.yellow + "\n".ljust(22) + "Imphash: ".ljust(15) + mycolors.reset + str(imphash),end='')
                    if('import_list' in vttext['data']['attributes']['pe_info']):
                        print(mycolors.foreground.yellow + "\n".ljust(22) + "Libraries: ".ljust(15),end='')
                        for lib in vttext['data']['attributes']['pe_info']['import_list']:
                            print(mycolors.reset + "\n".ljust(37) + str(lib['library_name']),end='')
                    if('sections' in vttext['data']['attributes']['pe_info']):
                        print(mycolors.foreground.yellow + "\n".ljust(22) + "Sections: ",end='')
                        for section in vttext['data']['attributes']['pe_info']['sections']:
                            if('name' in section):
                                section_name = section['name']
                                print(mycolors.reset + "\n\n".ljust(38) + "section_name: ".ljust(14) + str(section_name),end=' ')
                            if('virtual_size' in section):
                                virtual_size = section['virtual_size']
                                print(mycolors.reset + "\n".ljust(37) + "virtual_size: ".ljust(14) + str(virtual_size),end=' ')
                            if('entropy' in section):
                                entropy = section['entropy'] 
                                print(mycolors.reset + "\n".ljust(37) + "entropy: ".ljust(14) + str(entropy),end=' ')
                            if('flags' in section):
                                flags = section['flags'] 
                                print(mycolors.reset + "\n".ljust(37) + "flags: ".ljust(14) + str(flags),end=' ')
                if('androguard' in vttext['data']['attributes']):
                    print(mycolors.foreground.lightcyan + "\n\nAndroguard: ", end='')
                    if('Activities' in vttext['data']['attributes']['androguard']):
                        print(mycolors.foreground.lightred + "\n".ljust(22) + "Activities: ".ljust(23), end='')
                        for activity in vttext['data']['attributes']['androguard']['Activities']:
                            print(mycolors.reset + "\n".ljust(37) + activity,end='')
                    if('main_activity' in vttext['data']['attributes']['androguard']):
                        print(mycolors.foreground.lightred + "\n\n".ljust(23) + "MainActivity: ".ljust(15), end='')
                        mainactivity = vttext['data']['attributes']['androguard']['main_activity']
                        print(mycolors.reset + mainactivity,end='')
                    if('Package' in vttext['data']['attributes']['androguard']):
                        print(mycolors.foreground.lightred + "\n".ljust(22) + "Package: ".ljust(15), end='')
                        mainactivity = vttext['data']['attributes']['androguard']['Package']
                        print(mycolors.reset + mainactivity,end='\n')
                    if('Providers' in vttext['data']['attributes']['androguard']):
                        print(mycolors.foreground.lightred + "\n".ljust(22) + "Providers: ".ljust(23), end='')
                        for provider in vttext['data']['attributes']['androguard']['Providers']:
                            print(mycolors.reset + "\n".ljust(37) + provider,end='')
                    if('Receivers' in vttext['data']['attributes']['androguard']):
                        print(mycolors.foreground.lightred + "\n".ljust(22) + "Receivers: ".ljust(23), end='')
                        for receiver in vttext['data']['attributes']['androguard']['Receivers']:
                            print(mycolors.reset + "\n".ljust(37) + receiver,end='')
                    if('Libraries' in vttext['data']['attributes']['androguard']):
                        print(mycolors.foreground.lightred + "\n".ljust(22) + "Libraries: ".ljust(23), end='')
                        for library in vttext['data']['attributes']['androguard']['Libraries']:
                            print(mycolors.reset + "\n".ljust(37) + library,end='')
                    if('Services' in vttext['data']['attributes']['androguard']):
                        print(mycolors.foreground.lightred + "\n".ljust(22) + "Services: ".ljust(23), end='')
                        for service in vttext['data']['attributes']['androguard']['Services']:
                            print(mycolors.reset + "\n".ljust(37) + service,end='')
                    if('StringsInformation' in vttext['data']['attributes']['androguard']):
                        print(mycolors.foreground.lightred + "\n".ljust(22) + "StringsInfo: ".ljust(23), end='')
                        for string in vttext['data']['attributes']['androguard']['StringsInformation']:
                            print(mycolors.reset + "\n".ljust(37) + string,end='')
                    if('certificate' in vttext['data']['attributes']['androguard']):
                        print(mycolors.foreground.lightred + "\n".ljust(22) + "Certificate: ", end='')
                        if('Issuer' in vttext['data']['attributes']['androguard']['certificate']):
                            print(mycolors.foreground.lightcyan + "\n".ljust(37) + "Issuer: ".ljust(15), end=' ')
                            if('DN' in vttext['data']['attributes']['androguard']['certificate']['Issuer']):
                                dn = vttext['data']['attributes']['androguard']['certificate']['Issuer']['DN']
                                print(mycolors.reset + "DN: " + dn,end='')
                        if('Subject' in vttext['data']['attributes']['androguard']['certificate']):
                            print(mycolors.foreground.lightcyan + "\n".ljust(37) + "Subject: ".ljust(15), end=' ')
                            if('DN' in vttext['data']['attributes']['androguard']['certificate']['Subject']):
                                dn = vttext['data']['attributes']['androguard']['certificate']['Subject']['DN']
                                print(mycolors.reset + "DN: " + dn,end='')
                        if('serialnumber' in vttext['data']['attributes']['androguard']['certificate']):
                            print(mycolors.foreground.lightcyan + "\n".ljust(37) + "SerialNumber: ".ljust(15), end=' ')
                            serialnumber = vttext['data']['attributes']['androguard']['certificate']['serialnumber']
                            print(mycolors.reset + serialnumber,end='')
                        if('validfrom' in vttext['data']['attributes']['androguard']['certificate']):
                            print(mycolors.foreground.lightcyan + "\n".ljust(37) + "ValidFrom: ".ljust(15), end=' ')
                            validfrom = vttext['data']['attributes']['androguard']['certificate']['validfrom']
                            print(mycolors.reset + validfrom,end='')
                        if('validto' in vttext['data']['attributes']['androguard']['certificate']):
                            print(mycolors.foreground.lightcyan + "\n".ljust(37) + "ValidTo: ".ljust(15), end=' ')
                            validto = vttext['data']['attributes']['androguard']['certificate']['validto']
                            print(mycolors.reset + validto,end='')
                        if('thumbprint' in vttext['data']['attributes']['androguard']['certificate']):
                            print(mycolors.foreground.lightcyan + "\n".ljust(37) + "Thumbprint: ".ljust(15), end=' ')
                            thumbprint = vttext['data']['attributes']['androguard']['certificate']['thumbprint']
                            print(mycolors.reset + thumbprint,end='')
                    if('intent_filters' in vttext['data']['attributes']['androguard']):
                        print(mycolors.foreground.lightred + "\n".ljust(22) + "IntentFilters: ", end='')
                        if('Activities' in vttext['data']['attributes']['androguard']['intent_filters']):
                            print(mycolors.foreground.lightcyan + "\n".ljust(37) + "Activities: ".ljust(15), end=' ')
                            for key, value in (vttext['data']['attributes']['androguard']['intent_filters']['Activities']).items():
                                print(mycolors.reset + "\n\n".ljust(54) + mycolors.foreground.yellow + "name: ".ljust(11) + mycolors.reset + key,end='')
                                if('action' in value):
                                    for action_item in value['action']:
                                        print(mycolors.reset + "\n".ljust(53) + mycolors.foreground.lightcyan + "action: ".ljust(11) + mycolors.reset + action_item,end='')
                                if('category' in value):
                                    for category in value['category']:
                                        print(mycolors.reset + "\n".ljust(53) + mycolors.foreground.lightcyan + "category: ".ljust(11) + mycolors.reset + category,end='')
                        if('Receivers' in vttext['data']['attributes']['androguard']['intent_filters']):
                            print(mycolors.foreground.lightcyan + "\n".ljust(37) + "Receivers: ".ljust(15), end=' ')
                            for key, value in (vttext['data']['attributes']['androguard']['intent_filters']['Receivers']).items():
                                print(mycolors.reset + "\n\n".ljust(54) + mycolors.foreground.yellow + "name: ".ljust(11) + mycolors.reset + key,end='')
                                if('action' in value):
                                    for action_item in value['action']:
                                        print(mycolors.reset + "\n".ljust(53) + mycolors.foreground.lightcyan + "action: ".ljust(11) + mycolors.reset + action_item,end='')
                                if('category' in value):
                                    for category in value['category']:
                                        print(mycolors.reset + "\n".ljust(53) + mycolors.foreground.lightcyan + "category: ".ljust(11) + mycolors.reset + category,end='')
                        if('Services' in vttext['data']['attributes']['androguard']['intent_filters']):
                            print(mycolors.foreground.lightcyan + "\n".ljust(37) + "Services: ".ljust(15), end=' ')
                            for key, value in (vttext['data']['attributes']['androguard']['intent_filters']['Services']).items():
                                print(mycolors.reset + "\n\n".ljust(54) + mycolors.foreground.yellow + "name: ".ljust(11) + mycolors.reset + key,end='')
                                if('action' in value):
                                    for action_item in value['action']:
                                        print(mycolors.reset + "\n".ljust(53) + mycolors.foreground.lightcyan + "action: ".ljust(11) + mycolors.reset + action_item,end='')
                                if('category' in value):
                                    for category in value['category']:
                                        print(mycolors.reset + "\n".ljust(53) + mycolors.foreground.lightcyan + "category: ".ljust(11) + mycolors.reset + category,end='')
                    if('permission_details' in vttext['data']['attributes']['androguard']):
                        print(mycolors.foreground.lightred + "\n".ljust(22) + "Permissions: ", end='')
                        for key, value in (vttext['data']['attributes']['androguard']['permission_details']).items():
                            print(mycolors.reset + "\n\n".ljust(54) + mycolors.foreground.yellow + "name: ".ljust(11) + mycolors.reset + key,end='')
                            if('full_description' in value):
                                print(mycolors.reset + ("\n".ljust(53) + mycolors.foreground.lightcyan + "details: ".ljust(11) + mycolors.reset + (mycolors.reset + "\n".ljust(64)).join(textwrap.wrap(" ".join(value['full_description'].split()),width=80))),end=' ')
                            if('permission_type' in value):
                                print(mycolors.reset + "\n".ljust(53) + mycolors.foreground.lightcyan + "type: ".ljust(11) + mycolors.reset + value['permission_type'],end='')
                            if('short_description' in value):
                                print(mycolors.reset + ("\n".ljust(53) + mycolors.foreground.lightcyan + "info: ".ljust(11) + mycolors.reset + ("\n" + mycolors.reset + "".ljust(63)).join(textwrap.wrap(value['short_description'],width=80))),end=' ')

                print("\n")

                if(showreport == 1):
                    vtreportwork(myhash, url, 0)

            if(bkg == 0):
                if('md5' in vttext['data']['attributes']):
                    md5hash = vttext['data']['attributes']['md5']
                    print(mycolors.foreground.cyan + "\nMD5 hash: ".ljust(22) + mycolors.reset + md5hash, end='')
                if('sha1' in vttext['data']['attributes']):
                    sha1hash = vttext['data']['attributes']['sha1']
                    print(mycolors.foreground.cyan + "\nSHA1 hash: ".ljust(22) + mycolors.reset + sha1hash, end='')
                if('sha256' in vttext['data']['attributes']):
                    sha256hash = vttext['data']['attributes']['sha256']
                    print(mycolors.foreground.cyan + "\nSHA256 hash: ".ljust(22) + mycolors.reset + sha256hash, end='')
                if('last_analysis_stats' in vttext['data']['attributes']):
                    malicious =  vttext['data']['attributes']['last_analysis_stats']['malicious']
                    undetected =  vttext['data']['attributes']['last_analysis_stats']['undetected']
                    print(mycolors.foreground.red + "\n\nMalicious: ".ljust(23) + mycolors.reset + str(malicious), end='')
                    print(mycolors.foreground.red + "\nUndetected: ".ljust(22) + mycolors.reset + str(undetected), end='\n')
                if('type_description' in vttext['data']['attributes']):
                    type_description = vttext['data']['attributes']['type_description']
                    print(mycolors.foreground.purple + "\nType Description: ".ljust(22) + mycolors.reset + type_description, end='')
                if('size' in vttext['data']['attributes']):
                    size = vttext['data']['attributes']['size']
                    print(mycolors.foreground.purple + "\nSize: ".ljust(22) + mycolors.reset + str(size), end='')
                if('last_analysis_date' in vttext['data']['attributes']):
                    last_analysis_date = vttext['data']['attributes']['last_analysis_date']
                    print(mycolors.foreground.purple + "\nLast Analysis Date: ".ljust(22) + mycolors.reset + str(datetime.fromtimestamp(last_analysis_date)), end='')
                if('type_tag' in vttext['data']['attributes']):
                    type_tag = vttext['data']['attributes']['type_tag']
                    print(mycolors.foreground.cyan + "\nType Tag: ".ljust(22) + mycolors.reset + type_tag, end='')
                if('times_submitted' in vttext['data']['attributes']):
                    times_submitted = vttext['data']['attributes']['times_submitted']
                    print(mycolors.foreground.cyan + "\nTimes Submitted: ".ljust(22) + mycolors.reset + str(times_submitted), end='')
                if('popular_threat_classification' in vttext['data']['attributes']):
                    print(mycolors.foreground.red + "\n\nThreat Label: ".ljust(23), end='')
                    if('suggested_threat_label' in vttext['data']['attributes']['popular_threat_classification']):
                        threat_label = vttext['data']['attributes']['popular_threat_classification']['suggested_threat_label']
                    else:
                        threat_label = 'NO GIVEN NAME'
                    print(mycolors.reset + str(threat_label),end='')
                    if('popular_threat_category' in vttext['data']['attributes']['popular_threat_classification']):
                        print(mycolors.foreground.red + "\nClassification: ", end='')
                        for popular in vttext['data']['attributes']['popular_threat_classification']['popular_threat_category']:
                            count = popular['count']
                            value = popular['value'] 
                            print(mycolors.reset + "\n".ljust(22) + "popular count: ".ljust(15) + str(count),end='')
                            print(mycolors.reset + "\n".ljust(22) + "label: ".ljust(15) + str(value),end='\n')
                if('trid' in vttext['data']['attributes']):
                    print(mycolors.foreground.cyan + "\nTrid: ", end='')
                    for trid in vttext['data']['attributes']['trid']:
                        file_type = trid['file_type']
                        probability = trid['probability'] 
                        print(mycolors.reset + "\n".ljust(22) + "file_type: ".ljust(15) + str(file_type),end='')
                        print(mycolors.reset + "\n".ljust(22) + "probability: ".ljust(15) + str(probability),end='\n')
                if('names' in vttext['data']['attributes']):
                    print(mycolors.foreground.cyan + "\nNames: ", end='')
                    for name in vttext['data']['attributes']['names']:
                        print(mycolors.reset + ("\n".ljust(22) + (mycolors.reset + "\n".ljust(22)).join(textwrap.wrap(" ".join(name.split()),width=80))),end=' ')
                if('pe_info' in vttext['data']['attributes']):
                    print(mycolors.foreground.red + "\n\nPE Info: ", end='')
                    if('imphash' in vttext['data']['attributes']['pe_info']):
                        imphash = vttext['data']['attributes']['pe_info']['imphash']
                        print(mycolors.foreground.blue + "\n".ljust(22) + "Imphash: ".ljust(15) + mycolors.reset + str(imphash),end='')
                    if('import_list' in vttext['data']['attributes']['pe_info']):
                        print(mycolors.foreground.blue + "\n".ljust(22) + "Libraries: ".ljust(15),end='')
                        for lib in vttext['data']['attributes']['pe_info']['import_list']:
                            print(mycolors.reset + "\n".ljust(37) + str(lib['library_name']),end='')
                    if('sections' in vttext['data']['attributes']['pe_info']):
                        print(mycolors.foreground.blue + "\n".ljust(22) + "Sections: ",end='')
                        for section in vttext['data']['attributes']['pe_info']['sections']:
                            if('name' in section):
                                section_name = section['name']
                                print(mycolors.reset + "\n\n".ljust(38) + "section_name: ".ljust(14) + str(section_name),end=' ')
                            if('virtual_size' in section):
                                virtual_size = section['virtual_size']
                                print(mycolors.reset + "\n".ljust(37) + "virtual_size: ".ljust(14) + str(virtual_size),end=' ')
                            if('entropy' in section):
                                entropy = section['entropy'] 
                                print(mycolors.reset + "\n".ljust(37) + "entropy: ".ljust(14) + str(entropy),end=' ')
                            if('flags' in section):
                                flags = section['flags'] 
                                print(mycolors.reset + "\n".ljust(37) + "flags: ".ljust(14) + str(flags),end=' ')
                if('androguard' in vttext['data']['attributes']):
                    print(mycolors.foreground.cyan + "\n\nAndroguard: ", end='')
                    if('Activities' in vttext['data']['attributes']['androguard']):
                        print(mycolors.foreground.red + "\n".ljust(22) + "Activities: ".ljust(23), end='')
                        for activity in vttext['data']['attributes']['androguard']['Activities']:
                            print(mycolors.reset + "\n".ljust(37) + activity,end='')
                    if('main_activity' in vttext['data']['attributes']['androguard']):
                        print(mycolors.foreground.red + "\n\n".ljust(23) + "MainActivity: ".ljust(15), end='')
                        mainactivity = vttext['data']['attributes']['androguard']['main_activity']
                        print(mycolors.reset + mainactivity,end='')
                    if('Package' in vttext['data']['attributes']['androguard']):
                        print(mycolors.foreground.red + "\n".ljust(22) + "Package: ".ljust(15), end='')
                        mainactivity = vttext['data']['attributes']['androguard']['Package']
                        print(mycolors.reset + mainactivity,end='\n')
                    if('Providers' in vttext['data']['attributes']['androguard']):
                        print(mycolors.foreground.red + "\n".ljust(22) + "Providers: ".ljust(23), end='')
                        for provider in vttext['data']['attributes']['androguard']['Providers']:
                            print(mycolors.reset + "\n".ljust(37) + provider,end='')
                    if('Receivers' in vttext['data']['attributes']['androguard']):
                        print(mycolors.foreground.red + "\n".ljust(22) + "Receivers: ".ljust(23), end='')
                        for receiver in vttext['data']['attributes']['androguard']['Receivers']:
                            print(mycolors.reset + "\n".ljust(37) + receiver,end='')
                    if('Libraries' in vttext['data']['attributes']['androguard']):
                        print(mycolors.foreground.red + "\n".ljust(22) + "Libraries: ".ljust(23), end='')
                        for library in vttext['data']['attributes']['androguard']['Libraries']:
                            print(mycolors.reset + "\n".ljust(37) + library,end='')
                    if('Services' in vttext['data']['attributes']['androguard']):
                        print(mycolors.foreground.red + "\n".ljust(22) + "Services: ".ljust(23), end='')
                        for service in vttext['data']['attributes']['androguard']['Services']:
                            print(mycolors.reset + "\n".ljust(37) + service,end='')
                    if('StringsInformation' in vttext['data']['attributes']['androguard']):
                        print(mycolors.foreground.red + "\n".ljust(22) + "StringsInfo: ".ljust(23), end='')
                        for string in vttext['data']['attributes']['androguard']['StringsInformation']:
                            print(mycolors.reset + "\n".ljust(37) + string,end='')
                    if('certificate' in vttext['data']['attributes']['androguard']):
                        print(mycolors.foreground.red + "\n".ljust(22) + "Certificate: ", end='')
                        if('Issuer' in vttext['data']['attributes']['androguard']['certificate']):
                            print(mycolors.foreground.blue + "\n".ljust(37) + "Issuer: ".ljust(15), end=' ')
                            if('DN' in vttext['data']['attributes']['androguard']['certificate']['Issuer']):
                                dn = vttext['data']['attributes']['androguard']['certificate']['Issuer']['DN']
                                print(mycolors.reset + "DN: " + dn,end='')
                        if('Subject' in vttext['data']['attributes']['androguard']['certificate']):
                            print(mycolors.foreground.blue + "\n".ljust(37) + "Subject: ".ljust(15), end=' ')
                            if('DN' in vttext['data']['attributes']['androguard']['certificate']['Subject']):
                                dn = vttext['data']['attributes']['androguard']['certificate']['Subject']['DN']
                                print(mycolors.reset + "DN: " + dn,end='')
                        if('serialnumber' in vttext['data']['attributes']['androguard']['certificate']):
                            print(mycolors.foreground.blue + "\n".ljust(37) + "SerialNumber: ".ljust(15), end=' ')
                            serialnumber = vttext['data']['attributes']['androguard']['certificate']['serialnumber']
                            print(mycolors.reset + serialnumber,end='')
                        if('validfrom' in vttext['data']['attributes']['androguard']['certificate']):
                            print(mycolors.foreground.blue + "\n".ljust(37) + "ValidFrom: ".ljust(15), end=' ')
                            validfrom = vttext['data']['attributes']['androguard']['certificate']['validfrom']
                            print(mycolors.reset + validfrom,end='')
                        if('validto' in vttext['data']['attributes']['androguard']['certificate']):
                            print(mycolors.foreground.blue + "\n".ljust(37) + "ValidTo: ".ljust(15), end=' ')
                            validto = vttext['data']['attributes']['androguard']['certificate']['validto']
                            print(mycolors.reset + validto,end='')
                        if('thumbprint' in vttext['data']['attributes']['androguard']['certificate']):
                            print(mycolors.foreground.blue + "\n".ljust(37) + "Thumbprint: ".ljust(15), end=' ')
                            thumbprint = vttext['data']['attributes']['androguard']['certificate']['thumbprint']
                            print(mycolors.reset + thumbprint,end='')
                    if('intent_filters' in vttext['data']['attributes']['androguard']):
                        print(mycolors.foreground.red + "\n".ljust(22) + "IntentFilters: ", end='')
                        if('Activities' in vttext['data']['attributes']['androguard']['intent_filters']):
                            print(mycolors.foreground.blue + "\n".ljust(37) + "Activities: ".ljust(15), end=' ')
                            for key, value in (vttext['data']['attributes']['androguard']['intent_filters']['Activities']).items():
                                print(mycolors.reset + "\n\n".ljust(54) + mycolors.foreground.purple + "name: ".ljust(11) + mycolors.reset + key,end='')
                                if('action' in value):
                                    for action_item in value['action']:
                                        print(mycolors.reset + "\n".ljust(53) + mycolors.foreground.cyan + "action: ".ljust(11) + mycolors.reset + action_item,end='')
                                if('category' in value):
                                    for category in value['category']:
                                        print(mycolors.reset + "\n".ljust(53) + mycolors.foreground.cyan + "category: ".ljust(11) + mycolors.reset + category,end='')
                        if('Receivers' in vttext['data']['attributes']['androguard']['intent_filters']):
                            print(mycolors.foreground.blue + "\n".ljust(37) + "Receivers: ".ljust(15), end=' ')
                            for key, value in (vttext['data']['attributes']['androguard']['intent_filters']['Receivers']).items():
                                print(mycolors.reset + "\n\n".ljust(54) + mycolors.foreground.purple + "name: ".ljust(11) + mycolors.reset + key,end='')
                                if('action' in value):
                                    for action_item in value['action']:
                                        print(mycolors.reset + "\n".ljust(53) + mycolors.foreground.cyan + "action: ".ljust(11) + mycolors.reset + action_item,end='')
                                if('category' in value):
                                    for category in value['category']:
                                        print(mycolors.reset + "\n".ljust(53) + mycolors.foreground.cyan + "category: ".ljust(11) + mycolors.reset + category,end='')
                        if('Services' in vttext['data']['attributes']['androguard']['intent_filters']):
                            print(mycolors.foreground.blue + "\n".ljust(37) + "Services: ".ljust(15), end=' ')
                            for key, value in (vttext['data']['attributes']['androguard']['intent_filters']['Services']).items():
                                print(mycolors.reset + "\n\n".ljust(54) + mycolors.foreground.purple + "name: ".ljust(11) + mycolors.reset + key,end='')
                                if('action' in value):
                                    for action_item in value['action']:
                                        print(mycolors.reset + "\n".ljust(53) + mycolors.foreground.cyan + "action: ".ljust(11) + mycolors.reset + action_item,end='')
                                if('category' in value):
                                    for category in value['category']:
                                        print(mycolors.reset + "\n".ljust(53) + mycolors.foreground.cyan + "category: ".ljust(11) + mycolors.reset + category,end='')
                    if('permission_details' in vttext['data']['attributes']['androguard']):
                        print(mycolors.foreground.red + "\n".ljust(22) + "Permissions: ", end='')
                        for key, value in (vttext['data']['attributes']['androguard']['permission_details']).items():
                            print(mycolors.reset + "\n\n".ljust(54) + mycolors.foreground.purple + "name: ".ljust(11) + mycolors.reset + key,end='')
                            if('full_description' in value):
                                print(mycolors.reset + ("\n".ljust(53) + mycolors.foreground.cyan + "details: ".ljust(11) + mycolors.reset + (mycolors.reset + "\n".ljust(64)).join(textwrap.wrap(" ".join(value['full_description'].split()),width=80))),end=' ')
                            if('permission_type' in value):
                                print(mycolors.reset + "\n".ljust(53) + mycolors.foreground.cyan + "type: ".ljust(11) + mycolors.reset + value['permission_type'],end='')
                            if('short_description' in value):
                                print(mycolors.reset + ("\n".ljust(53) + mycolors.foreground.cyan + "info: ".ljust(11) + mycolors.reset + ("\n" + mycolors.reset + "".ljust(63)).join(textwrap.wrap(value['short_description'],width=80))),end=' ')

                print("\n")

                if(showreport == 1):
                    vtreportwork(myhash, url, 0)


    except ValueError as e:
        if(bkg == 1):
            print((mycolors.foreground.lightred + "Error while connecting to Virus Total!\n"))
        else:
            print((mycolors.foreground.red + "Error while connecting to Virus Total!\n"))
        print(mycolors.reset)
        exit(3)


def vtlargefile(file_item, url):

    try:

        finalurl = ''.join([url, "/upload_url" ])
        requestsession = requests.Session( )
        requestsession.headers.update({'x-apikey': VTAPI})
        requestsession.headers.update({'content-type': 'application/json'})
        response = requestsession.get(finalurl)
        vttext = json.loads(response.text)

        if (response.status_code == 404):
            if (bkg == 1):
                print(mycolors.foreground.yellow + "\tThere was an issue while getting a URL for uploading the file.")
            if (bkg == 0):
                print(mycolors.foreground.blue + "\tThere was an issue while getting a URL for uploading the file.")
        else:
            if (bkg == 1):
                print(mycolors.foreground.yellow + "\n\tUploading file...")
                vtuploadfile(file_item, vttext['data'])
            if (bkg == 0):
                print(mycolors.foreground.blue + "\n\tUploading file...")
                vtuploadfile(file_item, vttext['data'])

    except ValueError as e:
        if(bkg == 1):
            print((mycolors.foreground.lightred + "Error while connecting to Virus Total!\n"))
        else:
            print((mycolors.foreground.red + "Error while connecting to Virus Total!\n"))
        print(mycolors.reset)
        exit(3)


def vtbatchwork(myhash, url):
    
    type_description = 'NOT FOUND'
    threat_label = 'NOT FOUND'
    malicious = 'NOT FOUND'

    try:

        finalurl = ''.join([url, "/", myhash ])
        requestsession = requests.Session( )
        requestsession.headers.update({'x-apikey': VTAPI})
        requestsession.headers.update({'content-type': 'application/json'})
        response = requestsession.get(finalurl)
        vttext = json.loads(response.text)

        if (response.status_code == 404):
            return (type_description, threat_label, malicious)
        else:
            if('type_description' in vttext['data']['attributes']):
                type_description = vttext['data']['attributes']['type_description']
            else:
                type_description = 'NO DESCRIPTION'
            if('popular_threat_classification' in vttext['data']['attributes']):
                if('suggested_threat_label' in vttext['data']['attributes']['popular_threat_classification']):
                    threat_label = vttext['data']['attributes']['popular_threat_classification']['suggested_threat_label']
            else:
                threat_label = 'NO GIVEN NAME'
            if('last_analysis_stats' in vttext['data']['attributes']):
                if('malicious' in vttext['data']['attributes']['last_analysis_stats']):
                    malicious = vttext['data']['attributes']['last_analysis_stats']['malicious']
            else:
                malicious = 'NOT FOUND'

            return (type_description, threat_label, malicious)

    except ValueError as e:
        if(bkg == 1):
            print((mycolors.foreground.lightred + "Error while connecting to Virus Total!\n"))
        else:
            print((mycolors.foreground.red + "Error while connecting to Virus Total!\n"))
        print(mycolors.reset)
        exit(3)


def vtbatchcheck(filename, url, apitype):

    type_description = ''
    threat_label = ''
    malicious = ''
    apitype_var = apitype

    try:

        print("\nSample".center(10) + "Hash".center(68) + "Description".center(30) + "Threat Label".center(26) + "AV Detection".center(24))
        print('-' * 152, end="\n\n")

        fh = open(filename,'r')
        filelines = fh.readlines()

        hashnumber = 0
        for hashitem in filelines:
            hashnumber = hashnumber + 1
            (type_description, threat_label, malicious) = vtbatchwork(hashitem,url)
            if (type_description == "NOT FOUND"):
                if (bkg == 1):
                    print(mycolors.foreground.lightcyan + "hash_" + str(hashnumber) + "\t   " +  mycolors.reset + (hashitem.strip()).ljust(79) + mycolors.foreground.yellow + (type_description).ljust(28) + mycolors.foreground.lightcyan + (threat_label).ljust(26) +  mycolors.foreground.lightred + str(malicious))
                if (bkg == 0):
                    print(mycolors.foreground.purple + "hash_" + str(hashnumber) + "\t   " +  mycolors.reset + (hashitem.strip()).ljust(79) + mycolors.foreground.cyan + (type_description).ljust(28) + mycolors.foreground.blue + (threat_label).ljust(26) +  mycolors.foreground.red + str(malicious))
                if (apitype_var == 1):
                    if ((hashnumber % 4) == 0):
                        time.sleep(61)
            else:
                if (bkg == 1):
                    print(mycolors.foreground.lightcyan + "hash_" + str(hashnumber) + "\t   " +  mycolors.reset + (hashitem.strip()).ljust(68) + mycolors.foreground.yellow + (type_description).ljust(30) + mycolors.foreground.lightcyan + (threat_label).ljust(34) +  mycolors.foreground.lightred + str(malicious))
                if (bkg == 0):
                    print(mycolors.foreground.purple + "hash_" + str(hashnumber) + "\t   " +  mycolors.reset + (hashitem.strip()).ljust(68) + mycolors.foreground.cyan + (type_description).ljust(30) + mycolors.foreground.blue + (threat_label).ljust(34) +  mycolors.foreground.red + str(malicious))
                if (apitype_var == 1):
                    if ((hashnumber % 4) == 0):
                        time.sleep(61)

        fh.close()

    except OSError:
        if(bkg == 1):
            print((mycolors.foreground.lightred + "The provided file doesn't exist!\n"))
        else:
            print((mycolors.foreground.red + "The provided file doesn't exist!\n"))
        print(mycolors.reset)
        exit(3)


def vtbehavior(myhash, url):

    try:

        finalurl = ''.join([url, "/", myhash, "/behaviour_summary" ])
        requestsession = requests.Session( )
        requestsession.headers.update({'x-apikey': VTAPI})
        requestsession.headers.update({'content-type': 'application/json'})
        response = requestsession.get(finalurl)
        vttext = json.loads(response.text)

        if (response.status_code == 404):
            if (bkg == 1):
                print(mycolors.foreground.yellow + "\tReport not found for the provided hash!")
            if (bkg == 0):
                print(mycolors.foreground.blue + "\tReport not found for the provided hash!")
        else:
            if(bkg == 1):
                finalhash = myhash
                print(mycolors.foreground.lightred + "\nProvided Hash: ".ljust(24) + mycolors.reset + finalhash)
                if('verdicts' in vttext['data']):
                    print(mycolors.foreground.yellow + "Verdicts: ".ljust(22) + mycolors.reset, end=' ')
                    for verdict in vttext['data']['verdicts']:
                        print(mycolors.reset + (verdict),end=' | ')
                if('verdict_confidence' in vttext['data']):
                    print(mycolors.foreground.yellow + "\nVerdict Confidence: ".ljust(24) + mycolors.reset + str(vttext['data']['verdict_confidence']) + mycolors.reset, end=' ')
                if('verdict_labels' in vttext['data']):
                    print(mycolors.foreground.yellow + "\nVerdict Labels: ".ljust(23) + mycolors.reset, end=' ')
                    for label in vttext['data']['verdict_labels']:
                        print(mycolors.reset + (label),end=' ')
                if('processes_injected' in vttext['data']):
                    print(mycolors.foreground.lightred + "\n\nProcesses Injected: ", end='')
                    for injected in vttext['data']['processes_injected']:
                        print(mycolors.reset + ("\n".ljust(24) + ("\n" + "".ljust(24)).join(textwrap.wrap(injected,width=120))),end=' ')
                if('calls_highlighted' in vttext['data']):
                    print(mycolors.foreground.lightred + "\n\nCalls Highlighted: ", end='')
                    for calls in vttext['data']['calls_highlighted']:
                        print(mycolors.reset + ("\n".ljust(24) + ("\n" + "".ljust(24)).join(textwrap.wrap(calls,width=120))),end=' ')
                if('processes_tree' in vttext['data']):
                    print(mycolors.foreground.lightcyan + "\n\nProcesses Tree: ", end='')
                    for process in vttext['data']['processes_tree']:
                        print("\n")
                        print(mycolors.reset + " ".ljust(23) + "process_id: ".ljust(15) + process['process_id'],end='')
                        print(mycolors.reset + ("\n".ljust(24) + "process_name: ".ljust(15) + mycolors.reset + (mycolors.reset + "\n".ljust(39)).join(textwrap.wrap(" ".join(process['name'].split()),width=80))),end=' ')
                        if('children' in process):
                            print(mycolors.reset + "\n".ljust(24) + "children: ".ljust(15),end='')
                            for child in process['children']:
                                print(mycolors.reset + "\n".ljust(28) + "process_id: ".ljust(15) + child['process_id'],end='')
                                print(mycolors.reset + ("\n".ljust(28) + "process_name: ".ljust(15) + mycolors.reset + (mycolors.reset + "\n".ljust(43)).join(textwrap.wrap(" ".join(child['name'].split()),width=80))),end=' ')
                if('processes_terminated' in vttext['data']):
                    print(mycolors.foreground.lightcyan + "\n\nProcesses Terminated: ", end='\n')
                    for process_term in vttext['data']['processes_terminated']:
                        print(mycolors.reset + "".ljust(23) + process_term,end='\n')
                if('processes_killed' in vttext['data']):
                    print(mycolors.foreground.lightcyan + "\n\nProcesses Killed: ", end='\n')
                    for process_kill in vttext['data']['processes_killed']:
                        print(mycolors.reset + "".ljust(23) + process_kill,end='\n')
                if('services_created' in vttext['data']):
                    print(mycolors.foreground.lightred + "\n\nServices Created: ", end='\n')
                    for services_created in vttext['data']['services_created']:
                        print(mycolors.reset + "".ljust(23) + services_created,end='\n')
                if('services_deleted' in vttext['data']):
                    print(mycolors.foreground.lightred + "\n\nServices Deleted: ", end='\n')
                    for services_deleted in vttext['data']['services_deleted']:
                        print(mycolors.reset + "".ljust(23) + services_deleted,end='\n')
                if('services_started' in vttext['data']):
                    print(mycolors.foreground.lightred + "\n\nServices Started: ", end='\n')
                    for services_started in vttext['data']['services_started']:
                        print(mycolors.reset + "".ljust(23) + services_started,end='\n')
                if('services_stopped' in vttext['data']):
                    print(mycolors.foreground.lightred + "\n\nServices Stopped: ", end='\n')
                    for services_stopped in vttext['data']['services_stopped']:
                        print(mycolors.reset + "".ljust(23) + services_stopped,end='\n')
                if('dns_lookups' in vttext['data']):
                    print(mycolors.foreground.yellow + "\nDNS Lookups: ", end='')
                    for lookup in vttext['data']['dns_lookups']:
                        if('resolved_ips' in lookup):
                            print(mycolors.reset + "\n".ljust(24) + "resolved_ips: ",end='')
                            for ip in (lookup['resolved_ips']):
                                print(ip,end=' | ')
                        if('hostname' in lookup):
                            print(mycolors.reset + "\n".ljust(24) + "hostname: ".ljust(14) + lookup['hostname'],end='\n')
                if('ja3_digests' in vttext['data']):
                    print(mycolors.foreground.yellow + "\n\nJA3 Digests: ", end='\n')
                    for ja3 in vttext['data']['ja3_digests']:
                        print(mycolors.reset + "".ljust(23) + ja3,end='\n')
                if('modules_loaded' in vttext['data']):
                    print(mycolors.foreground.yellow + "\nModules Loaded: ", end='')
                    for module in vttext['data']['modules_loaded']:
                        print(mycolors.reset + ("\n".ljust(24) + ("\n" + "".ljust(24)).join(textwrap.wrap(module,width=120))),end=' ')
                if('registry_keys_opened' in vttext['data']):
                    print(mycolors.foreground.yellow + "\n\nRegistry Keys Opened: ", end='')
                    for key in vttext['data']['registry_keys_opened']:
                        print(mycolors.reset + ("\n".ljust(24) + ("\n" + "".ljust(24)).join(textwrap.wrap(key,width=120))),end=' ')
                if('files_opened' in vttext['data']):
                    print(mycolors.foreground.lightcyan + "\n\nFiles Opened: ", end='')
                    for filename in vttext['data']['files_opened']:
                        print(mycolors.reset + ("\n".ljust(24) + ("\n" + "".ljust(24)).join(textwrap.wrap(filename,width=120))),end=' ')
                if('files_written' in vttext['data']):
                    print(mycolors.foreground.lightcyan + "\n\nFiles Written: ", end='')
                    for filewritten in vttext['data']['files_written']:
                        print(mycolors.reset + ("\n".ljust(24) + ("\n" + "".ljust(24)).join(textwrap.wrap(filewritten,width=120))),end=' ')
                if('files_deleted' in vttext['data']):
                    print(mycolors.foreground.lightcyan + "\n\nFiles Deleted: ", end='')
                    for filedeleted in vttext['data']['files_deleted']:
                        print(mycolors.reset + ("\n".ljust(24) + ("\n" + "".ljust(24)).join(textwrap.wrap(filedeleted,width=120))),end=' ')
                if('command_executions' in vttext['data']):
                    print(mycolors.foreground.yellow + "\n\nCommand Executions: ", end='')
                    for command in vttext['data']['command_executions']:
                        print(mycolors.reset + ("\n".ljust(24) + ("\n" + "".ljust(24)).join(textwrap.wrap(command,width=120))),end=' ')
                if('mutexes_created' in vttext['data']):
                    print(mycolors.foreground.yellow + "\n\nMutex Created: ", end='')
                    for mutex in vttext['data']['mutexes_created']:
                        print(mycolors.reset + ("\n".ljust(24) + ("\n" + "".ljust(24)).join(textwrap.wrap(mutex,width=120))),end=' ')
                if('windows_hidden' in vttext['data']):
                    print(mycolors.foreground.yellow + "\n\nWindows Hidden: ", end='\n')
                    for windows_hidden in vttext['data']['windows_hidden']:
                        print(mycolors.reset + "".ljust(23) + windows_hidden,end='\n')

            if(bkg == 0):
                finalhash = myhash
                print(mycolors.foreground.red + "\nProvided Hash: ".ljust(24) + mycolors.reset + finalhash)
                if('verdicts' in vttext['data']):
                    print(mycolors.foreground.purple + "Verdicts: ".ljust(22) + mycolors.reset, end=' ')
                    for verdict in vttext['data']['verdicts']:
                        print(mycolors.reset + (verdict),end=' | ')
                if('verdict_confidence' in vttext['data']):
                    print(mycolors.foreground.purple + "\nVerdict Confidence: ".ljust(24) + mycolors.reset + str(vttext['data']['verdict_confidence']) + mycolors.reset, end=' ')
                if('verdict_labels' in vttext['data']):
                    print(mycolors.foreground.purple + "\nVerdict Labels: ".ljust(23) + mycolors.reset, end=' ')
                    for label in vttext['data']['verdict_labels']:
                        print(mycolors.reset + (label),end=' ')
                if('processes_injected' in vttext['data']):
                    print(mycolors.foreground.red + "\n\nProcesses Injected: ", end='')
                    for injected in vttext['data']['processes_injected']:
                        print(mycolors.reset + ("\n".ljust(24) + ("\n" + "".ljust(24)).join(textwrap.wrap(injected,width=120))),end=' ')
                if('calls_highlighted' in vttext['data']):
                    print(mycolors.foreground.red + "\n\nCalls Highlighted: ", end='')
                    for calls in vttext['data']['calls_highlighted']:
                        print(mycolors.reset + ("\n".ljust(24) + ("\n" + "".ljust(24)).join(textwrap.wrap(calls,width=120))),end=' ')
                if('processes_tree' in vttext['data']):
                    print(mycolors.foreground.blue + "\n\nProcesses Tree: ", end='')
                    for process in vttext['data']['processes_tree']:
                        print("\n")
                        print(mycolors.reset + " ".ljust(23) + "process_id: ".ljust(15) + process['process_id'],end='')
                        print(mycolors.reset + ("\n".ljust(24) + "process_name: ".ljust(15) + mycolors.reset + (mycolors.reset + "\n".ljust(39)).join(textwrap.wrap(" ".join(process['name'].split()),width=80))),end=' ')
                        if('children' in process):
                            print(mycolors.reset + "\n".ljust(24) + "children: ".ljust(15),end='')
                            for child in process['children']:
                                print(mycolors.reset + "\n".ljust(28) + "process_id: ".ljust(15) + child['process_id'],end='')
                                print(mycolors.reset + ("\n".ljust(28) + "process_name: ".ljust(15) + mycolors.reset + (mycolors.reset + "\n".ljust(43)).join(textwrap.wrap(" ".join(child['name'].split()),width=80))),end=' ')
                if('processes_terminated' in vttext['data']):
                    print(mycolors.foreground.blue + "\n\nProcesses Terminated: ", end='\n')
                    for process_term in vttext['data']['processes_terminated']:
                        print(mycolors.reset + "".ljust(23) + process_term,end='\n')
                if('processes_killed' in vttext['data']):
                    print(mycolors.foreground.blue + "\n\nProcesses Killed: ", end='\n')
                    for process_kill in vttext['data']['processes_killed']:
                        print(mycolors.reset + "".ljust(23) + process_kill,end='\n')
                if('services_created' in vttext['data']):
                    print(mycolors.foreground.blue + "\n\nServices Created: ", end='\n')
                    for services_created in vttext['data']['services_created']:
                        print(mycolors.reset + "".ljust(23) + services_created,end='\n')
                if('services_deleted' in vttext['data']):
                    print(mycolors.foreground.blue + "\n\nServices Deleted: ", end='\n')
                    for services_deleted in vttext['data']['services_deleted']:
                        print(mycolors.reset + "".ljust(23) + services_deleted,end='\n')
                if('services_started' in vttext['data']):
                    print(mycolors.foreground.blue + "\n\nServices Started: ", end='\n')
                    for services_started in vttext['data']['services_started']:
                        print(mycolors.reset + "".ljust(23) + services_started,end='\n')
                if('services_stopped' in vttext['data']):
                    print(mycolors.foreground.blue + "\n\nServices Stopped: ", end='\n')
                    for services_stopped in vttext['data']['services_stopped']:
                        print(mycolors.reset + "".ljust(23) + services_stopped,end='\n')
                if('dns_lookups' in vttext['data']):
                    print(mycolors.foreground.blue + "\nDNS Lookups: ", end='')
                    for lookup in vttext['data']['dns_lookups']:
                        if('resolved_ips' in lookup):
                            print(mycolors.reset + "\n".ljust(24) + "resolved_ips: ",end='')
                            for ip in (lookup['resolved_ips']):
                                print(ip,end=' | ')
                        if('hostname' in lookup):
                            print(mycolors.reset + "\n".ljust(24) + "hostname: ".ljust(14) + lookup['hostname'],end='\n')
                if('ja3_digests' in vttext['data']):
                    print(mycolors.foreground.blue + "\n\nJA3 Digests: ", end='\n')
                    for ja3 in vttext['data']['ja3_digests']:
                        print(mycolors.reset + "".ljust(23) + ja3,end='\n')
                if('modules_loaded' in vttext['data']):
                    print(mycolors.foreground.blue + "\nModules Loaded: ", end='')
                    for module in vttext['data']['modules_loaded']:
                        print(mycolors.reset + ("\n".ljust(24) + ("\n" + "".ljust(24)).join(textwrap.wrap(module,width=120))),end=' ')
                if('registry_keys_opened' in vttext['data']):
                    print(mycolors.foreground.blue + "\n\nRegistry Keys Opened: ", end='')
                    for key in vttext['data']['registry_keys_opened']:
                        print(mycolors.reset + ("\n".ljust(24) + ("\n" + "".ljust(24)).join(textwrap.wrap(key,width=120))),end=' ')
                if('files_opened' in vttext['data']):
                    print(mycolors.foreground.blue + "\n\nFiles Opened: ", end='')
                    for filename in vttext['data']['files_opened']:
                        print(mycolors.reset + ("\n".ljust(24) + ("\n" + "".ljust(24)).join(textwrap.wrap(filename,width=120))),end=' ')
                if('files_written' in vttext['data']):
                    print(mycolors.foreground.blue + "\n\nFiles Written: ", end='')
                    for filewritten in vttext['data']['files_written']:
                        print(mycolors.reset + ("\n".ljust(24) + ("\n" + "".ljust(24)).join(textwrap.wrap(filewritten,width=120))),end=' ')
                if('files_deleted' in vttext['data']):
                    print(mycolors.foreground.blue + "\n\nFiles Deleted: ", end='')
                    for filedeleted in vttext['data']['files_deleted']:
                        print(mycolors.reset + ("\n".ljust(24) + ("\n" + "".ljust(24)).join(textwrap.wrap(filedeleted,width=120))),end=' ')
                if('command_executions' in vttext['data']):
                    print(mycolors.foreground.purple + "\n\nCommand Executions: ", end='')
                    for command in vttext['data']['command_executions']:
                        print(mycolors.reset + ("\n".ljust(24) + ("\n" + "".ljust(24)).join(textwrap.wrap(command,width=120))),end=' ')
                if('mutexes_created' in vttext['data']):
                    print(mycolors.foreground.purple + "\n\nMutex Created: ", end='')
                    for mutex in vttext['data']['mutexes_created']:
                        print(mycolors.reset + ("\n".ljust(24) + ("\n" + "".ljust(24)).join(textwrap.wrap(mutex,width=120))),end=' ')
                if('windows_hidden' in vttext['data']):
                    print(mycolors.foreground.purple + "\n\nWindows Hidden: ", end='\n')
                    for windows_hidden in vttext['data']['windows_hidden']:
                        print(mycolors.reset + "".ljust(23) + windows_hidden,end='\n')

    except ValueError as e:
        if(bkg == 1):
            print((mycolors.foreground.lightred + "Error while connecting to Virus Total!\n"))
        else:
            print((mycolors.foreground.red + "Error while connecting to Virus Total!\n"))
        print(mycolors.reset)
        exit(3)


def vtdirchecking(repo2, url, apitype):

    type_description = ''
    threat_label = ''
    malicious = ''
    apitype_var = apitype

    directory = repo2
    if os.path.isabs(directory) == False:
        directory = os.path.abspath('.') + "/" + directory
    os.chdir(directory)

    try:
        
        for filen in os.listdir(directory):
            try:
                filename = str(filen)
                if(os.path.isdir(filename) == True):
                    continue
                targetfile = ftype(filename)
                F.append(filename)
                H.append(sha256hash(filename))

            except (AttributeError, NameError) as e:
                if (bkg == 1):
                    print(mycolors.foreground.lightred + "\An error has occured while reading the %s file." % filename)
                else:
                    print(mycolors.foreground.red + "\nAn error has occured while reading the %s file." % filename)
                print(mycolors.reset)

        file_hash_dict = dict(list(zip(F,H)))

        print("\nSample".center(10) + "Filename".center(72) + "Description".center(26) + "Threat Label".center(28) + "AV Detection".center(26))
        print('-' * 154, end="\n\n")

        hashnumber = 0

        for key,value in file_hash_dict.items(): 
            hashnumber = hashnumber + 1
            (type_description, threat_label, malicious) = vtbatchwork(value,url)
            if (bkg == 1):
                print(mycolors.foreground.lightcyan + "file_" + str(hashnumber) + "\t   " +  mycolors.reset + (key.strip()).ljust(71) + mycolors.foreground.yellow + (type_description).ljust(30) + mycolors.foreground.lightcyan + (threat_label).ljust(34) +  mycolors.foreground.lightred + str(malicious))
            if (bkg == 0):
                print(mycolors.foreground.blue + "file_" + str(hashnumber) + "\t   " +  mycolors.reset + (key.strip()).ljust(71) + mycolors.foreground.cyan + (type_description).ljust(30) + mycolors.foreground.blue + (threat_label).ljust(34) +  mycolors.foreground.red + str(malicious))
            if (apitype_var == 1):
                if ((hashnumber % 4) == 0):
                    time.sleep(61)

    except OSError:
        if(bkg == 1):
            print((mycolors.foreground.lightred + "The provided file doesn't exist!\n"))
        else:
            print((mycolors.foreground.red + "The provided file doesn't exist!\n"))
        print(mycolors.reset)
        exit(3)


def hashow(filehash):

    hatext = ''
    haresponse = ''
    final = ''

    requestHAAPI()

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
        if 'Failed' in rc:
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
            print((mycolors.foreground.lightcyan))
        else:
            print((mycolors.foreground.purple))

        print("\nCertificates:\n", end='\n')
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
            print(mycolors.foreground.lightcyan)
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

    requestPOLYAPI()
    polyswarm = PolyswarmAPI(key=POLYAPI)

    if (metainfo == 4):
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

        if (metainfo == 4):
            metaresults = polyswarm.search_by_metadata("pefile.imphash:" + fimph)
            for x in metaresults:
                if (bkg == 1):
                    if(x.sha256):
                        print(mycolors.reset + "\nSHA256: " +  mycolors.foreground.lightred + "%s" % x.sha256, end=' ') 
                    else:
                        print(mycolors.reset + "\nSHA256: " +  mycolors.foreground.lightred + "%s" + "None", end=' ') 
                    if(x.md5):
                        print(mycolors.reset + "MD5: " + mycolors.foreground.lightcyan + "%s" % x.md5, end=' ')
                    else:
                        print(mycolors.reset + "MD5: " + mycolors.foreground.lightcyan + "%s" + "None", end=' ')
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

        if (metainfo == 5):
            metaresults = polyswarm.search_by_metadata("strings.ipv4:" + poly)
        if (metainfo == 6):
            metaresults = polyswarm.search_by_metadata("strings.domains:" + poly)
        if (metainfo == 7):
            poly = (r'"' + poly + r'"')
            metaresults = polyswarm.search_by_metadata("strings.urls:" + poly)
        if (metainfo == 8):
            poly = ('scan.latest_scan.\*.metadata.malware_family:' + poly)
            metaresults = polyswarm.search_by_metadata(poly)
        for y in metaresults:
            if (bkg == 1):
                if (y.sha256):
                    print(mycolors.reset + "\nSHA256: " +  mycolors.foreground.lightcyan + "%s" % y.sha256, end=' ') 
                else:
                    print(mycolors.reset + "Result: " + mycolors.foreground.yellow + "Sample not found!", end=' ')
                    exit(0)
                score = next(polyswarm.search(y.sha256))
                print(mycolors.reset + "Polyscore: " +  mycolors.foreground.yellow + "%20s" % score.polyscore, end=' ') 
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
                print(mycolors.reset + "Polyscore: " +  mycolors.foreground.red + "%20s" % score.polyscore, end=' ') 
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

    requestPOLYAPI()
    polyswarm = PolyswarmAPI(key=POLYAPI)

    try:
    
        myhash = sha256hash(poly)
        instance = polyswarm.submit(poly)
        result = polyswarm.wait_for(instance)
        print(mycolors.reset)
        print("POLYSWARM.NETWORK RESULTS")
        print('-' * 25, end="\n\n")
        for assertion in result.assertions:
            if (bkg == 1):
                print(mycolors.reset + "Engine: " + mycolors.foreground.lightcyan + "%-25s" % assertion.author_name, end='')
                print(mycolors.reset + "\tVerdict:" + mycolors.foreground.lightred + " ", "Malicious" if assertion.verdict else "Clean")
            else:
                print(mycolors.reset + "Engine: " + mycolors.foreground.green + "%-25s" % assertion.author_name, end='')
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
                print(mycolors.foreground.lightred + "\nSHA256: \t%s" % sha256)
            if(filetype):
                print(mycolors.foreground.lightred + "File Type: \t%s" % filetype)
            if(extended):
                print(mycolors.foreground.lightred + "Extended Info: \t%s" % extended)
            if(firstseen):
                print(mycolors.foreground.lightred + "First seen: \t%s" % firstseen)
            if (score is not None):
                print(mycolors.foreground.yellow + "\nPolyscore: \t%f" % score)
        else:
            if(sha256):
                print(mycolors.foreground.cyan + "\nSHA256: \t%s" % sha256)
            if(filetype):
                print(mycolors.foreground.cyan + "File Type: \t%s" % filetype)
            if(extended):
                print(mycolors.foreground.cyan + "Extended Info: \t%s" % extended)
            if(firstseen):
                print(mycolors.foreground.cyan + "First seen: \t%s" % firstseen)
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

def polyhashsearch(poly, download):


    sha256 = '' 
    filetype = ''
    extended = ''
    firstseen = ''
    score = 0
    down = download
    DOWN_DIR = '.'

    requestPOLYAPI()
    polyswarm = PolyswarmAPI(key=POLYAPI)

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
                    print(mycolors.foreground.lightcyan + "%s" % i)
                else:
                    print(mycolors.foreground.green + "%s" % i)

        if (bkg == 1):
            if(sha256):
                print(mycolors.foreground.lightred + "\nSHA256: \t%s" % sha256)
            if(filetype):
                print(mycolors.foreground.lightred + "File Type: \t%s" % filetype)
            if(extended):
                print(mycolors.foreground.lightred + "Extended Info: \t%s" % extended)
            if(firstseen):
                print(mycolors.foreground.lightred + "First seen: \t%s" % firstseen)
            if (score is not None):
                print(mycolors.foreground.yellow + "\nPolyscore: \t%f" % score)
            if (down == 1):
                artifact = polyswarm.download(DOWN_DIR, sha256)
                print(mycolors.reset + "\n\nThe sample has been SAVED!")
        else:
            if(sha256):
                print(mycolors.foreground.cyan + "\nSHA256: \t%s" % sha256)
            if(filetype):
                print(mycolors.foreground.cyan + "File Type: \t%s" % filetype)
            if(extended):
                print(mycolors.foreground.cyan + "Extended Info: \t%s" % extended)
            if(firstseen):
                print(mycolors.foreground.cyan + "First seen: \t%s" % firstseen)
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

    requestHAAPI()

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


def downhash(filehash):

    hatext = ''
    haresponse = ''
    final = ''

    requestHAAPI()

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
        print((mycolors.foreground.yellow + "\n\nOverlay extracted:   " + mycolors.reset + "%s.overlay"  % fname))
    else:
        print((mycolors.foreground.green + "\n\nOverlay extracted:   " + mycolors.reset + "%s.overlay"  % fname))
    print(mycolors.reset)


def keysort(item):
    return item[1]


def calchash(ffpname2):
    targetfile = ffpname2
    mysha256hash=''
    dname = str(os.path.dirname(targetfile))
    if os.path.abspath(dname) == False:
        dname = os.path.abspath('.') + "/" + dname
    fname = os.path.basename(targetfile)

    print(mycolors.reset, end=' ')

    try:

        mysha256hash = sha256hash(targetfile)
        return mysha256hash

    except:
        if (bkg == 1):
            print((mycolors.foreground.lightred + "Error while calculing the hash!\n"))
        else:
            print((mycolors.foreground.red + "Error while calculating the hash\n"))
        print(mycolors.reset)

def isoverlay(file_item):

    mype2 = pefile.PE(file_item)
    over = mype2.get_overlay_data_start_offset()
    if over == None:
        ovr =  "NO"
    else:
        ovr =  "YES"
    return ovr


def filechecking_v3(ffpname2, url, showreport, impexp, ovrly):

    targetfile = ffpname2
    mysha256hash=''
    dname = str(os.path.dirname(targetfile))
    if os.path.abspath(dname) == False:
        dname = os.path.abspath('.') + "/" + dname
    fname = os.path.basename(targetfile)

    try:
        mysha256hash = sha256hash(targetfile)

        magictype = ftype(targetfile)
        if re.match(r'^PE[0-9]{2}|^MS-DOS', magictype):
            ret_overlay = isoverlay(targetfile) 

        if(showreport == 0):
            vthashwork(mysha256hash, url, showreport)

            if re.match(r'^PE[0-9]{2}|^MS-DOS', magictype):
                if(bkg == 1):
                    print(mycolors.foreground.lightred + "Overlay: ".ljust(21) + mycolors.reset + ret_overlay, end='\n')
            if re.match(r'^PE[0-9]{2}|^MS-DOS', magictype):
                if(bkg == 0):
                    print(mycolors.foreground.red + "Overlay: ".ljust(21) + mycolors.reset + ret_overlay, end='\n')
        else:
            vtreportwork(mysha256hash, url, 1)

            if re.match(r'^PE[0-9]{2}|^MS-DOS', magictype):
                if(bkg == 1):
                    print(mycolors.foreground.lightred + "Overlay: ".ljust(21) + mycolors.reset + ret_overlay, end='\n')
            if re.match(r'^PE[0-9]{2}|^MS-DOS', magictype):
                if(bkg == 0):
                    print(mycolors.foreground.red + "Overlay: ".ljust(21) + mycolors.reset + ret_overlay, end='\n')

        if (impexp == 1):
            list_imports_exports(targetfile)
        
        if (ovrly == 1):
                overextract(targetfile)

    except (AttributeError, NameError) as e:
        print(e)
        if (bkg == 1):
            print((mycolors.foreground.yellow + "\nAn error has occured while handling the %s file.\n" % targetfile))
            pass
        else:
            print((mycolors.foreground.red + "\nAn error has occured while handling the %s file.\n" % targetfile))
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

    requestHAAPI()

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


class quickHAThread(threading.Thread):

    def __init__(self, key):

        threading.Thread.__init__(self)
        self.key = key

    def run(self):

        key1 = self.key

        myhashdir = sha256hash(key1)
        (final, verdict, avdetect, totalsignatures, threatscore, totalprocesses, networkconnections) =  quickhashow(myhashdir)

        if (bkg == 1):
            print((mycolors.foreground.yellow + "%-70s" % key1), end=' ')
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
            print((mycolors.foreground.lightcyan + "%6s" % totalprocesses), end='')
            print((mycolors.foreground.lightcyan + "%6s" % networkconnections + mycolors.reset))
        else:
            print((mycolors.foreground.cyan + "%-70s" % key1), end=' ')
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


def malsharedown(filehash):

    maltext3 = ''
    malresponse3 = ''
    resource = ''

    requestMALSHAREAPI()

    try:

        resource = filehash
        requestsession3 = requests.Session( )
        finalurl3 = ''.join([urlmalshare, MALSHAREAPI, '&action=getfile&hash=', resource])
        malresponse3 = requestsession3.get(url=finalurl3, allow_redirects=True)
        if (b'Sample not found by hash' in malresponse3.content):
            if(bkg == 1):
                print((mycolors.foreground.lightred + "\nSample not found by the provided hash.\n"))
            else:
                print((mycolors.foreground.red + "\nSample not found by the provided hash.\n"))
            print(mycolors.reset)
            exit(1)

        open(resource, 'wb').write(malresponse3.content)

        print("\n")
        print((mycolors.reset + "MALWARE SAMPLE SAVED! "))
        print((mycolors.reset))

    except (BrokenPipeError, IOError):
        print(mycolors.reset , file=sys.stderr)
        exit(2)

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

    requestMALSHAREAPI()

    if (maltype == 2):
        filetype = 'PE32'
    elif (maltype == 3):
        filetype = 'ELF'
    elif (maltype == 4):
        filetype = 'Java'
    elif (maltype == 5):
        filetype = 'PDF'
    elif (maltype == 5):
        filetype = 'PDF'
    elif (maltype == 6):
        filetype = 'PDF'
    else:
        filetype = 'all'

    try:

        if (filetype != "all"):
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
        
        if (filetype == "all"):
            print("\n")
            print((mycolors.reset + "SHA256 hash".center(75)), end='')
            print((mycolors.reset + "MD5 hash".center(38)), end='')
            print("\n" + (112*'-').center(56))
            print((mycolors.reset))

            requestsession = requests.Session( )
            requestsession.headers.update({'accept': 'application/json'})
            finalurl = ''.join([urlmalshare, MALSHAREAPI, '&action=getlist'])
            malresponse = requestsession.get(url=finalurl)
            maltext = json.loads(malresponse.text)

        if ((maltext) and filetype!="all"):
            try:
                for i in range(0, len(maltext)):
                    if (maltext[i].get('sha256')):
                        if (bkg == 1):
                            print((mycolors.reset + "sha256: " + mycolors.foreground.yellow + "%s" % maltext[i]['sha256'] + mycolors.reset + "  md5: " + mycolors.foreground.lightcyan + "%s" % maltext[i]['md5'] + mycolors.reset + "  type: " + mycolors.foreground.lightred + "%s" % filetype))
                        else:
                            print((mycolors.reset + "sha256: " + mycolors.foreground.red + "%s" % maltext[i]['sha256'] + mycolors.reset + "  md5: " + mycolors.foreground.blue + "%s" % maltext[i]['md5'] + mycolors.reset + "   type: " + mycolors.foreground.purple + "%s" % filetype))
            
            except KeyError as e:
                pass

            except (BrokenPipeError, IOError):
                print(mycolors.reset, file=sys.stderr)
                exit(1)

        if ((maltext) and filetype=="all"):
            try:
                for i in range(0, len(maltext)):
                    if (maltext[i].get('sha256')):
                        if (bkg == 1):
                            print((mycolors.reset + "sha256: " + mycolors.foreground.yellow + "%s" % maltext[i]['sha256'] + mycolors.reset + "  md5: " + mycolors.foreground.lightcyan + "%s" % maltext[i]['md5'] + mycolors.reset))
                        else:
                            print((mycolors.reset + "sha256: " + mycolors.foreground.red + "%s" % maltext[i]['sha256'] + mycolors.reset + "  md5: " + mycolors.foreground.blue + "%s" % maltext[i]['md5'] + mycolors.reset))

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
                print(mycolors.foreground.lightcyan + "Is available?: \t"  +  haustext.get('query_status').upper())
            else:
                print(mycolors.foreground.purple + "Is available?: \t"  +  haustext.get('query_status').upper())
        else:
            if (bkg == 1):
                print(mycolors.foreground.lightcyan + 'Is availble?: ')
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
                print(mycolors.foreground.lightcyan + "URL: \t\t"  +  haustext.get('url') + "  (city: " +  urlcity + ")" )
            else:
                print(mycolors.foreground.purple + "URL: \t\t"  +  haustext.get('url') + "  (city: " +  urlcity + ")" )
        else:
            if (bkg == 1):
                print(mycolors.foreground.lightcyan + 'URL: ')
            else:
                print(mycolors.foreground.purple + 'URL: ')
        
        if 'url_status' in haustext:
            if (bkg == 1):
                if(haustext.get('url_status') == 'online'):
                    print(mycolors.foreground.lightcyan + "Status: \t"  + mycolors.reverse + haustext.get('url_status') + mycolors.reset)
                if(haustext.get('url_status') == 'offline'):
                    print(mycolors.foreground.lightred + "Status: \t"  +  mycolors.reverse + haustext.get('url_status') + mycolors.reset)
                if(haustext.get('url_status') == ''):
                    print(mycolors.foreground.yellow + "Status: \t"  +  mycolors.reverse + "unknown" + mycolors.reset)
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
                    print(mycolors.foreground.lightcyan + "Reporter: \t"  +  haustext.get('reporter'))
                else:
                    print(mycolors.foreground.blue + "Reporter: \t"  +  haustext.get('reporter'))
            else:
                if (bkg == 1):
                    print(mycolors.foreground.lightcyan + 'Reporter: ')
                else:
                    print(mycolors.foreground.blue + 'Reporter: ')

        if 'larted' in haustext:
            if haustext.get('larted') is not None:
                if (bkg == 1):
                    print(mycolors.foreground.lightcyan + "Larted: \t" + haustext.get('larted'))
                else:
                    print(mycolors.foreground.blue + "Larted: \t" + haustext.get('larted'))

            else:
                if (bkg == 1):
                    print(mycolors.foreground.lightcyan + "Larted: ")
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
                        print(mycolors.foreground.yellow + "filename: %-30s" % i['filename'].ljust(40), end = ' ' + "")
                        print(mycolors.foreground.lightred + "filetype: %s" % i['file_type'].ljust(10) + Fore.WHITE, end= ' ' + "")
                        results = i['virustotal']
                        if (results) is not None:
                            print(mycolors.foreground.lightcyan + "VirusTotal: %s" % results['result'] + Fore.WHITE)
                        else:
                            print(mycolors.foreground.lightcyan + "VirusTotal: Not Found" + Fore.WHITE)
                    else:
                        print(mycolors.reset + "Payload_%d:\t" % x, end='')
                        print(mycolors.foreground.purple + "firstseen:%12s" % i['firstseen'], end = '     ')
                        print(mycolors.foreground.green + "filename: %-30s" % i['filename'].ljust(40), end = ' ' + "")
                        print(mycolors.foreground.red + "filetype: %s" % i['file_type'].ljust(10) + Fore.BLACK, end = '' + "")
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
                        print(mycolors.foreground.lightcyan + j['response_sha256'])
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
                print(mycolors.foreground.lightcyan + "Is available?: \t"  +  haustext.get('query_status').upper())
            else:
                print(mycolors.foreground.green + "Is available?: \t"  +  haustext.get('query_status').upper())
        else:
            if (bkg == 1):
                print(mycolors.foreground.lightcyan + 'Is availble?: Not available')
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
                            print(mycolors.foreground.lightcyan + mycolors.reverse + w['url_status'] + " " + mycolors.reset, end=' ')
                        if(w['url_status'] == 'offline'):
                            print(mycolors.foreground.lightred + mycolors.reverse + w['url_status'] + mycolors.reset, end=' ')
                        if(w['url_status'] == ''):
                            print(mycolors.foreground.yellow + mycolors.reverse + "unknown" + mycolors.reset, end=' ')
                        if w['filename'] is not None:
                            print(mycolors.foreground.pink + "%-36s" % w['filename'] + mycolors.reset, end=' ')
                        else:
                            print(mycolors.foreground.pink + "%-36s" % "Filename not reported!" + mycolors.reset, end=' ')
                        if (w['url'] is not None):
                            if(validators.url(w['url'])):
                                print(mycolors.foreground.lightcyan + urltoip((w['url'])).ljust(20) + mycolors.reset, end=' ')
                            else:
                                print(mycolors.foreground.lightcyan + "Not located".center(20) + mycolors.reset, end=' ')
                            print(mycolors.foreground.yellow + w['url'] + mycolors.reset)
                        else:
                            print(mycolors.foreground.lightcyan + "Not located".center(20) + mycolors.reset, end=' ')
                            print(mycolors.foreground.lightcyan + "URL not provided".center(20) + mycolors.reset, end=' ')

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
                            print(mycolors.foreground.lightcyan + "Not located".center(20) + mycolors.reset, end=' ')
                            print(mycolors.foreground.lightcyan + "URL not provided".center(20) + mycolors.reset, end=' ')

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

                            if ("comment" in y):
                                if d['comment']:
                                    print(mycolors.foreground.lightcyan + "\ncomments: ".ljust(15) + mycolors.reset, end='')
                                    s = d['comment'].split('\n')
                                    for n in range(len(s)):
                                        print("\n".ljust(15) + s[n], end=' ')

                            if ("reporter" in y):
                                if d['reporter']:
                                    print(mycolors.foreground.lightcyan + "\nreporter: ".ljust(15) + mycolors.reset + d['reporter'], end=' ')

                            if ("oleinformation" in y):
                                print(mycolors.foreground.lightcyan + "\noleinformation: ".ljust(15),end='') 
                                for t in d['oleinformation']:
                                    print(mycolors.reset + t, end=' ')

                            if ("delivery_method" in y):
                                if d['delivery_method']:
                                    print(mycolors.foreground.lightcyan + "\ndelivery: ".ljust(15) + mycolors.reset + d['delivery_method'], end=' ')

                            if ("tags" in y):
                                if d['tags']:
                                    print(mycolors.foreground.lightcyan + "\ntags: ".ljust(15),end='') 
                                    for t in d['tags']:
                                        print(mycolors.reset + t, end=' ')

                            if ("file_information" in y):
                                if (d['file_information'] is not None):
                                    for x in d['file_information']:
                                        if ("context" in x):
                                            if (x['context'] == "twitter"):
                                                print(mycolors.foreground.yellow + "\nTwitter: ".ljust(15) + mycolors.reset + x['value'], end=' ')
                                            if (x['context'] == "cape"):
                                                print(mycolors.foreground.yellow + "\nCape: ".ljust(15) + mycolors.reset + x['value'], end=' ')

                            if ("vendor_intel" in y):
                                if (d['vendor_intel'] is not None):
                                    if ("UnpacMe" in d['vendor_intel']):
                                        if (d['vendor_intel']['UnpacMe']):
                                            print(mycolors.foreground.yellow + "\nUnpacMe: ".ljust(15) + mycolors.reset, end=' ')
                                            filtered_list = []
                                            for j in d['vendor_intel']['UnpacMe']:
                                                    if ("link" in j):
                                                        if j['link'] not in filtered_list:
                                                            filtered_list.append(j['link'])
                                                            for h in filtered_list:
                                                                print('\n'.ljust(15) + h, end=' ')

                                    if ("ANY.RUN" in d['vendor_intel']):
                                        print(mycolors.foreground.yellow + "\nAny.Run: ".ljust(15) + mycolors.reset, end=' ')
                                        for j in d['vendor_intel']['ANY.RUN']:
                                            if ("analysis_url" in j):
                                                print("\n".ljust(15) + j['analysis_url'], end=' ')

                                    if ("Triage" in d['vendor_intel']):
                                        for j in d['vendor_intel']['Triage']:
                                            if ("link" in j):
                                                print(mycolors.foreground.yellow + "\n\nTriage: ".ljust(16) + mycolors.reset + d['vendor_intel']['Triage']['link'], end=' ')

                                        if (d['vendor_intel']['Triage']['signatures']):
                                            print(mycolors.foreground.yellow + "\nTriage sigs: ".ljust(15) + mycolors.reset,end='\n')
                                            for m in d['vendor_intel']['Triage']['signatures']:
                                                if ("signature" in m):
                                                    print(mycolors.reset + "".ljust(14) + m['signature'])

                                    if ("vxCube" in d['vendor_intel']):
                                        for j in d['vendor_intel']['vxCube']:
                                            if ("behaviour" in j):
                                                print(mycolors.foreground.yellow + "\nDr.Web rules: ".ljust(15) + mycolors.reset)
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


def triage_search(triagex, triage):

    triagetext = ''
    triageresponse = ''
    params = ''

    requestTRIAGEAPI()

    try:

        print("\n")
        print((mycolors.reset + "TRIAGE OVERVIEW REPORT".center(100)), end='')
        print((mycolors.reset + "".center(28)), end='')
        print("\n" + (100*'-').center(50))

        requestsession = requests.Session( )
        requestsession.headers.update({'accept':'application/json', 'Authorization':'Bearer ' + TRIAGEAPI})
        triageresponse = requestsession.get(triage + triagex)
        triagetext = json.loads(triageresponse.text)

        if 'error' in triagetext:
            if triagetext['error'] == "NOT_FOUND":
                if (bkg == 1):
                    print(mycolors.foreground.lightred + "\nThe provided argument was not found!\n" + mycolors.reset)
                else:
                    print(mycolors.foreground.red + "\nThe provided argument was not found!\n" + mycolors.reset)
                exit(1)

            if triagetext['error'] == "INVALID":
                if (bkg == 1):
                    print(mycolors.foreground.lightred + "\nThe provided argument is not valid!\n" + mycolors.reset)
                else:
                    print(mycolors.foreground.red + "\nThe provided argument is not valid!\n" + mycolors.reset)
                exit(1)

            if triagetext['error'] == "UNAUTHORIZED":
                if (bkg == 1):
                    print(mycolors.foreground.lightred + "\nThe provided credential is not valid!\n" + mycolors.reset)
                else:
                    print(mycolors.foreground.red + "\nThe provided credential is not valid!\n" + mycolors.reset)
                exit(1)
            
            if triagetext['error'] == "INVALID_QUERY":
                if (bkg == 1):
                    print("\n" + mycolors.foreground.lightred + triagetext['message'] + mycolors.reset, end='\n\n')
                else:
                    print("\n" + mycolors.foreground.red + triagetext['message'] + mycolors.reset, end='\n\n')
                exit(1)

        if (bkg == 1):
            for i in triagetext.keys():
                if (i == "data"):
                    if (triagetext['data'] is not None):
                        for d in triagetext['data']:
                            y = d.keys()    
                            if ("id" in y):
                                if d['id']:
                                    print(mycolors.foreground.lightcyan + "\nid: ".ljust(12) + mycolors.reset + d['id'],end=' ')

                            if ("status" in y):
                                if d['status']:
                                    print(mycolors.foreground.lightcyan + "\nstatus: ".ljust(12) + mycolors.reset + d['status'], end=' ')

                            if ("kind" in y):
                                if d['kind']:
                                    print(mycolors.foreground.lightcyan + "\nkind: ".ljust(12) + mycolors.reset + d['kind'], end=' ')

                            if ("filename" in y):
                                if d['filename']:
                                    print(mycolors.foreground.lightcyan + "\nfilename: ".ljust(12) + mycolors.reset + d['filename'], end=' ')

                            if ("submitted" in y):
                                if d['submitted']:
                                    print(mycolors.foreground.lightcyan + "\nsubmitted: ".ljust(12) + mycolors.reset + d['submitted'], end=' ')

                            if ("completed" in y):
                                if d['completed']:
                                    print(mycolors.foreground.lightcyan + "\ncompleted: ".ljust(12) + mycolors.reset + d['completed'], end=' ')

                            if ("private" in y):
                                if d['private']:
                                    print(mycolors.foreground.lightcyan + "\nprivate: ".ljust(12) + mycolors.reset + d['private'], end=' ')

                            for x in triagetext['data'][0].keys():
                                if (x == "tasks"):
                                    if (triagetext['data'][0]['tasks'] is not None):
                                        for d in triagetext['data'][0]['tasks']:
                                            print(mycolors.foreground.lightcyan + "\ntasks: " + mycolors.reset, end=' ')
                                            z = d.keys()    
                                            if ("id" in z):
                                                if d['id']:
                                                    print(mycolors.foreground.lightcyan + "\n\t   id: ".ljust(13) + mycolors.reset + d['id'], end=' ')

                                            if ("status" in z):
                                                if d['status']:
                                                    print(mycolors.foreground.lightcyan + "\n\t   status: ".ljust(12) + mycolors.reset + d['status'], end=' ')

                                            if ("target" in z):
                                                if d['target']:
                                                    print(mycolors.foreground.lightcyan + "\n\t   target: ".ljust(12) + mycolors.reset + d['target'], end=' ')
                                            
                                            if ("pick" in z):
                                                if d['pick']:
                                                    print(mycolors.foreground.lightcyan + "\n\t   pick: ".ljust(13) + mycolors.reset + d['pick'], end=' ')

                            print("\n" + (90*'-').center(45),end='')

                if (i == "next"):
                    if (triagetext['next'] is not None):
                        print(mycolors.foreground.lightcyan + "\nnext: ".ljust(12) + mycolors.reset + triagetext['next'], end=' ')

        if (bkg == 0):
            for i in triagetext.keys():
                if (i == "data"):
                    if (triagetext['data'] is not None):
                        for d in triagetext['data']:
                            y = d.keys()    
                            if ("id" in y):
                                if d['id']:
                                    print(mycolors.foreground.cyan + "\nid: ".ljust(12) + mycolors.reset + d['id'],end=' ')

                            if ("status" in y):
                                if d['status']:
                                    print(mycolors.foreground.cyan + "\nstatus: ".ljust(12) + mycolors.reset + d['status'], end=' ')

                            if ("kind" in y):
                                if d['kind']:
                                    print(mycolors.foreground.cyan + "\nkind: ".ljust(12) + mycolors.reset + d['kind'], end=' ')

                            if ("filename" in y):
                                if d['filename']:
                                    print(mycolors.foreground.cyan + "\nfilename: ".ljust(12) + mycolors.reset + d['filename'], end=' ')

                            if ("submitted" in y):
                                if d['submitted']:
                                    print(mycolors.foreground.cyan + "\nsubmitted: ".ljust(12) + mycolors.reset + d['submitted'], end=' ')

                            if ("completed" in y):
                                if d['completed']:
                                    print(mycolors.foreground.cyan + "\ncompleted: ".ljust(12) + mycolors.reset + d['completed'], end=' ')

                            if ("private" in y):
                                if d['private']:
                                    print(mycolors.foreground.cyan + "\nprivate: ".ljust(12) + mycolors.reset + d['private'], end=' ')

                            for x in triagetext['data'][0].keys():
                                if (x == "tasks"):
                                    if (triagetext['data'][0]['tasks'] is not None):
                                        for d in triagetext['data'][0]['tasks']:
                                            print(mycolors.foreground.purple + "\ntasks: " + mycolors.reset, end=' ')
                                            z = d.keys()    
                                            if ("id" in z):
                                                if d['id']:
                                                    print(mycolors.foreground.purple + "\n\t   id: ".ljust(13) + mycolors.reset + d['id'], end=' ')

                                            if ("status" in z):
                                                if d['status']:
                                                    print(mycolors.foreground.purple + "\n\t   status: ".ljust(12) + mycolors.reset + d['status'], end=' ')

                                            if ("target" in z):
                                                if d['target']:
                                                    print(mycolors.foreground.purple + "\n\t   target: ".ljust(12) + mycolors.reset + d['target'], end=' ')
                                            
                                            if ("pick" in z):
                                                if d['pick']:
                                                    print(mycolors.foreground.purple + "\n\t   pick: ".ljust(13) + mycolors.reset + d['pick'], end=' ')

                            print("\n" + (90*'-').center(45),end='')

                if (i == "next"):
                    if (triagetext['next'] is not None):
                        print(mycolors.foreground.purple + "\nnext: ".ljust(12) + mycolors.reset + triagetext['next'], end=' ')


        print(mycolors.reset)
        exit(0)
    
    except ValueError as e:
        print(e)
        if (bkg == 1):
            print((mycolors.foreground.lightred + "\nError while connecting to Tri.age!\n"))
        else:
            print((mycolors.foreground.lightred + "\nError while connecting to Tri.age!\n"))
        print(mycolors.reset)


def triage_summary(triagex, triage):

    triagetext = ''
    triageresponse = ''
    params = ''
    idx = ''

    requestTRIAGEAPI()

    try:

        print("\n")
        print((mycolors.reset + "TRIAGE SEARCH REPORT".center(100)), end='')
        print((mycolors.reset + "".center(28)), end='')
        print("\n" + (100*'-').center(50))

        requestsession = requests.Session( )
        requestsession.headers.update({'accept':'application/json', 'Authorization':'Bearer ' + TRIAGEAPI})
        triageresponse = requestsession.get(triage + 'samples/' +  triagex + '/overview.json')
        triagetext = json.loads(triageresponse.text)

        if 'error' in triagetext:
            if triagetext['error'] == "NOT_FOUND":
                if (bkg == 1):
                    print(mycolors.foreground.lightred + "\nThe provided ID was not found!\n" + mycolors.reset)
                else:
                    print(mycolors.foreground.red + "\nThe provided ID was not found!\n" + mycolors.reset)
                exit(1)

            if triagetext['error'] == "UNAUTHORIZED":
                if (bkg == 1):
                    print(mycolors.foreground.lightred + "\nThe provided credential is not valid!\n" + mycolors.reset)
                else:
                    print(mycolors.foreground.red + "\nThe provided credential is not valid!\n" + mycolors.reset)
                exit(1)
            
            if triagetext['error'] == "INVALID_QUERY":
                if (bkg == 1):
                    print("\n" + mycolors.foreground.lightred + triagetext['message'] + mycolors.reset, end='\n\n')
                else:
                    print("\n" + mycolors.foreground.red + triagetext['message'] + mycolors.reset, end='\n\n')
                exit(1)

        if (bkg == 1):
            for i in triagetext.keys():
                if (i == "sample"):
                    if (triagetext['sample'] is not None):
                        y = triagetext['sample'].keys()    
                        if ("id" in y):
                            print(mycolors.foreground.lightcyan + "\n\nid: ".ljust(13) + mycolors.reset + triagetext['sample']['id'],end=' ')

                        if ("target" in y):
                            print(mycolors.foreground.lightcyan + "\ntarget: ".ljust(12) + mycolors.reset + triagetext['sample']['target'], end=' ')

                        if ("size" in y):
                            print((mycolors.foreground.lightcyan + "\nsize: ".ljust(12) + mycolors.reset + "%d") % int(triagetext['sample']['size']), end=' ')

                        if ("md5" in y):
                            print(mycolors.foreground.lightcyan + "\nmd5: ".ljust(12) + mycolors.reset + triagetext['sample']['md5'], end=' ')

                        if ("sha1" in y):
                            print(mycolors.foreground.lightcyan + "\nsha1: ".ljust(12) + mycolors.reset + triagetext['sample']['sha1'], end=' ')

                        if ("sha256" in y):
                            print(mycolors.foreground.lightcyan + "\nsha256: ".ljust(12) + mycolors.reset + triagetext['sample']['sha256'], end=' ')

                        if ("completed" in y):
                            print(mycolors.foreground.lightcyan + "\ncompleted: ".ljust(12) + mycolors.reset + triagetext['sample']['completed'], end=' ')

                if (i == "analysis"):
                    if (triagetext['analysis'] is not None):
                        if ("score" in triagetext['analysis']):
                            print(mycolors.foreground.lightcyan + "\nscore: ".ljust(12) + mycolors.reset + str(triagetext['analysis']['score']),end=' ')

                if (i == "tasks"):
                    if (triagetext[i] is not None):
                        print(mycolors.foreground.lightcyan + "\n\ntasks: ".ljust(11) + mycolors.reset,end=' ')
                        for d in (triagetext[i].keys()):
                            print("\n".ljust(12) + mycolors.foreground.lightcyan + "* " + d + ": \n" + mycolors.reset,end=' ')
                            if ("kind" in triagetext[i][d]):
                                print(mycolors.foreground.yellow + "\n".ljust(12) + "kind: ".ljust(10)+ mycolors.reset + triagetext[i][d]['kind'], end=' ')
                            if ("status" in triagetext[i][d]):
                                print(mycolors.foreground.yellow + "\n".ljust(12) + "status: ".ljust(10) + mycolors.reset + triagetext[i][d]['status'], end=' ')
                            if ("score" in triagetext[i][d]):
                                print(mycolors.foreground.yellow + "\n".ljust(12) + "score: ".ljust(10) + mycolors.reset + str(triagetext[i][d]['score']), end=' ')
                            if ("target" in triagetext[i][d]):
                                print(mycolors.foreground.yellow + "\n".ljust(12) + "target: ".ljust(10) + mycolors.reset + triagetext[i][d]['target'], end=' ')
                            if ("resource" in triagetext[i][d]):
                                print(mycolors.foreground.yellow + "\n".ljust(12) + "resource: ".ljust(8) + mycolors.reset + triagetext[i][d]['resource'], end=' ')
                            if ("platform" in triagetext[i][d]):
                                print(mycolors.foreground.yellow + "\n".ljust(12) + "platform: ".ljust(8) + mycolors.reset + triagetext[i][d]['platform'], end=' ')

                            print(mycolors.foreground.yellow + "\n".ljust(12) + "tags: ".ljust(10) + mycolors.reset, end=' ')
                            if ("tags" in triagetext[i][d]):
                                for j in triagetext[i][d]['tags']:
                                    print("\n".ljust(22) +  mycolors.reset + j, end=' ')

                            print(mycolors.reset + "")

                if (i == "targets"):
                    if (triagetext['targets'] is not None):
                        print(mycolors.foreground.lightcyan + "\ntargets: ".ljust(12) + mycolors.reset,end=' ')
                        for k in range(len(triagetext['targets'])):
                            for m in (triagetext['targets'][k]):
                                if ("tasks" == m):
                                    print(mycolors.foreground.yellow + "\n".ljust(12) + "tasks: ".ljust(9) + mycolors.reset,end=' ')
                                    for i in range(len(triagetext['targets'][k][m])):
                                        print(str(triagetext['targets'][k][m][i]),end=' ')
                                if ("score" == m):
                                    print(mycolors.foreground.yellow + "\n".ljust(12) + "score: ".ljust(10) + mycolors.reset + str(triagetext['targets'][k][m]),end=' ')
                                if ("target" == m):
                                    print(mycolors.foreground.yellow + "\n".ljust(12) + "target: ".ljust(10) + mycolors.reset + str(triagetext['targets'][k][m]),end=' ')
                                if ("size" == m):
                                    print(mycolors.foreground.yellow + "\n".ljust(12) + "size: ".ljust(10) + mycolors.reset + str(triagetext['targets'][k][m]) + "bytes",end=' ')
                                if ("md5" == m):
                                    print(mycolors.foreground.yellow + "\n".ljust(12) + "md5: ".ljust(10) + mycolors.reset + str(triagetext['targets'][k][m]),end=' ')
                                if ("sha1" == m):
                                    print(mycolors.foreground.yellow + "\n".ljust(12) + "sha1: ".ljust(10) + mycolors.reset + str(triagetext['targets'][k][m]),end=' ')
                                if ("sha256" == m):
                                    print(mycolors.foreground.yellow + "\n".ljust(12) + "sha256: ".ljust(10) + mycolors.reset + str(triagetext['targets'][k][m]),end=' ')
                                if ("tags" == m):
                                    print(mycolors.foreground.yellow + "\n".ljust(12) + "tags: ".ljust(10) + mycolors.reset,end=' ')
                                    for j in (triagetext['targets'][k][m]):
                                        print("\n".ljust(22) + mycolors.reset + j,end=' ')
                                if ("family" == m):
                                    print(mycolors.foreground.yellow + "\n".ljust(12) + "family: ".ljust(9) + mycolors.reset,end=' ')
                                    for n in range(len(triagetext['targets'][k][m])):
                                        print(mycolors.reset + str(triagetext['targets'][k][m][n]),end=' ')
                                if ("iocs" == m):
                                    print(mycolors.foreground.yellow + "\n".ljust(12) + "iocs: ",end=' ')
                                    for j in (triagetext['targets'][k][m]):
                                        if ('ips' == j):
                                            for i in range(len(triagetext['targets'][k][m][j])):
                                                print("\n".ljust(22) + mycolors.reset + str(triagetext['targets'][k][m][j][i]),end=' ')
                                        if ('domains' == j):
                                            for i in range(len(triagetext['targets'][k][m][j])):
                                                print("\n".ljust(22) + mycolors.reset + str(triagetext['targets'][k][m][j][i]),end=' ')
                                        if ('urls' == j):
                                            for i in range(len(triagetext['targets'][k][m][j])):
                                                print(mycolors.reset + ("\n".ljust(22) + ("\n" + "".ljust(21)).join(textwrap.wrap((triagetext['targets'][k][m][j][i]),width=80))),end=' ')

                if (i == "signatures"):
                    if (triagetext[i] is not None):
                        print(mycolors.foreground.lightcyan + "\nsignatures: ".ljust(12) + mycolors.reset,end=' ')
                        for y in range(len(triagetext[i])):
                            for d in (triagetext[i][y]).keys():
                                if (d == 'name'):
                                    print(mycolors.foreground.yellow + "\n".ljust(12) + mycolors.reset + str(triagetext[i][y][d]),end=' ')

                        print(mycolors.reset + "")

                if (i == "extracted"):
                    if (triagetext['extracted'] is not None):
                        print(mycolors.foreground.lightcyan + "\nextracted: ".ljust(12) + mycolors.reset,end=' ')
                        for k in range(len(triagetext['extracted'])):
                            for m in (triagetext['extracted'][k]):
                                if ("tasks" == m):
                                    print(mycolors.foreground.yellow + "\n".ljust(12) + "tasks: ".ljust(9) + mycolors.reset,end=' ')
                                    for i in range(len(triagetext['extracted'][k][m])):
                                        print(str(triagetext['extracted'][k][m][i]),end=' ')
                                if ("resource" == m):
                                    print(mycolors.foreground.yellow + "\n".ljust(12) + "resource: ".ljust(10) + mycolors.reset + str(triagetext['extracted'][k][m]),end=' ')
                                if ("dumped_file" == m):
                                    print(mycolors.foreground.yellow + "\n".ljust(12) + "dumped: ".ljust(10) + mycolors.reset + str(triagetext['extracted'][k][m]),end=' ')
                                if ("config" == m):
                                    for x in ((triagetext['extracted'][k][m]).keys()):
                                        if ('family' == x):
                                            print(mycolors.foreground.yellow + "\n".ljust(12) + "family: ".ljust(10) + mycolors.reset + str(triagetext['extracted'][k][m][x]),end=' ')
                                        if ('rule' == x):
                                            print(mycolors.foreground.yellow + "\n".ljust(12) + "rule: ".ljust(10) + mycolors.reset + str(triagetext['extracted'][k][m][x]),end=' ')
                                        if ("extracted_pe" == x):
                                            print(mycolors.foreground.yellow + "\n".ljust(12) + "extracted_pe: ".ljust(9) + mycolors.reset,end=' ')
                                            for i in range(len(triagetext['extracted'][k][m][x])):
                                                print("\n".ljust(22) + str(triagetext['extracted'][k][m][x][i]),end=' ')
                                        if ('c2' == x):
                                            print(mycolors.foreground.yellow + "\n".ljust(12) + "c2: ".ljust(9) + mycolors.reset,end=' ')
                                            for z in range(len(triagetext['extracted'][k][m][x])):
                                                print("\n".ljust(22) + mycolors.reset + str(triagetext['extracted'][k][m][x][z]),end=' ')
                                        if ("botnet" == x):
                                            print(mycolors.foreground.yellow + "\n".ljust(12) + "botnet: ".ljust(10) + mycolors.reset + str(triagetext['extracted'][k][m][x]),end=' ')
                                        if ("keys" == x):
                                            for p in range(len(triagetext['extracted'][k][m][x])):
                                                for q in (triagetext['extracted'][k][m][x][p]).keys():
                                                    if ('key' == q):
                                                        print(mycolors.foreground.yellow + "\n".ljust(12) + "key: ".ljust(10) + mycolors.reset + str(triagetext['extracted'][k][m][x][p][q]),end=' ')
                                                    if ('value' == q):
                                                        print(mycolors.foreground.yellow + "\n".ljust(12) + "value:".ljust(10) + mycolors.reset,end='')
                                                        print(mycolors.reset + (("\n" + "".ljust(21)).join(textwrap.wrap((triagetext['extracted'][k][m][x][p][q]),width=80))),end=' ')


        if (bkg == 0):
            for i in triagetext.keys():
                if (i == "sample"):
                    if (triagetext['sample'] is not None):
                        y = triagetext['sample'].keys()    
                        if ("id" in y):
                            print(mycolors.foreground.green + "\n\nid: ".ljust(13) + mycolors.reset + triagetext['sample']['id'],end=' ')

                        if ("target" in y):
                            print(mycolors.foreground.green + "\ntarget: ".ljust(12) + mycolors.reset + triagetext['sample']['target'], end=' ')

                        if ("size" in y):
                            print((mycolors.foreground.green + "\nsize: ".ljust(12) + mycolors.reset + "%d") % int(triagetext['sample']['size']), end=' ')

                        if ("md5" in y):
                            print(mycolors.foreground.green + "\nmd5: ".ljust(12) + mycolors.reset + triagetext['sample']['md5'], end=' ')

                        if ("sha1" in y):
                            print(mycolors.foreground.green + "\nsha1: ".ljust(12) + mycolors.reset + triagetext['sample']['sha1'], end=' ')

                        if ("sha256" in y):
                            print(mycolors.foreground.green + "\nsha256: ".ljust(12) + mycolors.reset + triagetext['sample']['sha256'], end=' ')

                        if ("completed" in y):
                            print(mycolors.foreground.green + "\ncompleted: ".ljust(12) + mycolors.reset + triagetext['sample']['completed'], end=' ')

                if (i == "analysis"):
                    if (triagetext['analysis'] is not None):
                        if ("score" in triagetext['analysis']):
                            print(mycolors.foreground.green + "\nscore: ".ljust(12) + mycolors.reset + str(triagetext['analysis']['score']),end=' ')
                
                if (i == "tasks"):
                    if (triagetext[i] is not None):
                        print(mycolors.foreground.green + "\n\ntasks: ".ljust(11) + mycolors.reset,end=' ')
                        for d in (triagetext[i].keys()):
                            print("\n".ljust(12) + mycolors.foreground.blue + "* " + d + ": \n" + mycolors.reset,end=' ')
                            if ("kind" in triagetext[i][d]):
                                print(mycolors.foreground.red + "\n".ljust(12) + "kind: ".ljust(10)+ mycolors.reset + triagetext[i][d]['kind'], end=' ')
                            if ("status" in triagetext[i][d]):
                                print(mycolors.foreground.red + "\n".ljust(12) + "status: ".ljust(10) + mycolors.reset + triagetext[i][d]['status'], end=' ')
                            if ("score" in triagetext[i][d]):
                                print(mycolors.foreground.red + "\n".ljust(12) + "score: ".ljust(10) + mycolors.reset + str(triagetext[i][d]['score']), end=' ')
                            if ("target" in triagetext[i][d]):
                                print(mycolors.foreground.red + "\n".ljust(12) + "target: ".ljust(10) + mycolors.reset + triagetext[i][d]['target'], end=' ')
                            if ("resource" in triagetext[i][d]):
                                print(mycolors.foreground.red + "\n".ljust(12) + "resource: ".ljust(8) + mycolors.reset + triagetext[i][d]['resource'], end=' ')
                            if ("platform" in triagetext[i][d]):
                                print(mycolors.foreground.red + "\n".ljust(12) + "platform: ".ljust(8) + mycolors.reset + triagetext[i][d]['platform'], end=' ')

                            print(mycolors.foreground.red + "\n".ljust(12) + "tags: ".ljust(10) + mycolors.reset, end=' ')
                            if ("tags" in triagetext[i][d]):
                                for j in triagetext[i][d]['tags']:
                                    print("\n".ljust(22) +  mycolors.reset + j, end=' ')
                            
                            print(mycolors.reset + "")

                if (i == "targets"):
                    if (triagetext['targets'] is not None):
                        print(mycolors.foreground.green + "\ntargets: ".ljust(12) + mycolors.reset,end=' ')
                        for k in range(len(triagetext['targets'])):
                            for m in (triagetext['targets'][k]):
                                if ("tasks" == m):
                                    print(mycolors.foreground.red + "\n".ljust(12) + "tasks: ".ljust(9) + mycolors.reset,end=' ')
                                    for i in range(len(triagetext['targets'][k][m])):
                                        print(str(triagetext['targets'][k][m][i]),end=' ')
                                if ("score" == m):
                                    print(mycolors.foreground.red + "\n".ljust(12) + "score: ".ljust(10) + mycolors.reset + str(triagetext['targets'][k][m]),end=' ')
                                if ("target" == m):
                                    print(mycolors.foreground.red + "\n".ljust(12) + "target: ".ljust(10) + mycolors.reset + str(triagetext['targets'][k][m]),end=' ')
                                if ("size" == m):
                                    print(mycolors.foreground.red + "\n".ljust(12) + "size: ".ljust(10) + mycolors.reset + str(triagetext['targets'][k][m]) + "bytes",end=' ')
                                if ("md5" == m):
                                    print(mycolors.foreground.red + "\n".ljust(12) + "md5: ".ljust(10) + mycolors.reset + str(triagetext['targets'][k][m]),end=' ')
                                if ("sha1" == m):
                                    print(mycolors.foreground.red + "\n".ljust(12) + "sha1: ".ljust(10) + mycolors.reset + str(triagetext['targets'][k][m]),end=' ')
                                if ("sha256" == m):
                                    print(mycolors.foreground.red + "\n".ljust(12) + "sha256: ".ljust(10) + mycolors.reset + str(triagetext['targets'][k][m]),end=' ')
                                if ("tags" == m):
                                    print(mycolors.foreground.red + "\n".ljust(12) + "tags: ".ljust(10) + mycolors.reset,end=' ')
                                    for j in (triagetext['targets'][k][m]):
                                        print("\n".ljust(22) + mycolors.reset + j,end=' ')
                                if ("family" == m):
                                    print(mycolors.foreground.red + "\n".ljust(12) + "family: ".ljust(9) + mycolors.reset,end=' ')
                                    for n in range(len(triagetext['targets'][k][m])):
                                        print(mycolors.reset + str(triagetext['targets'][k][m][n]),end=' ')
                                if ("iocs" == m):
                                    print(mycolors.foreground.red + "\n".ljust(12) + "iocs: ",end=' ')
                                    for j in (triagetext['targets'][k][m]):
                                        if ('ips' == j):
                                            for i in range(len(triagetext['targets'][k][m][j])):
                                                print("\n".ljust(22) + mycolors.reset + str(triagetext['targets'][k][m][j][i]),end=' ')
                                        if ('domains' == j):
                                            for i in range(len(triagetext['targets'][k][m][j])):
                                                print("\n".ljust(22) + mycolors.reset + str(triagetext['targets'][k][m][j][i]),end=' ')
                                        if ('urls' == j):
                                            for i in range(len(triagetext['targets'][k][m][j])):
                                                print(mycolors.reset + ("\n".ljust(22) + ("\n" + "".ljust(21)).join(textwrap.wrap((triagetext['targets'][k][m][j][i]),width=80))),end=' ')

                if (i == "signatures"):
                    if (triagetext[i] is not None):
                        print(mycolors.foreground.green + "\nsignatures: ".ljust(12) + mycolors.reset,end=' ')
                        for y in range(len(triagetext[i])):
                            for d in (triagetext[i][y]).keys():
                                if (d == 'name'):
                                    print(mycolors.foreground.red + "\n".ljust(12) + mycolors.reset + str(triagetext[i][y][d]),end=' ')

                        print(mycolors.reset + "")


                if (i == "extracted"):
                    if (triagetext['extracted'] is not None):
                        print(mycolors.foreground.green + "\nextracted: ".ljust(12) + mycolors.reset,end=' ')
                        for k in range(len(triagetext['extracted'])):
                            for m in (triagetext['extracted'][k]):
                                if ("tasks" == m):
                                    print(mycolors.foreground.red + "\n".ljust(12) + "tasks: ".ljust(9) + mycolors.reset,end=' ')
                                    for i in range(len(triagetext['extracted'][k][m])):
                                        print(str(triagetext['extracted'][k][m][i]),end=' ')
                                if ("resource" == m):
                                    print(mycolors.foreground.red + "\n".ljust(12) + "resource: ".ljust(10) + mycolors.reset + str(triagetext['extracted'][k][m]),end=' ')
                                if ("dumped_file" == m):
                                    print(mycolors.foreground.red + "\n".ljust(12) + "dumped: ".ljust(10) + mycolors.reset + str(triagetext['extracted'][k][m]),end=' ')
                                if ("config" == m):
                                    for x in ((triagetext['extracted'][k][m]).keys()):
                                        if ('family' == x):
                                            print(mycolors.foreground.red + "\n".ljust(12) + "family: ".ljust(10) + mycolors.reset + str(triagetext['extracted'][k][m][x]),end=' ')
                                        if ('rule' == x):
                                            print(mycolors.foreground.red + "\n".ljust(12) + "rule: ".ljust(10) + mycolors.reset + str(triagetext['extracted'][k][m][x]),end=' ')
                                        if ("extracted_pe" == x):
                                            print(mycolors.foreground.red + "\n".ljust(12) + "extracted_pe: ".ljust(9) + mycolors.reset,end=' ')
                                            for i in range(len(triagetext['extracted'][k][m][x])):
                                                print("\n".ljust(22) + str(triagetext['extracted'][k][m][x][i]),end=' ')
                                        if ('c2' == x):
                                            print(mycolors.foreground.red + "\n".ljust(12) + "c2: ".ljust(9) + mycolors.reset,end=' ')
                                            for z in range(len(triagetext['extracted'][k][m][x])):
                                                print("\n".ljust(22) + mycolors.reset + str(triagetext['extracted'][k][m][x][z]),end=' ')
                                        if ("botnet" == x):
                                            print(mycolors.foreground.red + "\n".ljust(12) + "botnet: ".ljust(10) + mycolors.reset + str(triagetext['extracted'][k][m][x]),end=' ')
                                        if ("keys" == x):
                                            for p in range(len(triagetext['extracted'][k][m][x])):
                                                for q in (triagetext['extracted'][k][m][x][p]).keys():
                                                    if ('key' == q):
                                                        print(mycolors.foreground.red + "\n".ljust(12) + "key: ".ljust(10) + mycolors.reset + str(triagetext['extracted'][k][m][x][p][q]),end=' ')
                                                    if ('value' == q):
                                                        print(mycolors.foreground.red + "\n".ljust(12) + "value:".ljust(10) + mycolors.reset,end='')
                                                        print(mycolors.reset + (("\n" + "".ljust(21)).join(textwrap.wrap((triagetext['extracted'][k][m][x][p][q]),width=80))),end=' ')


        print(mycolors.reset + "\n")
        exit(0)
    
    except ValueError as e:
        print(e)
        if (bkg == 1):
            print((mycolors.foreground.lightred + "\nError while connecting to Tri.age!\n"))
        else:
            print((mycolors.foreground.lightred + "\nError while connecting to Tri.age!\n"))
        print(mycolors.reset)


def triage_sample_submit(triagex, triage):

    triagetext = ''
    triageresponse = ''

    requestTRIAGEAPI()

    def encode_multipart_formdata(infodata):
        boundary = binascii.hexlify(os.urandom(16)).decode('ascii')

        body = BytesIO()
        for field, value in infodata.items():
            if isinstance(value, tuple):
                filename, file = value
                body.write('--{boundary}\r\nContent-Disposition: form-data; filename="{filename}"; name=\"{field}\"\r\n\r\n'.format(boundary=boundary, field=field, filename=filename).encode('utf-8'))
                b = file.read()
                if isinstance(b, str): 
                    b = b.encode('ascii')
                body.write(b)
                body.write(b'\r\n')
            else:
                body.write('--{boundary}\r\nContent-Disposition: form-data; name="{field}"\r\n\r\n{value}\r\n'.format(boundary=boundary, field=field, value=value).encode('utf-8'))
        body.write('--{0}--\r\n'.format(boundary).encode('utf-8'))
        body.seek(0)

        return body, "multipart/form-data; boundary=" + boundary

    try:

        print("\n")
        print((mycolors.reset + "TRIAGE SAMPLE SUBMIT REPORT".center(80)), end='')
        print((mycolors.reset + "".center(28)), end='')
        print("\n" + (80*'-').center(40))

        myfile = open(triagex,'rb')
        mydata = {
            'kind': 'file',
            'interactive': False,
        }

        filename = os.path.basename(triagex)
        mybody, content_type = encode_multipart_formdata({
            '_json': json.dumps(mydata),
            'file': (filename, myfile),
        })

        req = Request('POST', triage + 'samples', data=mybody, headers={"Content-Type": content_type, "Authorization": "Bearer " + TRIAGEAPI})
        requestsession = requests.Session( )
        triageres = requestsession.send(req.prepare())
        triagetext = triageres.json()

        if 'error' in triagetext:

            if triagetext['error'] == "UNAUTHORIZED":
                if (bkg == 1):
                    print(mycolors.foreground.lightred + "\nThe provided credential is not valid!\n" + mycolors.reset)
                else:
                    print(mycolors.foreground.red + "\nThe provided credential is not valid!\n" + mycolors.reset)
                exit(1)

            if triagetext['error'] == "INVALID_QUERY":
                if (bkg == 1):
                    print("\n" + mycolors.foreground.lightred + triagetext['message'] + mycolors.reset, end='\n\n')
                else:
                    print("\n" + mycolors.foreground.red + triagetext['message'] + mycolors.reset, end='\n\n')
                exit(1)

        if 'id' in triagetext:
            if (bkg == 1):
                print("\n" + mycolors.foreground.yellow + "id: ".ljust(12) + mycolors.reset + triagetext['id'], end=' ') 
                print("\n" + mycolors.foreground.yellow + "status: ".ljust(12) + mycolors.reset + triagetext['status'], end=' ') 
                print("\n" + mycolors.foreground.yellow + "filename: ".ljust(12) + mycolors.reset + triagetext['filename'], end=' ') 
                print("\n" + mycolors.foreground.yellow + "submitted: ".ljust(12) + mycolors.reset + triagetext['submitted'], end=' ') 
            if (bkg == 0):
                print("\n" + mycolors.foreground.blue + "id: ".ljust(12) + mycolors.reset + triagetext['id'], end=' ') 
                print("\n" + mycolors.foreground.blue + "status: ".ljust(12) + mycolors.reset + triagetext['status'], end=' ') 
                print("\n" + mycolors.foreground.blue + "filename: ".ljust(12) + mycolors.reset + triagetext['filename'], end=' ') 
                print("\n" + mycolors.foreground.blue + "submitted: ".ljust(12) + mycolors.reset + triagetext['submitted'], end=' ') 

        print(mycolors.reset + "\n")
        exit(0)
    
    except ValueError as e:
        print(e)
        if (bkg == 1):
            print((mycolors.foreground.lightred + "\nError while connecting to Tri.age!\n"))
        else:
            print((mycolors.foreground.lightred + "\nError while connecting to Tri.age!\n"))
        print(mycolors.reset)


def triage_url_sample_submit(triagex, triage):

    triagetext = ''
    triageresponse = ''

    requestTRIAGEAPI()

    try:

        print("\n")
        print((mycolors.reset + "TRIAGE URL SAMPLE SUBMIT REPORT".center(80)), end='')
        print((mycolors.reset + "".center(28)), end='')
        print("\n" + (80*'-').center(40))

        mydata = {
            'kind': 'fetch',
            'url': triagex,
            'interactive': False,
            }

        requestsession = requests.Session( )
        requestsession.headers.update({'accept':'application/json', 'Authorization':'Bearer ' + TRIAGEAPI, 'Content-Type': 'application/json'})
        triageresponse = requestsession.post(triage + 'samples', data=json.dumps(mydata))
        triagetext = json.loads(triageresponse.text)

        if 'error' in triagetext:

            if triagetext['error'] == "UNAUTHORIZED":
                if (bkg == 1):
                    print(mycolors.foreground.lightred + "\nThe provided credential is not valid!\n" + mycolors.reset)
                else:
                    print(mycolors.foreground.red + "\nThe provided credential is not valid!\n" + mycolors.reset)
                exit(1)
            
            if triagetext['error'] == "INVALID_QUERY":
                if (bkg == 1):
                    print("\n" + mycolors.foreground.lightred + triagetext['message'] + mycolors.reset, end='\n\n')
                else:
                    print("\n" + mycolors.foreground.red + triagetext['message'] + mycolors.reset, end='\n\n')
                exit(1)

        if 'id' in triagetext:
            if (bkg == 1):
                print("\n" + mycolors.foreground.yellow + "id: ".ljust(12) + mycolors.reset + triagetext['id'], end=' ') 
                print("\n" + mycolors.foreground.yellow + "status: ".ljust(12) + mycolors.reset + triagetext['status'], end=' ') 
                print("\n" + mycolors.foreground.yellow + "filename: ".ljust(12) + mycolors.reset + triagetext['filename'], end=' ') 
                print("\n" + mycolors.foreground.yellow + "submitted: ".ljust(12) + mycolors.reset + triagetext['submitted'], end=' ') 
            if (bkg == 0):
                print("\n" + mycolors.foreground.blue + "id: ".ljust(12) + mycolors.reset + triagetext['id'], end=' ') 
                print("\n" + mycolors.foreground.blue + "status: ".ljust(12) + mycolors.reset + triagetext['status'], end=' ') 
                print("\n" + mycolors.foreground.blue + "filename: ".ljust(12) + mycolors.reset + triagetext['filename'], end=' ') 
                print("\n" + mycolors.foreground.blue + "submitted: ".ljust(12) + mycolors.reset + triagetext['submitted'], end=' ') 


        print(mycolors.reset + "\n")
        exit(0)

    except ValueError as e:
        print(e)
        if (bkg == 1):
            print((mycolors.foreground.lightred + "\nError while connecting to Tri.age!\n"))
        else:
            print((mycolors.foreground.lightred + "\nError while connecting to Tri.age!\n"))
        print(mycolors.reset)


def triage_download(triagex, triage):

    triagetext = ''
    triageresponse = ''

    requestTRIAGEAPI()

    try:

        print("\n")
        print((mycolors.reset + "TRIAGE DOWNLOAD REPORT".center(80)), end='')
        print((mycolors.reset + "".center(28)), end='')
        print("\n" + (80*'-').center(40))

        requestsession = requests.Session( )
        requestsession.headers.update({'Authorization':'Bearer ' + TRIAGEAPI})
        triageresponse = requestsession.get(triage + 'samples/' + triagex + '/sample')
        if (triageresponse.status_code == 404):
            triagetext = json.loads(triageresponse.text)

        if 'error' in triagetext:
            if triagetext['error'] == "NOT_FOUND":
                if (bkg == 1):
                    print(mycolors.foreground.lightred + "\nThe provided ID was not found!\n" + mycolors.reset)
                else:
                    print(mycolors.foreground.red + "\nThe provided ID was not found!\n" + mycolors.reset)
                exit(1)

            if triagetext['error'] == "UNAUTHORIZED":
                if (bkg == 1):
                    print(mycolors.foreground.lightred + "\nThe provided credential is not valid!\n" + mycolors.reset)
                else:
                    print(mycolors.foreground.red + "\nThe provided credential is not valid!\n" + mycolors.reset)
                exit(1)
            
            if triagetext['error'] == "INVALID_QUERY":
                if (bkg == 1):
                    print("\n" + mycolors.foreground.lightred + triagetext['message'] + mycolors.reset, end='\n\n')
                else:
                    print("\n" + mycolors.foreground.red + triagetext['message'] + mycolors.reset, end='\n\n')
                exit(1)

        open(triagex + '.bin', 'wb').write(triageresponse.content)
        if (bkg == 1):
            print("\n" + mycolors.foreground.yellow + "SAMPLE SAVED as: " + triagex + ".bin" + mycolors.reset, end=' ')
        if (bkg == 0):
            print("\n" + mycolors.foreground.blue + "SAMPLE SAVED as: " + triagex + ".bin" + mycolors.reset, end=' ')

        print(mycolors.reset + "\n")
        exit(0)

    except ValueError as e:
        print(e)
        if (bkg == 1):
            print((mycolors.foreground.lightred + "\nError while connecting to Tri.age!\n"))
        else:
            print((mycolors.foreground.lightred + "\nError while connecting to Tri.age!\n"))
        print(mycolors.reset)


def triage_download_pcap(triagex, triage):

    triagetext = ''
    triageresponse = ''

    requestTRIAGEAPI()

    try:

        print("\n")
        print((mycolors.reset + "TRIAGE PCAPNG DOWNLOAD REPORT".center(80)), end='')
        print((mycolors.reset + "".center(28)), end='')
        print("\n" + (80*'-').center(40))

        requestsession = requests.Session( )
        requestsession.headers.update({'Authorization':'Bearer ' + TRIAGEAPI})
        triageresponse = requestsession.get(triage + 'samples/' + triagex + '/behavioral1/dump.pcapng')
        if (triageresponse.status_code == 404):
            triagetext = json.loads(triageresponse.text)

        if 'error' in triagetext:
            if triagetext['error'] == "NOT_FOUND":
                if (bkg == 1):
                    print(mycolors.foreground.lightred + "\nThe pcap file was not found!\n" + mycolors.reset)
                else:
                    print(mycolors.foreground.red + "\nThe pcap file was not found!\n" + mycolors.reset)
                exit(1)

            if triagetext['error'] == "UNAUTHORIZED":
                if (bkg == 1):
                    print(mycolors.foreground.lightred + "\nThe provided credential is not valid!\n" + mycolors.reset)
                else:
                    print(mycolors.foreground.red + "\nThe provided credential is not valid!\n" + mycolors.reset)
                exit(1)
            
            if triagetext['error'] == "INVALID_QUERY":
                if (bkg == 1):
                    print("\n" + mycolors.foreground.lightred + triagetext['message'] + mycolors.reset, end='\n\n')
                else:
                    print("\n" + mycolors.foreground.red + triagetext['message'] + mycolors.reset, end='\n\n')
                exit(1)

        open(triagex + '.pcapng', 'wb').write(triageresponse.content)
        if (bkg == 1):
            print("\n" + mycolors.foreground.yellow + "PCAP SAVED as: " + triagex + ".pcapng" + mycolors.reset, end=' ')
        if (bkg == 0):
            print("\n" + mycolors.foreground.blue + "PCAP SAVED as: " + triagex + ".pcapng" + mycolors.reset, end=' ')

        print(mycolors.reset + "\n")
        exit(0)

    except ValueError as e:
        print(e)
        if (bkg == 1):
            print((mycolors.foreground.lightred + "\nError while connecting to Tri.age!\n"))
        else:
            print((mycolors.foreground.lightred + "\nError while connecting to Tri.age!\n"))
        print(mycolors.reset)


def triage_dynamic(triagex, triage):

    triagetext = ''
    triageresponse = ''
    params = ''
    idx = ''

    requestTRIAGEAPI()

    try:

        print("\n")
        print((mycolors.reset + "TRIAGE DYNAMIC REPORT".center(100)), end='')
        print((mycolors.reset + "".center(28)), end='')
        print("\n" + (100*'-').center(50))

        requestsession = requests.Session( )
        requestsession.headers.update({'accept':'application/json', 'Authorization':'Bearer ' + TRIAGEAPI})
        triageresponse = requestsession.get(triage + 'samples/' +  triagex + '/behavioral1/report_triage.json')
        triagetext = json.loads(triageresponse.text)

        if 'error' in triagetext:
            if triagetext['error'] == "NOT_FOUND":
                if (bkg == 1):
                    print(mycolors.foreground.lightred + "\nThe provided ID was not found!\n" + mycolors.reset)
                else:
                    print(mycolors.foreground.red + "\nThe provided ID was not found!\n" + mycolors.reset)
                exit(1)

            if triagetext['error'] == "UNAUTHORIZED":
                if (bkg == 1):
                    print(mycolors.foreground.lightred + "\nThe provided credential is not valid!\n" + mycolors.reset)
                else:
                    print(mycolors.foreground.red + "\nThe provided credential is not valid!\n" + mycolors.reset)
                exit(1)
            
            if triagetext['error'] == "INVALID_QUERY":
                if (bkg == 1):
                    print("\n" + mycolors.foreground.lightred + triagetext['message'] + mycolors.reset, end='\n\n')
                else:
                    print("\n" + mycolors.foreground.red + triagetext['message'] + mycolors.reset, end='\n\n')
                exit(1)

        if (bkg == 1):
            for i in triagetext.keys():
                if (i == "sample"):
                    if (triagetext['sample'] is not None):
                        y = triagetext['sample'].keys()    
                        if ("id" in y):
                            print(mycolors.foreground.lightcyan + "\nid: ".ljust(12) + mycolors.reset + triagetext['sample']['id'],end=' ')

                        if ("target" in y):
                            print(mycolors.foreground.lightcyan + "\ntarget: ".ljust(12) + mycolors.reset + triagetext['sample']['target'], end=' ')

                        if ("score" in y):
                            print(mycolors.foreground.lightcyan + "\nscore: ".ljust(12) + mycolors.reset + str(triagetext['sample']['score']), end=' ')

                        if ("submitted" in y):
                            print(mycolors.foreground.lightcyan + "\nsubmitted: ".ljust(12) + mycolors.reset + triagetext['sample']['submitted'], end=' ')

                        if ("size" in y):
                            print(mycolors.foreground.lightcyan + "\nsize: ".ljust(12) + mycolors.reset + str(triagetext['sample']['size']), end=' ')

                        if ("md5" in y):
                            print(mycolors.foreground.lightcyan + "\nmd5: ".ljust(12) + mycolors.reset + triagetext['sample']['md5'], end=' ')

                        if ("sha1" in y):
                            print(mycolors.foreground.lightcyan + "\nsha1: ".ljust(12) + mycolors.reset + triagetext['sample']['sha1'], end=' ')

                        if ("sha256" in y):
                            print(mycolors.foreground.lightcyan + "\nsha256: ".ljust(12) + mycolors.reset + triagetext['sample']['sha256'], end=' ')

                        print(mycolors.foreground.lightcyan + "\nstatic_tags: ".ljust(12) + mycolors.reset, end=' ')
                        if ("static_tags" in triagetext[i]):
                            for j in triagetext[i]['static_tags']:
                                print("\n".ljust(12) +  mycolors.reset + j, end=' ')

                if (i == "analysis"):
                    if (triagetext[i] is not None):
                        print(mycolors.foreground.lightcyan + "\n\nanalysis: ".ljust(11) + mycolors.reset,end=' ')
                        if ("score" in triagetext[i]):
                            print(mycolors.foreground.lightred + "\n".ljust(12) + "score: ".ljust(10)+ mycolors.reset + str(triagetext[i]['score']), end=' ')
                        if ("reported" in triagetext[i]):
                            print(mycolors.foreground.lightred + "\n".ljust(12) + "reported: ".ljust(10) + mycolors.reset + triagetext[i]['reported'], end=' ')
                        if ("platform" in triagetext[i]):
                            print(mycolors.foreground.lightred + "\n".ljust(12) + "platform: ".ljust(10) + mycolors.reset + str(triagetext[i]['platform']), end=' ')
                        if ("resource" in triagetext[i]):
                            print(mycolors.foreground.lightred + "\n".ljust(12) + "resource: ".ljust(10) + mycolors.reset + triagetext[i]['resource'], end=' ')
                        if ("max_time_network" in triagetext[i]):
                            print(mycolors.foreground.lightred + "\n".ljust(12) + "time_net: ".ljust(8) + mycolors.reset + str(triagetext[i]['max_time_network']), end=' ')
                        if ("max_time_kernel" in triagetext[i]):
                            print(mycolors.foreground.lightred + "\n".ljust(12) + "time_krn: ".ljust(8) + mycolors.reset + str(triagetext[i]['max_time_kernel']), end=' ')

                        print(mycolors.foreground.lightred + "\n".ljust(12) + "tags: ".ljust(10) + mycolors.reset, end=' ')
                        if ("tags" in triagetext[i]):
                            for j in triagetext[i]['tags']:
                                print("\n".ljust(22) +  mycolors.reset + j, end=' ')
                        
                        print(mycolors.foreground.lightred + "\n".ljust(12) + "ttps: ".ljust(10) + mycolors.reset, end=' ')
                        if ("ttp" in triagetext[i]):
                            for j in triagetext[i]['ttp']:
                                print("\n".ljust(22) +  mycolors.reset + j, end=' ')

                        print(mycolors.foreground.lightred + "\n".ljust(12) + "features: ".ljust(10) + mycolors.reset, end=' ')
                        if ("features" in triagetext[i]):
                            for j in triagetext[i]['features']:
                                print("\n".ljust(22) +  mycolors.reset + j, end=' ')
                            
                        print(mycolors.reset + "")


                if (i == "processes"):
                    if (triagetext[i] is not None):
                        print(mycolors.foreground.lightcyan + "\nprocesses: ".ljust(12) + mycolors.reset,end=' ')
                        for k in range(len(triagetext[i])):
                            for m in (triagetext[i][k]):
                                if ("pid" == m):
                                    print(mycolors.foreground.lightred + "\n".ljust(12) + "pid: ".ljust(10) + mycolors.reset + str(triagetext[i][k][m]),end=' ')
                                if ("ppid" == m):
                                    print(mycolors.foreground.lightred + "\n".ljust(12) + "ppid: ".ljust(10) + mycolors.reset + str(triagetext[i][k][m]),end=' ')
                                if ("procid" == m):
                                    print(mycolors.foreground.lightred + "\n".ljust(12) + "procid: ".ljust(10) + mycolors.reset + str(triagetext[i][k][m]),end=' ')
                                if ("procid_parent" == m):
                                    print(mycolors.foreground.lightred + "\n".ljust(12) + "procid_p: ".ljust(10) + mycolors.reset + str(triagetext[i][k][m]),end=' ')
                                if ("cmd" == m):
                                    print(mycolors.foreground.lightred + "\n".ljust(12) + "cmd: ".ljust(10) + mycolors.reset + (("\n".ljust(22)).join(textwrap.wrap(str(triagetext[i][k][m]),width=90))),end=' ')
                                if ("image" == m):
                                    print(mycolors.foreground.lightred + "\n".ljust(12) + "image: ".ljust(10) + mycolors.reset + str(triagetext[i][k][m]),end=' ')
                            print(mycolors.reset + "")

                if (i == "signatures"):
                    if (triagetext[i] is not None):
                        print(mycolors.foreground.lightcyan + "\nsignatures: ".ljust(12) + mycolors.reset,end=' ')
                        for y in range(len(triagetext[i])):
                            for d in (triagetext[i][y]).keys():
                                if (d == 'name'):
                                    print(mycolors.foreground.lightred + "\n".ljust(12) + mycolors.reset + str(triagetext[i][y][d]),end=' ')
                        print(mycolors.reset + "")

                    if (triagetext[i] is not None):
                        list_1 = []
                        set_1 = ()
                        print(mycolors.foreground.lightcyan + "\n".ljust(12) + "iocs: ".ljust(10) + mycolors.reset,end='')
                        for y in range(len(triagetext[i])):
                            for d in (triagetext[i][y]).keys():
                                if (d == 'indicators'):
                                    for z in range(len(triagetext[i][y][d])):
                                        for t in (triagetext[i][y][d][z]).keys():
                                            if (t == 'ioc'):
                                                list_1.append(triagetext[i][y][d][z][t])
                        set_1 = set(list_1)
                        final_list = (list(set_1))
                        for w in final_list:
                            print("\n".ljust(17) + mycolors.reset + (("\n".ljust(19)).join(textwrap.wrap("* " + w,width=90))),end=' ')

                if (i == "network"):
                        list_1 = []
                        set_1 = ()
                        print(mycolors.foreground.lightcyan + "\nnetwork: ".ljust(12) + mycolors.reset,end='')
                        for d in (triagetext[i]).keys():
                            if (d == 'flows'):
                                for z in range(len(triagetext[i][d])):
                                    for t in (triagetext[i][d][z]).keys():
                                        if (t == 'domain'):
                                            list_1.append(triagetext[i][d][z][t])
                        set_1 = set(list_1)
                        final_list = (list(set_1))
                        for w in final_list:
                            print("\n".ljust(12) + mycolors.reset + (("\n".ljust(12)).join(textwrap.wrap(w,width=90))),end=' ')

                        print(mycolors.reset + "")


        if (bkg == 0):
            for i in triagetext.keys():
                if (i == "sample"):
                    if (triagetext['sample'] is not None):
                        y = triagetext['sample'].keys()    
                        if ("id" in y):
                            print(mycolors.foreground.purple + "\nid: ".ljust(12) + mycolors.reset + triagetext['sample']['id'],end=' ')

                        if ("target" in y):
                            print(mycolors.foreground.purple + "\ntarget: ".ljust(12) + mycolors.reset + triagetext['sample']['target'], end=' ')

                        if ("score" in y):
                            print(mycolors.foreground.purple + "\nscore: ".ljust(12) + mycolors.reset + str(triagetext['sample']['score']), end=' ')

                        if ("submitted" in y):
                            print(mycolors.foreground.purple + "\nsubmitted: ".ljust(12) + mycolors.reset + triagetext['sample']['submitted'], end=' ')

                        if ("size" in y):
                            print(mycolors.foreground.purple + "\nsize: ".ljust(12) + mycolors.reset + str(triagetext['sample']['size']), end=' ')

                        if ("md5" in y):
                            print(mycolors.foreground.purple + "\nmd5: ".ljust(12) + mycolors.reset + triagetext['sample']['md5'], end=' ')

                        if ("sha1" in y):
                            print(mycolors.foreground.purple + "\nsha1: ".ljust(12) + mycolors.reset + triagetext['sample']['sha1'], end=' ')

                        if ("sha256" in y):
                            print(mycolors.foreground.purple + "\nsha256: ".ljust(12) + mycolors.reset + triagetext['sample']['sha256'], end=' ')

                        print(mycolors.foreground.purple + "\nstatic_tags: ".ljust(12) + mycolors.reset, end=' ')
                        if ("static_tags" in triagetext[i]):
                            for j in triagetext[i]['static_tags']:
                                print("\n".ljust(12) +  mycolors.reset + j, end=' ')

                if (i == "analysis"):
                    if (triagetext[i] is not None):
                        print(mycolors.foreground.purple + "\n\nanalysis: ".ljust(11) + mycolors.reset,end=' ')
                        if ("score" in triagetext[i]):
                            print(mycolors.foreground.red + "\n".ljust(12) + "score: ".ljust(10)+ mycolors.reset + str(triagetext[i]['score']), end=' ')
                        if ("reported" in triagetext[i]):
                            print(mycolors.foreground.red + "\n".ljust(12) + "reported: ".ljust(10) + mycolors.reset + triagetext[i]['reported'], end=' ')
                        if ("platform" in triagetext[i]):
                            print(mycolors.foreground.red + "\n".ljust(12) + "platform: ".ljust(10) + mycolors.reset + str(triagetext[i]['platform']), end=' ')
                        if ("resource" in triagetext[i]):
                            print(mycolors.foreground.red + "\n".ljust(12) + "resource: ".ljust(10) + mycolors.reset + triagetext[i]['resource'], end=' ')
                        if ("max_time_network" in triagetext[i]):
                            print(mycolors.foreground.red + "\n".ljust(12) + "time_net: ".ljust(8) + mycolors.reset + str(triagetext[i]['max_time_network']), end=' ')
                        if ("max_time_kernel" in triagetext[i]):
                            print(mycolors.foreground.red + "\n".ljust(12) + "time_krn: ".ljust(8) + mycolors.reset + str(triagetext[i]['max_time_kernel']), end=' ')

                        print(mycolors.foreground.red + "\n".ljust(12) + "tags: ".ljust(10) + mycolors.reset, end=' ')
                        if ("tags" in triagetext[i]):
                            for j in triagetext[i]['tags']:
                                print("\n".ljust(22) +  mycolors.reset + j, end=' ')
                        
                        print(mycolors.foreground.red + "\n".ljust(12) + "ttps: ".ljust(10) + mycolors.reset, end=' ')
                        if ("ttp" in triagetext[i]):
                            for j in triagetext[i]['ttp']:
                                print("\n".ljust(22) +  mycolors.reset + j, end=' ')

                        print(mycolors.foreground.red + "\n".ljust(12) + "features: ".ljust(10) + mycolors.reset, end=' ')
                        if ("features" in triagetext[i]):
                            for j in triagetext[i]['features']:
                                print("\n".ljust(22) +  mycolors.reset + j, end=' ')
                            
                        print(mycolors.reset + "")


                if (i == "processes"):
                    if (triagetext[i] is not None):
                        print(mycolors.foreground.purple + "\nprocesses: ".ljust(12) + mycolors.reset,end=' ')
                        for k in range(len(triagetext[i])):
                            for m in (triagetext[i][k]):
                                if ("pid" == m):
                                    print(mycolors.foreground.red + "\n".ljust(12) + "pid: ".ljust(10) + mycolors.reset + str(triagetext[i][k][m]),end=' ')
                                if ("ppid" == m):
                                    print(mycolors.foreground.red + "\n".ljust(12) + "ppid: ".ljust(10) + mycolors.reset + str(triagetext[i][k][m]),end=' ')
                                if ("procid" == m):
                                    print(mycolors.foreground.red + "\n".ljust(12) + "procid: ".ljust(10) + mycolors.reset + str(triagetext[i][k][m]),end=' ')
                                if ("procid_parent" == m):
                                    print(mycolors.foreground.red + "\n".ljust(12) + "procid_p: ".ljust(10) + mycolors.reset + str(triagetext[i][k][m]),end=' ')
                                if ("cmd" == m):
                                    print(mycolors.foreground.red + "\n".ljust(12) + "cmd: ".ljust(10) + mycolors.reset + (("\n".ljust(22)).join(textwrap.wrap(str(triagetext[i][k][m]),width=90))),end=' ')
                                if ("image" == m):
                                    print(mycolors.foreground.red + "\n".ljust(12) + "image: ".ljust(10) + mycolors.reset + str(triagetext[i][k][m]),end=' ')
                            print(mycolors.reset + "")

                if (i == "signatures"):
                    if (triagetext[i] is not None):
                        print(mycolors.foreground.purple + "\nsignatures: ".ljust(12) + mycolors.reset,end=' ')
                        for y in range(len(triagetext[i])):
                            for d in (triagetext[i][y]).keys():
                                if (d == 'name'):
                                    print(mycolors.foreground.red + "\n".ljust(12) + mycolors.reset + str(triagetext[i][y][d]),end=' ')
                        print(mycolors.reset + "")

                    if (triagetext[i] is not None):
                        list_1 = []
                        set_1 = ()
                        print(mycolors.foreground.purple + "\n".ljust(12) + "iocs: ".ljust(10) + mycolors.reset,end='')
                        for y in range(len(triagetext[i])):
                            for d in (triagetext[i][y]).keys():
                                if (d == 'indicators'):
                                    for z in range(len(triagetext[i][y][d])):
                                        for t in (triagetext[i][y][d][z]).keys():
                                            if (t == 'ioc'):
                                                list_1.append(triagetext[i][y][d][z][t])
                        set_1 = set(list_1)
                        final_list = (list(set_1))
                        for w in final_list:
                            print("\n".ljust(17) + mycolors.reset + (("\n".ljust(19)).join(textwrap.wrap("* " + w,width=90))),end=' ')

                if (i == "network"):
                        list_1 = []
                        set_1 = ()
                        print(mycolors.foreground.purple + "\nnetwork: ".ljust(12) + mycolors.reset,end='')
                        for d in (triagetext[i]).keys():
                            if (d == 'flows'):
                                for z in range(len(triagetext[i][d])):
                                    for t in (triagetext[i][d][z]).keys():
                                        if (t == 'domain'):
                                            list_1.append(triagetext[i][d][z][t])
                        set_1 = set(list_1)
                        final_list = (list(set_1))
                        for w in final_list:
                            print("\n".ljust(12) + mycolors.reset + (("\n".ljust(12)).join(textwrap.wrap(w,width=90))),end=' ')

                        print(mycolors.reset + "")


        print(mycolors.reset + "\n")
        exit(0)

    except ValueError as e:
        print(e)
        if (bkg == 1):
            print((mycolors.foreground.lightred + "\nError while connecting to Tri.age!\n"))
        else:
            print((mycolors.foreground.lightred + "\nError while connecting to Tri.age!\n"))
        print(mycolors.reset)


def inquest_download(inquestx, inquest):

    inquestext = ''
    inquestresponse = ''

    requestINQUESTAPI()

    try:

        print("\n")
        print((mycolors.reset + "INQUEST DOWNLOAD REPORT".center(80)), end='')
        print((mycolors.reset + "".center(28)), end='')
        print("\n" + (86*'-').center(43))

        if(not inquestx):
            if (bkg == 1):
                print(mycolors.foreground.lightred + "\nThe -I parameter with the provided SHA256 hash is required!\n" + mycolors.reset)
            else:
                print(mycolors.foreground.red + "\nThe -I parameter with the provided SHA256 hash is required!\n" + mycolors.reset)
            exit(1)

        requestsession = requests.Session( )
        requestsession.headers.update({'Accept': 'application/octet-stream'})
        requestsession.headers.update({'Authorization':INQUESTAPI})
        inquestresponse = requestsession.get(inquest + '/download?sha256=' + inquestx)

        if (inquestresponse.status_code == 400):
            inquesttext = json.loads(inquestresponse.text)

            if 'error' in inquesttext:
                if inquesttext['error'] == "Supplied 'sha256' value is not a valid hash.":
                    if (bkg == 1):
                        print(mycolors.foreground.lightred + "\nThe provided SHA256 hash is not valid!\n" + mycolors.reset)
                    else:
                        print(mycolors.foreground.red + "\nThe provided SHA256 hash is not valid!\n" + mycolors.reset)
                    exit(1)

        open(inquestx + '.bin', 'wb').write(inquestresponse.content)
        if (bkg == 1):
            print("\n" + mycolors.foreground.yellow + "SAMPLE SAVED as: " + inquestx + ".bin" + mycolors.reset, end=' ')
        if (bkg == 0):
            print("\n" + mycolors.foreground.blue + "SAMPLE SAVED as: " + inquestx + ".bin" + mycolors.reset, end=' ')

        print(mycolors.reset + "\n")
        exit(0)

    except ValueError as e:
        print(e)
        if (bkg == 1):
            print((mycolors.foreground.lightred + "\nError while connecting to InQuest!\n"))
        else:
            print((mycolors.foreground.lightred + "\nError while connecting to InQuest!\n"))
        print(mycolors.reset)


def inquest_hash(inquestx, inquest):

    inquestext = ''
    inquestresponse = ''

    requestINQUESTAPI()

    try:

        print("\n")
        print((mycolors.reset + "INQUEST SAMPLE REPORT".center(80)), end='')
        print((mycolors.reset + "".center(28)), end='')
        print("\n" + (86*'-').center(43))

        if(not inquestx):
            if (bkg == 1):
                print(mycolors.foreground.lightred + "\nThe -I parameter with the provided SHA256 hash is required!\n" + mycolors.reset)
            else:
                print(mycolors.foreground.red + "\nThe -I parameter with the provided SHA256 hash is required!\n" + mycolors.reset)
            exit(1)

        requestsession = requests.Session( )
        requestsession.headers.update({'Accept': 'application/json'})
        requestsession.headers.update({'Authorization':INQUESTAPI})
        inquestresponse = requestsession.get(inquest + '/search/hash/sha256?hash=' + inquestx)
        inquesttext = json.loads(inquestresponse.text)

        if (inquestresponse.status_code == 400 or inquestresponse.status_code == 500):
            inquesttext = json.loads(inquestresponse.text)

            if 'error' in inquesttext:
                if inquesttext['error'] == "The 'source' parameter must be one of md5, sha1, sha256, sha512":
                    if (bkg == 1):
                        print(mycolors.foreground.lightred + "\nThe provided hash is not a SHA256 hash!\n" + mycolors.reset)
                    else:
                        print(mycolors.foreground.red + "\nThe provided hash is not a SHA256 hash!\n" + mycolors.reset)
                    exit(1)

            if inquesttext['error'] == "Invalid SHA256 hash supplied.":
                if (bkg == 1):
                    print(mycolors.foreground.lightred + "\nThe provided SHA256 hash is not valid!\n" + mycolors.reset)
                else:
                    print(mycolors.foreground.red + "\nThe provided SHA256 hash is not valid!\n" + mycolors.reset)
                exit(1)

        if (bkg == 1):
            for i in inquesttext.keys():
                if (i == "data"):
                    if (inquesttext['data'] is not None):
                        for d in inquesttext['data']:
                            y = d.keys()    
                            if ("sha256" in y):
                                if d['sha256']:
                                    print(mycolors.foreground.lightcyan + "\nsha256: ".ljust(20) + mycolors.reset + d['sha256'],end=' ')

                            if ("classification" in y):
                                if d['classification']:
                                    print(mycolors.foreground.lightcyan + "\nclassification: ".ljust(20) + mycolors.reset + d['classification'], end=' ')

                            if ("file_type" in y):
                                if d['file_type']:
                                    print(mycolors.foreground.lightcyan + "\nfile type: ".ljust(20) + mycolors.reset + d['file_type'], end=' ')

                            if ("first_seen" in y):
                                if d['first_seen']:
                                    print(mycolors.foreground.lightcyan + "\nfirst seen: ".ljust(20) + mycolors.reset + d['first_seen'], end=' ')

                            if ("downloadable" in y):
                                if d['downloadable']:
                                    print(mycolors.foreground.lightcyan + "\ndownloadable: ".ljust(20) + mycolors.reset + str(d['downloadable']), end=' ')

                            if ("size" in y):
                                if d['size']:
                                    print(mycolors.foreground.lightcyan + "\nsize: ".ljust(20) + mycolors.reset + str(d['size']), end=' ')

                            if ("vt_positives" in y):
                                if d['vt_positives']:
                                    print(mycolors.foreground.lightcyan + "\nvt positives: ".ljust(20) + mycolors.reset + str(d['vt_positives']), end=' ')

                            if ("vt_weight" in y):
                                if d['vt_weight']:
                                    print(mycolors.foreground.lightcyan + "\nvt weight: ".ljust(20) + mycolors.reset + str(d['vt_weight']), end=' ')

                            if ("inquest_alerts" in y):
                                if (d['inquest_alerts']):
                                    print(mycolors.foreground.lightcyan + "\ninquest alerts:", end=' ')
                                    for j in d['inquest_alerts']:
                                        print('\n')
                                        for k in j:
                                            print(mycolors.foreground.yellow + "".ljust(19) + k + ":\t" + mycolors.reset  + (("\n" + " ".ljust(32)).join(textwrap.wrap(str(j[k]), width=80))), end="\n")
                            print('\n')

        if (bkg == 0):
            for i in inquesttext.keys():
                if (i == "data"):
                    if (inquesttext['data'] is not None):
                        for d in inquesttext['data']:
                            y = d.keys()    
                            if ("sha256" in y):
                                if d['sha256']:
                                    print(mycolors.foreground.blue + "\nsha256: ".ljust(20) + mycolors.reset + d['sha256'],end=' ')

                            if ("classification" in y):
                                if d['classification']:
                                    print(mycolors.foreground.blue + "\nclassification: ".ljust(20) + mycolors.reset + d['classification'], end=' ')

                            if ("file_type" in y):
                                if d['file_type']:
                                    print(mycolors.foreground.blue + "\nfile type: ".ljust(20) + mycolors.reset + d['file_type'], end=' ')

                            if ("first_seen" in y):
                                if d['first_seen']:
                                    print(mycolors.foreground.blue + "\nfirst seen: ".ljust(20) + mycolors.reset + d['first_seen'], end=' ')

                            if ("downloadable" in y):
                                if d['downloadable']:
                                    print(mycolors.foreground.blue + "\ndownloadable: ".ljust(20) + mycolors.reset + str(d['downloadable']), end=' ')

                            if ("size" in y):
                                if d['size']:
                                    print(mycolors.foreground.blue + "\nsize: ".ljust(20) + mycolors.reset + str(d['size']), end=' ')

                            if ("vt_positives" in y):
                                if d['vt_positives']:
                                    print(mycolors.foreground.blue + "\nvt positives: ".ljust(20) + mycolors.reset + str(d['vt_positives']), end=' ')

                            if ("vt_weight" in y):
                                if d['vt_weight']:
                                    print(mycolors.foreground.blue + "\nvt weight: ".ljust(20) + mycolors.reset + str(d['vt_weight']), end=' ')

                            if ("inquest_alerts" in y):
                                if (d['inquest_alerts']):
                                    print(mycolors.foreground.blue + "\ninquest alerts:", end=' ')
                                    for j in d['inquest_alerts']:
                                        print('\n')
                                        for k in j:
                                            print(mycolors.foreground.cyan + "".ljust(19) + k + ":\t" + mycolors.reset  + (("\n" + " ".ljust(32)).join(textwrap.wrap(str(j[k]), width=80))), end="\n")
                            print('\n')

    except ValueError as e:
        print(e)
        if (bkg == 1):
            print((mycolors.foreground.lightred + "\nError while connecting to InQuest!\n"))
        else:
            print((mycolors.foreground.lightred + "\nError while connecting to InQuest!\n"))


def inquest_hash_md5(inquestx, inquest):

    inquestext = ''
    inquestresponse = ''

    requestINQUESTAPI()

    try:

        print("\n")
        print((mycolors.reset + "INQUEST SAMPLE REPORT".center(80)), end='')
        print((mycolors.reset + "".center(28)), end='')
        print("\n" + (86*'-').center(43))

        if(not inquestx):
            if (bkg == 1):
                print(mycolors.foreground.lightred + "\nThe -I parameter with the provided SHA256 hash is required!\n" + mycolors.reset)
            else:
                print(mycolors.foreground.red + "\nThe -I parameter with the provided SHA256 hash is required!\n" + mycolors.reset)
            exit(1)

        requestsession = requests.Session( )
        requestsession.headers.update({'Accept': 'application/json'})
        requestsession.headers.update({'Authorization':INQUESTAPI})
        inquestresponse = requestsession.get(inquest + '/search/hash/md5?hash=' + inquestx)
        inquesttext = json.loads(inquestresponse.text)

        if (inquestresponse.status_code == 400 or inquestresponse.status_code == 500):
            inquesttext = json.loads(inquestresponse.text)

            if 'error' in inquesttext:
                if inquesttext['error'] == "The 'source' parameter must be one of md5, sha1, sha256, sha512":
                    if (bkg == 1):
                        print(mycolors.foreground.lightred + "\nThe provided hash is not a MD5 hash!\n" + mycolors.reset)
                    else:
                        print(mycolors.foreground.red + "\nThe provided hash is not a MD5 hash!\n" + mycolors.reset)
                    exit(1)

            if inquesttext['error'] == "Invalid MD5 hash supplied.":
                if (bkg == 1):
                    print(mycolors.foreground.lightred + "\nThe provided MD5 hash is not valid!\n" + mycolors.reset)
                else:
                    print(mycolors.foreground.red + "\nThe provided MD5 hash is not valid!\n" + mycolors.reset)
                exit(1)

        if (bkg == 1):
            for i in inquesttext.keys():
                if (i == "data"):
                    if (inquesttext['data'] is not None):
                        for d in inquesttext['data']:
                            y = d.keys()    
                            if ("sha256" in y):
                                if d['sha256']:
                                    print(mycolors.foreground.lightcyan + "\nsha256: ".ljust(20) + mycolors.reset + d['sha256'],end=' ')
                            
                            if ("classification" in y):
                                if d['classification']:
                                    print(mycolors.foreground.lightcyan + "\nclassification: ".ljust(20) + mycolors.reset + d['classification'], end=' ')

                            if ("file_type" in y):
                                if d['file_type']:
                                    print(mycolors.foreground.lightcyan + "\nfile type: ".ljust(20) + mycolors.reset + d['file_type'], end=' ')

                            if ("first_seen" in y):
                                if d['first_seen']:
                                    print(mycolors.foreground.lightcyan + "\nfirst seen: ".ljust(20) + mycolors.reset + d['first_seen'], end=' ')

                            if ("downloadable" in y):
                                if d['downloadable']:
                                    print(mycolors.foreground.lightcyan + "\ndownloadable: ".ljust(20) + mycolors.reset + str(d['downloadable']), end=' ')

                            if ("size" in y):
                                if d['size']:
                                    print(mycolors.foreground.lightcyan + "\nsize: ".ljust(20) + mycolors.reset + str(d['size']), end=' ')

                            if ("vt_positives" in y):
                                if d['vt_positives']:
                                    print(mycolors.foreground.lightcyan + "\nvt positives: ".ljust(20) + mycolors.reset + str(d['vt_positives']), end=' ')

                            if ("vt_weight" in y):
                                if d['vt_weight']:
                                    print(mycolors.foreground.lightcyan + "\nvt weight: ".ljust(20) + mycolors.reset + str(d['vt_weight']), end=' ')

                            if ("inquest_alerts" in y):
                                if (d['inquest_alerts']):
                                    print(mycolors.foreground.lightcyan + "\ninquest alerts:", end=' ')
                                    for j in d['inquest_alerts']:
                                        print('\n')
                                        for k in j:
                                            print(mycolors.foreground.yellow + "".ljust(19) + k + ":\t" + mycolors.reset  + (("\n" + " ".ljust(32)).join(textwrap.wrap(str(j[k]), width=80))), end="\n")
                            print('\n')

        if (bkg == 0):
            for i in inquesttext.keys():
                if (i == "data"):
                    if (inquesttext['data'] is not None):
                        for d in inquesttext['data']:
                            y = d.keys()    
                            if ("sha256" in y):
                                if d['sha256']:
                                    print(mycolors.foreground.blue + "\nsha256: ".ljust(20) + mycolors.reset + d['sha256'],end=' ')
                            
                            if ("classification" in y):
                                if d['classification']:
                                    print(mycolors.foreground.blue + "\nclassification: ".ljust(20) + mycolors.reset + d['classification'], end=' ')

                            if ("file_type" in y):
                                if d['file_type']:
                                    print(mycolors.foreground.blue + "\nfile type: ".ljust(20) + mycolors.reset + d['file_type'], end=' ')

                            if ("first_seen" in y):
                                if d['first_seen']:
                                    print(mycolors.foreground.blue + "\nfirst seen: ".ljust(20) + mycolors.reset + d['first_seen'], end=' ')

                            if ("downloadable" in y):
                                if d['downloadable']:
                                    print(mycolors.foreground.blue + "\ndownloadable: ".ljust(20) + mycolors.reset + str(d['downloadable']), end=' ')

                            if ("size" in y):
                                if d['size']:
                                    print(mycolors.foreground.blue + "\nsize: ".ljust(20) + mycolors.reset + str(d['size']), end=' ')

                            if ("vt_positives" in y):
                                if d['vt_positives']:
                                    print(mycolors.foreground.blue + "\nvt positives: ".ljust(20) + mycolors.reset + str(d['vt_positives']), end=' ')

                            if ("vt_weight" in y):
                                if d['vt_weight']:
                                    print(mycolors.foreground.blue + "\nvt weight: ".ljust(20) + mycolors.reset + str(d['vt_weight']), end=' ')

                            if ("inquest_alerts" in y):
                                if (d['inquest_alerts']):
                                    print(mycolors.foreground.blue + "\ninquest alerts:", end=' ')
                                    for j in d['inquest_alerts']:
                                        print('\n')
                                        for k in j:
                                            print(mycolors.foreground.cyan + "".ljust(19) + k + ":\t" + mycolors.reset  + (("\n" + " ".ljust(32)).join(textwrap.wrap(str(j[k]), width=80))), end="\n")
                            print('\n')

    except ValueError as e:
        print(e)
        if (bkg == 1):
            print((mycolors.foreground.lightred + "\nError while connecting to InQuest!\n"))
        else:
            print((mycolors.foreground.lightred + "\nError while connecting to InQuest!\n"))



def inquest_list(inquestx, inquest):

    inquestext = ''
    inquestresponse = ''

    requestINQUESTAPI()

    try:

        print("\n")
        print((mycolors.reset + "INQUEST LIST REPORT".center(110)), end='')
        print((mycolors.reset + "".center(28)), end='')
        print("\n" + (110*'-').center(55))

        if(not inquestx == "list"):
            if (bkg == 1):
                print(mycolors.foreground.lightred + "\nThe word 'list' (no single quotes) must be provided as -I parameter!\n" + mycolors.reset)
            else:
                print(mycolors.foreground.red + "\nThe word 'list' (no single quotes) must be provided as -I parameter!\n" + mycolors.reset)
            exit(1)

        requestsession = requests.Session( )
        requestsession.headers.update({'Accept': 'application/json'})
        requestsession.headers.update({'Authorization':INQUESTAPI})
        inquestresponse = requestsession.get(inquest + "/" + inquestx)
        inquesttext = json.loads(inquestresponse.text)

        if (bkg == 1):
            for i in inquesttext.keys():
                if (i == "data"):
                    if (inquesttext['data'] is not None):
                        for d in inquesttext['data']:
                            y = d.keys()    
                            print("\n" + (110*'-').center(55), end=' ')
                            if ("sha256" in y):
                                if d['sha256']:
                                    print(mycolors.foreground.lightblue + "\nsha256: ".ljust(20) + mycolors.reset + d['sha256'],end=' ')

                            if ("classification" in y):
                                if d['classification']:
                                    print(mycolors.foreground.lightblue + "\nclassification: ".ljust(20) + mycolors.reset + d['classification'], end=' ')

                            if ("file_type" in y):
                                if d['file_type']:
                                    print(mycolors.foreground.lightblue + "\nfile type: ".ljust(20) + mycolors.reset + d['file_type'], end=' ')

                            if ("first_seen" in y):
                                if d['first_seen']:
                                    print(mycolors.foreground.lightblue + "\nfirst seen: ".ljust(20) + mycolors.reset + d['first_seen'], end=' ')

                            if ("downloadable" in y):
                                if d['downloadable']:
                                    print(mycolors.foreground.lightblue + "\ndownloadable: ".ljust(20) + mycolors.reset + str(d['downloadable']), end=' ')

                            if ("size" in y):
                                if d['size']:
                                    print(mycolors.foreground.lightblue + "\nsize: ".ljust(20) + mycolors.reset + str(d['size']), end=' ')

                            if ("vt_positives" in y):
                                if d['vt_positives']:
                                    print(mycolors.foreground.lightblue + "\nvt positives: ".ljust(20) + mycolors.reset + str(d['vt_positives']), end=' ')

                            if ("vt_weight" in y):
                                if d['vt_weight']:
                                    print(mycolors.foreground.lightblue + "\nvt weight: ".ljust(20) + mycolors.reset + str(d['vt_weight']), end=' ')

                            if ("inquest_alerts" in y):
                                if (d['inquest_alerts']):
                                    print(mycolors.foreground.lightblue + "\ninquest alerts:", end=' ')
                                    for j in d['inquest_alerts']:
                                        print('\n')
                                        for k in j:
                                            print(mycolors.foreground.orange + "".ljust(19) + k + ":\t" + mycolors.reset  + (("\n" + " ".ljust(32)).join(textwrap.wrap(str(j[k]), width=80))), end="\n")


        if (bkg == 0):
            for i in inquesttext.keys():
                if (i == "data"):
                    if (inquesttext['data'] is not None):
                        for d in inquesttext['data']:
                            y = d.keys()    
                            print("\n" + (110*'-').center(55), end=' ')
                            if ("sha256" in y):
                                if d['sha256']:
                                    print(mycolors.foreground.red + "\nsha256: ".ljust(20) + mycolors.reset + d['sha256'],end=' ')

                            if ("classification" in y):
                                if d['classification']:
                                    print(mycolors.foreground.red + "\nclassification: ".ljust(20) + mycolors.reset + d['classification'], end=' ')

                            if ("file_type" in y):
                                if d['file_type']:
                                    print(mycolors.foreground.red + "\nfile type: ".ljust(20) + mycolors.reset + d['file_type'], end=' ')

                            if ("first_seen" in y):
                                if d['first_seen']:
                                    print(mycolors.foreground.red + "\nfirst seen: ".ljust(20) + mycolors.reset + d['first_seen'], end=' ')

                            if ("downloadable" in y):
                                if d['downloadable']:
                                    print(mycolors.foreground.red + "\ndownloadable: ".ljust(20) + mycolors.reset + str(d['downloadable']), end=' ')

                            if ("size" in y):
                                if d['size']:
                                    print(mycolors.foreground.red + "\nsize: ".ljust(20) + mycolors.reset + str(d['size']), end=' ')

                            if ("vt_positives" in y):
                                if d['vt_positives']:
                                    print(mycolors.foreground.red + "\nvt positives: ".ljust(20) + mycolors.reset + str(d['vt_positives']), end=' ')

                            if ("vt_weight" in y):
                                if d['vt_weight']:
                                    print(mycolors.foreground.red + "\nvt weight: ".ljust(20) + mycolors.reset + str(d['vt_weight']), end=' ')

                            if ("inquest_alerts" in y):
                                if (d['inquest_alerts']):
                                    print(mycolors.foreground.red + "\ninquest alerts:", end=' ')
                                    for j in d['inquest_alerts']:
                                        print('\n')
                                        for k in j:
                                            print(mycolors.foreground.blue + "".ljust(19) + k + ":\t" + mycolors.reset  + (("\n" + " ".ljust(32)).join(textwrap.wrap(str(j[k]), width=80))), end="\n")


    except ValueError as e:
        print(e)
        if (bkg == 1):
            print((mycolors.foreground.lightred + "\nError while connecting to InQuest!\n"))
        else:
            print((mycolors.foreground.lightred + "\nError while connecting to InQuest!\n"))


def inquest_domain(inquestx, inquest):

    inquestext = ''
    inquestresponse = ''

    requestINQUESTAPI()

    try:

        print("\n")
        print((mycolors.reset + "INQUEST DOMAIN SEARCH REPORT".center(110)), end='')
        print((mycolors.reset + "".center(28)), end='')
        print("\n" + (110*'-').center(55))

        if(not inquestx):
            if (bkg == 1):
                print(mycolors.foreground.lightred + "\nThe -I parameter with the provided domain is required!\n" + mycolors.reset)
            else:
                print(mycolors.foreground.red + "\nThe -I parameter with the provided domain is required!\n" + mycolors.reset)
            exit(1)

        requestsession = requests.Session( )
        requestsession.headers.update({'Accept': 'application/json'})
        requestsession.headers.update({'Authorization':INQUESTAPI})
        inquestresponse = requestsession.get(inquest + '/search/ioc/domain?keyword=' + inquestx)
        inquesttext = json.loads(inquestresponse.text)

        if (bkg == 1):
            for i in inquesttext.keys():
                if (i == "data"):
                    if (inquesttext['data'] is not None):
                        for d in inquesttext['data']:
                            y = d.keys()    
                            print("\n" + (110*'-').center(55), end='\n')
                            if ("sha256" in y):
                                if d['sha256']:
                                    print(mycolors.foreground.lightblue + "\nsha256: ".ljust(20) + mycolors.reset + d['sha256'],end=' ')

                            if ("classification" in y):
                                if d['classification']:
                                    print(mycolors.foreground.lightblue + "\nclassification: ".ljust(20) + mycolors.reset + d['classification'], end=' ')

                            if ("file_type" in y):
                                if d['file_type']:
                                    print(mycolors.foreground.lightblue + "\nfile type: ".ljust(20) + mycolors.reset + d['file_type'], end=' ')

                            if ("first_seen" in y):
                                if d['first_seen']:
                                    print(mycolors.foreground.lightblue + "\nfirst seen: ".ljust(20) + mycolors.reset + d['first_seen'], end=' ')

                            if ("downloadable" in y):
                                if d['downloadable']:
                                    print(mycolors.foreground.lightblue + "\ndownloadable: ".ljust(20) + mycolors.reset + str(d['downloadable']), end=' ')

                            if ("size" in y):
                                if d['size']:
                                    print(mycolors.foreground.lightblue + "\nsize: ".ljust(20) + mycolors.reset + str(d['size']), end=' ')

                            if ("vt_positives" in y):
                                if d['vt_positives']:
                                    print(mycolors.foreground.lightblue + "\nvt positives: ".ljust(20) + mycolors.reset + str(d['vt_positives']), end=' ')

                            if ("vt_weight" in y):
                                if d['vt_weight']:
                                    print(mycolors.foreground.lightblue + "\nvt weight: ".ljust(20) + mycolors.reset + str(d['vt_weight']), end=' ')

                            if ("inquest_alerts" in y):
                                if (d['inquest_alerts']):
                                    print(mycolors.foreground.lightblue + "\ninquest alerts:", end=' ')
                                    for j in d['inquest_alerts']:
                                        print('\n')
                                        for k in j:
                                            print(mycolors.foreground.lightgreen + "".ljust(19) + k + ":\t" + mycolors.reset  + (("\n" + " ".ljust(32)).join(textwrap.wrap(str(j[k]), width=80))), end="\n")

        if (bkg == 0):
            for i in inquesttext.keys():
                if (i == "data"):
                    if (inquesttext['data'] is not None):
                        for d in inquesttext['data']:
                            y = d.keys()    
                            print("\n" + (110*'-').center(55), end='\n')
                            if ("sha256" in y):
                                if d['sha256']:
                                    print(mycolors.foreground.blue + "\nsha256: ".ljust(20) + mycolors.reset + d['sha256'],end=' ')

                            if ("classification" in y):
                                if d['classification']:
                                    print(mycolors.foreground.blue + "\nclassification: ".ljust(20) + mycolors.reset + d['classification'], end=' ')

                            if ("file_type" in y):
                                if d['file_type']:
                                    print(mycolors.foreground.blue + "\nfile type: ".ljust(20) + mycolors.reset + d['file_type'], end=' ')

                            if ("first_seen" in y):
                                if d['first_seen']:
                                    print(mycolors.foreground.blue + "\nfirst seen: ".ljust(20) + mycolors.reset + d['first_seen'], end=' ')

                            if ("downloadable" in y):
                                if d['downloadable']:
                                    print(mycolors.foreground.blue + "\ndownloadable: ".ljust(20) + mycolors.reset + str(d['downloadable']), end=' ')

                            if ("size" in y):
                                if d['size']:
                                    print(mycolors.foreground.blue + "\nsize: ".ljust(20) + mycolors.reset + str(d['size']), end=' ')

                            if ("vt_positives" in y):
                                if d['vt_positives']:
                                    print(mycolors.foreground.blue + "\nvt positives: ".ljust(20) + mycolors.reset + str(d['vt_positives']), end=' ')

                            if ("vt_weight" in y):
                                if d['vt_weight']:
                                    print(mycolors.foreground.blue + "\nvt weight: ".ljust(20) + mycolors.reset + str(d['vt_weight']), end=' ')

                            if ("inquest_alerts" in y):
                                if (d['inquest_alerts']):
                                    print(mycolors.foreground.blue + "\ninquest alerts:", end=' ')
                                    for j in d['inquest_alerts']:
                                        print('\n')
                                        for k in j:
                                            print(mycolors.foreground.purple + "".ljust(19) + k + ":\t" + mycolors.reset  + (("\n" + " ".ljust(32)).join(textwrap.wrap(str(j[k]), width=80))), end="\n")

    except ValueError as e:
        print(e)
        if (bkg == 1):
            print((mycolors.foreground.lightred + "\nError while connecting to InQuest!\n"))
        else:
            print((mycolors.foreground.lightred + "\nError while connecting to InQuest!\n"))


def inquest_ip(inquestx, inquest):

    inquestext = ''
    inquestresponse = ''

    requestINQUESTAPI()

    try:

        print("\n")
        print((mycolors.reset + "INQUEST IP ADDRESS SEARCH REPORT".center(110)), end='')
        print((mycolors.reset + "".center(28)), end='')
        print("\n" + (110*'-').center(55))

        if(not inquestx):
            if (bkg == 1):
                print(mycolors.foreground.lightred + "\nThe -I parameter with the provided IP address is required!\n" + mycolors.reset)
            else:
                print(mycolors.foreground.red + "\nThe -I parameter with the provided IP address is required!\n" + mycolors.reset)
            exit(1)

        requestsession = requests.Session( )
        requestsession.headers.update({'Accept': 'application/json'})
        requestsession.headers.update({'Authorization':INQUESTAPI})
        inquestresponse = requestsession.get(inquest + '/search/ioc/ip?keyword=' + inquestx)
        inquesttext = json.loads(inquestresponse.text)

        if (bkg == 1):
            for i in inquesttext.keys():
                if (i == "data"):
                    if (inquesttext['data'] is not None):
                        for d in inquesttext['data']:
                            y = d.keys()    
                            print("\n" + (110*'-').center(55), end='\n')
                            if ("sha256" in y):
                                if d['sha256']:
                                    print(mycolors.foreground.orange + "\nsha256: ".ljust(20) + mycolors.reset + d['sha256'],end=' ')

                            if ("classification" in y):
                                if d['classification']:
                                    print(mycolors.foreground.orange + "\nclassification: ".ljust(20) + mycolors.reset + d['classification'], end=' ')

                            if ("file_type" in y):
                                if d['file_type']:
                                    print(mycolors.foreground.orange + "\nfile type: ".ljust(20) + mycolors.reset + d['file_type'], end=' ')

                            if ("first_seen" in y):
                                if d['first_seen']:
                                    print(mycolors.foreground.orange + "\nfirst seen: ".ljust(20) + mycolors.reset + d['first_seen'], end=' ')

                            if ("downloadable" in y):
                                if d['downloadable']:
                                    print(mycolors.foreground.orange + "\ndownloadable: ".ljust(20) + mycolors.reset + str(d['downloadable']), end=' ')

                            if ("size" in y):
                                if d['size']:
                                    print(mycolors.foreground.orange + "\nsize: ".ljust(20) + mycolors.reset + str(d['size']), end=' ')

                            if ("vt_positives" in y):
                                if d['vt_positives']:
                                    print(mycolors.foreground.orange + "\nvt positives: ".ljust(20) + mycolors.reset + str(d['vt_positives']), end=' ')

                            if ("vt_weight" in y):
                                if d['vt_weight']:
                                    print(mycolors.foreground.orange + "\nvt weight: ".ljust(20) + mycolors.reset + str(d['vt_weight']), end=' ')

                            if ("inquest_alerts" in y):
                                if (d['inquest_alerts']):
                                    print(mycolors.foreground.orange + "\ninquest alerts:", end=' ')
                                    for j in d['inquest_alerts']:
                                        print('\n')
                                        for k in j:
                                            print(mycolors.foreground.lightcyan + "".ljust(19) + k + ":\t" + mycolors.reset  + (("\n" + " ".ljust(32)).join(textwrap.wrap(str(j[k]), width=80))), end="\n")

        if (bkg == 0):
            for i in inquesttext.keys():
                if (i == "data"):
                    if (inquesttext['data'] is not None):
                        for d in inquesttext['data']:
                            y = d.keys()    
                            print("\n" + (110*'-').center(55), end='\n')
                            if ("sha256" in y):
                                if d['sha256']:
                                    print(mycolors.foreground.cyan + "\nsha256: ".ljust(20) + mycolors.reset + d['sha256'],end=' ')

                            if ("classification" in y):
                                if d['classification']:
                                    print(mycolors.foreground.cyan + "\nclassification: ".ljust(20) + mycolors.reset + d['classification'], end=' ')

                            if ("file_type" in y):
                                if d['file_type']:
                                    print(mycolors.foreground.cyan + "\nfile type: ".ljust(20) + mycolors.reset + d['file_type'], end=' ')

                            if ("first_seen" in y):
                                if d['first_seen']:
                                    print(mycolors.foreground.cyan + "\nfirst seen: ".ljust(20) + mycolors.reset + d['first_seen'], end=' ')

                            if ("downloadable" in y):
                                if d['downloadable']:
                                    print(mycolors.foreground.cyan + "\ndownloadable: ".ljust(20) + mycolors.reset + str(d['downloadable']), end=' ')

                            if ("size" in y):
                                if d['size']:
                                    print(mycolors.foreground.cyan + "\nsize: ".ljust(20) + mycolors.reset + str(d['size']), end=' ')

                            if ("vt_positives" in y):
                                if d['vt_positives']:
                                    print(mycolors.foreground.cyan + "\nvt positives: ".ljust(20) + mycolors.reset + str(d['vt_positives']), end=' ')

                            if ("vt_weight" in y):
                                if d['vt_weight']:
                                    print(mycolors.foreground.cyan + "\nvt weight: ".ljust(20) + mycolors.reset + str(d['vt_weight']), end=' ')

                            if ("inquest_alerts" in y):
                                if (d['inquest_alerts']):
                                    print(mycolors.foreground.cyan + "\ninquest alerts:", end=' ')
                                    for j in d['inquest_alerts']:
                                        print('\n')
                                        for k in j:
                                            print(mycolors.foreground.purple + "".ljust(19) + k + ":\t" + mycolors.reset  + (("\n" + " ".ljust(32)).join(textwrap.wrap(str(j[k]), width=80))), end="\n")

    except ValueError as e:
        print(e)
        if (bkg == 1):
            print((mycolors.foreground.lightred + "\nError while connecting to InQuest!\n"))
        else:
            print((mycolors.foreground.lightred + "\nError while connecting to InQuest!\n"))


def inquest_email(inquestx, inquest):

    inquestext = ''
    inquestresponse = ''

    requestINQUESTAPI()

    try:

        print("\n")
        print((mycolors.reset + "INQUEST IOC SEARCH REPORT".center(110)), end='')
        print((mycolors.reset + "".center(28)), end='')
        print("\n" + (110*'-').center(55))

        if(not inquestx):
            if (bkg == 1):
                print(mycolors.foreground.lightred + "\nThe -I parameter with the provided email address is required!\n" + mycolors.reset)
            else:
                print(mycolors.foreground.red + "\nThe -I parameter with the provided email address is required!\n" + mycolors.reset)
            exit(1)

        requestsession = requests.Session( )
        requestsession.headers.update({'Accept': 'application/json'})
        requestsession.headers.update({'Authorization':INQUESTAPI})
        inquestresponse = requestsession.get(inquest + '/search/ioc/email?keyword=' + inquestx)
        inquesttext = json.loads(inquestresponse.text)

        if (bkg == 1):
            for i in inquesttext.keys():
                if (i == "data"):
                    if (inquesttext['data'] is not None):
                        for d in inquesttext['data']:
                            y = d.keys()    
                            print("\n" + (110*'-').center(55), end='\n')
                            if ("sha256" in y):
                                if d['sha256']:
                                    print(mycolors.foreground.lightgreen + "\nsha256: ".ljust(20) + mycolors.reset + d['sha256'],end=' ')

                            if ("classification" in y):
                                if d['classification']:
                                    print(mycolors.foreground.lightgreen + "\nclassification: ".ljust(20) + mycolors.reset + d['classification'], end=' ')

                            if ("file_type" in y):
                                if d['file_type']:
                                    print(mycolors.foreground.lightgreen + "\nfile type: ".ljust(20) + mycolors.reset + d['file_type'], end=' ')

                            if ("first_seen" in y):
                                if d['first_seen']:
                                    print(mycolors.foreground.lightgreen + "\nfirst seen: ".ljust(20) + mycolors.reset + d['first_seen'], end=' ')

                            if ("downloadable" in y):
                                if d['downloadable']:
                                    print(mycolors.foreground.lightgreen + "\ndownloadable: ".ljust(20) + mycolors.reset + str(d['downloadable']), end=' ')

                            if ("size" in y):
                                if d['size']:
                                    print(mycolors.foreground.lightgreen + "\nsize: ".ljust(20) + mycolors.reset + str(d['size']), end=' ')

                            if ("vt_positives" in y):
                                if d['vt_positives']:
                                    print(mycolors.foreground.lightgreen + "\nvt positives: ".ljust(20) + mycolors.reset + str(d['vt_positives']), end=' ')

                            if ("vt_weight" in y):
                                if d['vt_weight']:
                                    print(mycolors.foreground.lightgreen + "\nvt weight: ".ljust(20) + mycolors.reset + str(d['vt_weight']), end=' ')

                            if ("inquest_alerts" in y):
                                if (d['inquest_alerts']):
                                    print(mycolors.foreground.lightgreen + "\ninquest alerts:", end=' ')
                                    for j in d['inquest_alerts']:
                                        print('\n')
                                        for k in j:
                                            print(mycolors.foreground.yellow + "".ljust(19) + k + ":\t" + mycolors.reset  + (("\n" + " ".ljust(32)).join(textwrap.wrap(str(j[k]), width=80))), end="\n")

        if (bkg == 0):
            for i in inquesttext.keys():
                if (i == "data"):
                    if (inquesttext['data'] is not None):
                        for d in inquesttext['data']:
                            y = d.keys()    
                            print("\n" + (110*'-').center(55), end='\n')
                            if ("sha256" in y):
                                if d['sha256']:
                                    print(mycolors.foreground.purple + "\nsha256: ".ljust(20) + mycolors.reset + d['sha256'],end=' ')

                            if ("classification" in y):
                                if d['classification']:
                                    print(mycolors.foreground.purple + "\nclassification: ".ljust(20) + mycolors.reset + d['classification'], end=' ')

                            if ("file_type" in y):
                                if d['file_type']:
                                    print(mycolors.foreground.purple + "\nfile type: ".ljust(20) + mycolors.reset + d['file_type'], end=' ')

                            if ("first_seen" in y):
                                if d['first_seen']:
                                    print(mycolors.foreground.purple + "\nfirst seen: ".ljust(20) + mycolors.reset + d['first_seen'], end=' ')

                            if ("downloadable" in y):
                                if d['downloadable']:
                                    print(mycolors.foreground.purple + "\ndownloadable: ".ljust(20) + mycolors.reset + str(d['downloadable']), end=' ')

                            if ("size" in y):
                                if d['size']:
                                    print(mycolors.foreground.purple + "\nsize: ".ljust(20) + mycolors.reset + str(d['size']), end=' ')

                            if ("vt_positives" in y):
                                if d['vt_positives']:
                                    print(mycolors.foreground.purple + "\nvt positives: ".ljust(20) + mycolors.reset + str(d['vt_positives']), end=' ')

                            if ("vt_weight" in y):
                                if d['vt_weight']:
                                    print(mycolors.foreground.purple + "\nvt weight: ".ljust(20) + mycolors.reset + str(d['vt_weight']), end=' ')

                            if ("inquest_alerts" in y):
                                if (d['inquest_alerts']):
                                    print(mycolors.foreground.purple + "\ninquest alerts:", end=' ')
                                    for j in d['inquest_alerts']:
                                        print('\n')
                                        for k in j:
                                            print(mycolors.foreground.green + "".ljust(19) + k + ":\t" + mycolors.reset  + (("\n" + " ".ljust(32)).join(textwrap.wrap(str(j[k]), width=80))), end="\n")

        print("\n")

    except ValueError as e:
        print(e)
        if (bkg == 1):
            print((mycolors.foreground.lightred + "\nError while connecting to InQuest!\n"))
        else:
            print((mycolors.foreground.lightred + "\nError while connecting to InQuest!\n"))


def inquest_filename(inquestx, inquest):

    inquestext = ''
    inquestresponse = ''

    requestINQUESTAPI()

    try:

        print("\n")
        print((mycolors.reset + "INQUEST IOC SEARCH REPORT".center(110)), end='')
        print((mycolors.reset + "".center(28)), end='')
        print("\n" + (110*'-').center(55))

        if(not inquestx):
            if (bkg == 1):
                print(mycolors.foreground.lightred + "\nThe -I parameter with the provided filename is required!\n" + mycolors.reset)
            else:
                print(mycolors.foreground.red + "\nThe -I parameter with the provided filename is required!\n" + mycolors.reset)
            exit(1)

        requestsession = requests.Session( )
        requestsession.headers.update({'Accept': 'application/json'})
        requestsession.headers.update({'Authorization':INQUESTAPI})
        inquestresponse = requestsession.get(inquest + '/search/ioc/filename?keyword=' + inquestx)
        inquesttext = json.loads(inquestresponse.text)

        if (bkg == 1):
            for i in inquesttext.keys():
                if (i == "data"):
                    if (inquesttext['data'] is not None):
                        for d in inquesttext['data']:
                            y = d.keys()    
                            print("\n" + (110*'-').center(55), end='\n')
                            if ("sha256" in y):
                                if d['sha256']:
                                    print(mycolors.foreground.lightred + "\nsha256: ".ljust(20) + mycolors.reset + d['sha256'],end=' ')

                            if ("classification" in y):
                                if d['classification']:
                                    print(mycolors.foreground.lightred + "\nclassification: ".ljust(20) + mycolors.reset + d['classification'], end=' ')

                            if ("file_type" in y):
                                if d['file_type']:
                                    print(mycolors.foreground.lightred + "\nfile type: ".ljust(20) + mycolors.reset + d['file_type'], end=' ')

                            if ("first_seen" in y):
                                if d['first_seen']:
                                    print(mycolors.foreground.lightred + "\nfirst seen: ".ljust(20) + mycolors.reset + d['first_seen'], end=' ')

                            if ("downloadable" in y):
                                if d['downloadable']:
                                    print(mycolors.foreground.lightred + "\ndownloadable: ".ljust(20) + mycolors.reset + str(d['downloadable']), end=' ')

                            if ("size" in y):
                                if d['size']:
                                    print(mycolors.foreground.lightred + "\nsize: ".ljust(20) + mycolors.reset + str(d['size']), end=' ')

                            if ("vt_positives" in y):
                                if d['vt_positives']:
                                    print(mycolors.foreground.lightred + "\nvt positives: ".ljust(20) + mycolors.reset + str(d['vt_positives']), end=' ')

                            if ("vt_weight" in y):
                                if d['vt_weight']:
                                    print(mycolors.foreground.lightred + "\nvt weight: ".ljust(20) + mycolors.reset + str(d['vt_weight']), end=' ')

                            if ("inquest_alerts" in y):
                                if (d['inquest_alerts']):
                                    print(mycolors.foreground.lightred + "\ninquest alerts:", end=' ')
                                    for j in d['inquest_alerts']:
                                        print('\n')
                                        for k in j:
                                            print(mycolors.foreground.lightblue + "".ljust(19) + k + ":\t" + mycolors.reset  + (("\n" + " ".ljust(32)).join(textwrap.wrap(str(j[k]), width=80))), end="\n")

        if (bkg == 0):
            for i in inquesttext.keys():
                if (i == "data"):
                    if (inquesttext['data'] is not None):
                        for d in inquesttext['data']:
                            y = d.keys()    
                            print("\n" + (110*'-').center(55), end='\n')
                            if ("sha256" in y):
                                if d['sha256']:
                                    print(mycolors.foreground.red + "\nsha256: ".ljust(20) + mycolors.reset + d['sha256'],end=' ')

                            if ("classification" in y):
                                if d['classification']:
                                    print(mycolors.foreground.red + "\nclassification: ".ljust(20) + mycolors.reset + d['classification'], end=' ')

                            if ("file_type" in y):
                                if d['file_type']:
                                    print(mycolors.foreground.red + "\nfile type: ".ljust(20) + mycolors.reset + d['file_type'], end=' ')

                            if ("first_seen" in y):
                                if d['first_seen']:
                                    print(mycolors.foreground.red + "\nfirst seen: ".ljust(20) + mycolors.reset + d['first_seen'], end=' ')

                            if ("downloadable" in y):
                                if d['downloadable']:
                                    print(mycolors.foreground.red + "\ndownloadable: ".ljust(20) + mycolors.reset + str(d['downloadable']), end=' ')

                            if ("size" in y):
                                if d['size']:
                                    print(mycolors.foreground.red + "\nsize: ".ljust(20) + mycolors.reset + str(d['size']), end=' ')

                            if ("vt_positives" in y):
                                if d['vt_positives']:
                                    print(mycolors.foreground.red + "\nvt positives: ".ljust(20) + mycolors.reset + str(d['vt_positives']), end=' ')

                            if ("vt_weight" in y):
                                if d['vt_weight']:
                                    print(mycolors.foreground.red + "\nvt weight: ".ljust(20) + mycolors.reset + str(d['vt_weight']), end=' ')

                            if ("inquest_alerts" in y):
                                if (d['inquest_alerts']):
                                    print(mycolors.foreground.red + "\ninquest alerts:", end=' ')
                                    for j in d['inquest_alerts']:
                                        print('\n')
                                        for k in j:
                                            print(mycolors.foreground.blue + "".ljust(19) + k + ":\t" + mycolors.reset  + (("\n" + " ".ljust(32)).join(textwrap.wrap(str(j[k]), width=80))), end="\n")

        print("\n")

    except ValueError as e:
        print(e)
        if (bkg == 1):
            print((mycolors.foreground.lightred + "\nError while connecting to InQuest!\n"))
        else:
            print((mycolors.foreground.lightred + "\nError while connecting to InQuest!\n"))


def inquest_url(inquestx, inquest):

    inquestext = ''
    inquestresponse = ''

    requestINQUESTAPI()

    try:

        print("\n")
        print((mycolors.reset + "INQUEST URL SEARCH REPORT".center(110)), end='')
        print((mycolors.reset + "".center(28)), end='')
        print("\n" + (110*'-').center(55))

        if(not inquestx):
            if (bkg == 1):
                print(mycolors.foreground.lightred + "\nThe -I parameter with the provided URL is required!\n" + mycolors.reset)
            else:
                print(mycolors.foreground.red + "\nThe -I parameter with the provided URL is required!\n" + mycolors.reset)
            exit(1)

        requestsession = requests.Session( )
        requestsession.headers.update({'Accept': 'application/json'})
        requestsession.headers.update({'Authorization':INQUESTAPI})
        inquestresponse = requestsession.get(inquest + '/search/ioc/url?keyword=' + inquestx)
        inquesttext = json.loads(inquestresponse.text)

        if (bkg == 1):
            for i in inquesttext.keys():
                if (i == "data"):
                    if (inquesttext['data'] is not None):
                        for d in inquesttext['data']:
                            y = d.keys()    
                            print("\n" + (110*'-').center(55), end='\n')
                            if ("sha256" in y):
                                if d['sha256']:
                                    print(mycolors.foreground.lightcyan + "\nsha256: ".ljust(20) + mycolors.reset + d['sha256'],end=' ')

                            if ("classification" in y):
                                if d['classification']:
                                    print(mycolors.foreground.lightcyan + "\nclassification: ".ljust(20) + mycolors.reset + d['classification'], end=' ')

                            if ("file_type" in y):
                                if d['file_type']:
                                    print(mycolors.foreground.lightcyan + "\nfile type: ".ljust(20) + mycolors.reset + d['file_type'], end=' ')

                            if ("first_seen" in y):
                                if d['first_seen']:
                                    print(mycolors.foreground.lightcyan + "\nfirst seen: ".ljust(20) + mycolors.reset + d['first_seen'], end=' ')

                            if ("downloadable" in y):
                                if d['downloadable']:
                                    print(mycolors.foreground.lightcyan + "\ndownloadable: ".ljust(20) + mycolors.reset + str(d['downloadable']), end=' ')

                            if ("size" in y):
                                if d['size']:
                                    print(mycolors.foreground.lightcyan + "\nsize: ".ljust(20) + mycolors.reset + str(d['size']), end=' ')

                            if ("vt_positives" in y):
                                if d['vt_positives']:
                                    print(mycolors.foreground.lightcyan + "\nvt positives: ".ljust(20) + mycolors.reset + str(d['vt_positives']), end=' ')

                            if ("vt_weight" in y):
                                if d['vt_weight']:
                                    print(mycolors.foreground.lightcyan + "\nvt weight: ".ljust(20) + mycolors.reset + str(d['vt_weight']), end=' ')

                            if ("inquest_alerts" in y):
                                if (d['inquest_alerts']):
                                    print(mycolors.foreground.lightcyan + "\ninquest alerts:", end=' ')
                                    for j in d['inquest_alerts']:
                                        print('\n')
                                        for k in j:
                                            print(mycolors.foreground.lightred + "".ljust(19) + k + ":\t" + mycolors.reset  + (("\n" + " ".ljust(32)).join(textwrap.wrap(str(j[k]), width=80))), end="\n")

        if (bkg == 0):
            for i in inquesttext.keys():
                if (i == "data"):
                    if (inquesttext['data'] is not None):
                        for d in inquesttext['data']:
                            y = d.keys()    
                            print("\n" + (110*'-').center(55), end='\n')
                            if ("sha256" in y):
                                if d['sha256']:
                                    print(mycolors.foreground.red + "\nsha256: ".ljust(20) + mycolors.reset + d['sha256'],end=' ')

                            if ("classification" in y):
                                if d['classification']:
                                    print(mycolors.foreground.red + "\nclassification: ".ljust(20) + mycolors.reset + d['classification'], end=' ')

                            if ("file_type" in y):
                                if d['file_type']:
                                    print(mycolors.foreground.red + "\nfile type: ".ljust(20) + mycolors.reset + d['file_type'], end=' ')

                            if ("first_seen" in y):
                                if d['first_seen']:
                                    print(mycolors.foreground.red + "\nfirst seen: ".ljust(20) + mycolors.reset + d['first_seen'], end=' ')

                            if ("downloadable" in y):
                                if d['downloadable']:
                                    print(mycolors.foreground.red + "\ndownloadable: ".ljust(20) + mycolors.reset + str(d['downloadable']), end=' ')

                            if ("size" in y):
                                if d['size']:
                                    print(mycolors.foreground.red + "\nsize: ".ljust(20) + mycolors.reset + str(d['size']), end=' ')

                            if ("vt_positives" in y):
                                if d['vt_positives']:
                                    print(mycolors.foreground.red + "\nvt positives: ".ljust(20) + mycolors.reset + str(d['vt_positives']), end=' ')

                            if ("vt_weight" in y):
                                if d['vt_weight']:
                                    print(mycolors.foreground.red + "\nvt weight: ".ljust(20) + mycolors.reset + str(d['vt_weight']), end=' ')

                            if ("inquest_alerts" in y):
                                if (d['inquest_alerts']):
                                    print(mycolors.foreground.red + "\ninquest alerts:", end=' ')
                                    for j in d['inquest_alerts']:
                                        print('\n')
                                        for k in j:
                                            print(mycolors.foreground.purple + "".ljust(19) + k + ":\t" + mycolors.reset  + (("\n" + " ".ljust(32)).join(textwrap.wrap(str(j[k]), width=80))), end="\n")

        print("\n")

    except ValueError as e:
        print(e)
        if (bkg == 1):
            print((mycolors.foreground.lightred + "\nError while connecting to InQuest!\n"))
        else:
            print((mycolors.foreground.lightred + "\nError while connecting to InQuest!\n"))


def inquest_ioc_search(inquestx, inquest):

    inquestext = ''
    inquestresponse = ''

    requestINQUESTAPI()

    try:

        print("\n")
        print((mycolors.reset + "INQUEST IOC SEARCH REPORT".center(110)), end='')
        print((mycolors.reset + "".center(28)), end='')
        print("\n" + (110*'-').center(55))

        if(not inquestx):
            if (bkg == 1):
                print(mycolors.foreground.lightred + "\nThe -I parameter must have an IOC as argument!\n" + mycolors.reset)
            else:
                print(mycolors.foreground.red + "\nThe -I parameter must have an IOC as argument!\n" + mycolors.reset)
            exit(1)

        requestsession = requests.Session( )
        requestsession.headers.update({'Accept': 'application/json'})
        requestsession.headers.update({'Authorization':INQUESTAPI})
        inquestresponse = requestsession.get(inquest + '/search?keyword=' + inquestx)
        inquesttext = json.loads(inquestresponse.text)

        if (inquestresponse.status_code == 400 or inquestresponse.status_code == 500):
            inquesttext = json.loads(inquestresponse.text)

            if 'error' in inquesttext:
                if inquesttext['error'] == "The 'keyword' parameter must be at least 3 bytes long.":
                    if (bkg == 1):
                        print(mycolors.foreground.lightred + "\nThe -B parameter must be at least 3 bytes long!\n" + mycolors.reset)
                    else:
                        print(mycolors.foreground.red + "\nThe -B parameter must be at least 3 byte long!\n" + mycolors.reset)
                    exit(1)

        if (bkg == 1):
            for i in inquesttext.keys():
                if (i == "data"):
                    if (inquesttext['data'] is not None):
                        for d in inquesttext['data']:
                            print("\n" + (110*'-').center(55), end='\n\n')
                            for k in d:
                                print(mycolors.foreground.lightcyan + "".ljust(0) + k + ":\t" + mycolors.reset  + (("\n" + " ".ljust(0)).join(textwrap.wrap(str(d[k]), width=80))), end="\n")

        if (bkg == 0):
            for i in inquesttext.keys():
                if (i == "data"):
                    if (inquesttext['data'] is not None):
                        for d in inquesttext['data']:
                            print("\n" + (110*'-').center(55), end='\n\n')
                            for k in d:
                                print(mycolors.foreground.cyan + "".ljust(0) + k + ":\t" + mycolors.reset  + (("\n" + " ".ljust(0)).join(textwrap.wrap(str(d[k]), width=80))), end="\n")

    except ValueError as e:
        print(e)
        if (bkg == 1):
            print((mycolors.foreground.lightred + "\nError while connecting to InQuest!\n"))
        else:
            print((mycolors.foreground.lightred + "\nError while connecting to InQuest!\n"))


def inquest_ioc_list(inquestx, inquest):

    inquestext = ''
    inquestresponse = ''

    requestINQUESTAPI()

    try:

        print("\n")
        print((mycolors.reset + "INQUEST IOC SEARCH REPORT".center(110)), end='')
        print((mycolors.reset + "".center(28)), end='')
        print("\n" + (110*'-').center(55))
        
        if(not inquestx == "list"):
            if (bkg == 1):
                print(mycolors.foreground.lightred + "\nThe -I parameter must have the word 'list' (no quotes) as argument!\n" + mycolors.reset)
            else:
                print(mycolors.foreground.red + "\nThe -I parameter must have the word 'list' (no quotes) as argument!\n" + mycolors.reset)
            exit(1)

        requestsession = requests.Session( )
        requestsession.headers.update({'Accept': 'application/json'})
        requestsession.headers.update({'Authorization':INQUESTAPI})
        inquestresponse = requestsession.get(inquest + '/list')
        inquesttext = json.loads(inquestresponse.text)

        if (bkg == 1):
            for i in inquesttext.keys():
                if (i == "data"):
                    if (inquesttext['data'] is not None):
                        for d in inquesttext['data']:
                            print("\n" + (110*'-').center(55), end='\n\n')
                            for k in d:
                                print(mycolors.foreground.yellow + "".ljust(0) + k + ":\t" + mycolors.reset  + (("\n" + " ".ljust(0)).join(textwrap.wrap(str(d[k]), width=80))), end="\n")

        if (bkg == 0):
            for i in inquesttext.keys():
                if (i == "data"):
                    if (inquesttext['data'] is not None):
                        for d in inquesttext['data']:
                            print("\n" + (110*'-').center(55), end='\n\n')
                            for k in d:
                                print(mycolors.foreground.purple + "".ljust(0) + k + ":\t" + mycolors.reset  + (("\n" + " ".ljust(0)).join(textwrap.wrap(str(d[k]), width=80))), end="\n")

    except ValueError as e:
        print(e)
        if (bkg == 1):
            print((mycolors.foreground.lightred + "\nError while connecting to InQuest!\n"))
        else:
            print((mycolors.foreground.lightred + "\nError while connecting to InQuest!\n"))


def inquest_rep_search(inquestx, inquest):

    inquestext = ''
    inquestresponse = ''

    requestINQUESTAPI()

    try:

        print("\n")
        print((mycolors.reset + "INQUEST REPUTATION SEARCH REPORT".center(110)), end='')
        print((mycolors.reset + "".center(28)), end='')
        print("\n" + (110*'-').center(55), end='\n')

        if(not inquestx):
            if (bkg == 1):
                print(mycolors.foreground.lightred + "\nThe -I parameter must have an IOC as argument!\n" + mycolors.reset)
            else:
                print(mycolors.foreground.red + "\nThe -I parameter must have an IOC as argument!\n" + mycolors.reset)
            exit(1)

        requestsession = requests.Session( )
        requestsession.headers.update({'Accept': 'application/json'})
        requestsession.headers.update({'Authorization':INQUESTAPI})
        inquestresponse = requestsession.get(inquest + '/search?keyword=' + inquestx)
        inquesttext = json.loads(inquestresponse.text)

        if (inquestresponse.status_code == 400 or inquestresponse.status_code == 500):
            inquesttext = json.loads(inquestresponse.text)

            if 'error' in inquesttext:
                if inquesttext['error'] == "The 'keyword' parameter must be at least 3 bytes long.":
                    if (bkg == 1):
                        print(mycolors.foreground.lightred + "\nThe -B parameter must be at least 3 bytes long!\n" + mycolors.reset)
                    else:
                        print(mycolors.foreground.red + "\nThe -B parameter must be at least 3 byte long!\n" + mycolors.reset)
                    exit(1)

        if (bkg == 1):
            for i in inquesttext.keys():
                if (i == "data"):
                    if (inquesttext['data'] is not None):
                        for d in inquesttext['data']:
                            print("\n" + (110*'-').center(55), end=' ')
                            print('\n')
                            for k in d:
                                print(mycolors.foreground.lightred + "".ljust(0) + (k).rjust(12) + ": " + mycolors.reset  + (("\n" + " ".ljust(16)).join(textwrap.wrap(str(d[k]), width=80))), end="\n")

        if (bkg == 0):
            for i in inquesttext.keys():
                if (i == "data"):
                    if (inquesttext['data'] is not None):
                        for d in inquesttext['data']:
                            print("\n" + (110*'-').center(55), end=' ')
                            print('\n')
                            for k in d:
                                print(mycolors.foreground.red + "".ljust(0) + (k).rjust(12) + ": " + mycolors.reset  + (("\n" + " ".ljust(16)).join(textwrap.wrap(str(d[k]), width=80))), end="\n")

    except ValueError as e:
        print(e)
        if (bkg == 1):
            print((mycolors.foreground.lightred + "\nError while connecting to InQuest!\n"))
        else:
            print((mycolors.foreground.lightred + "\nError while connecting to InQuest!\n"))


def inquest_rep_list(inquestx, inquest):

    inquestext = ''
    inquestresponse = ''

    requestINQUESTAPI()

    try:

        print("\n")
        print((mycolors.reset + "INQUEST REPUTATION LIST REPORT".center(110)), end='')
        print((mycolors.reset + "".center(28)), end='')
        print("\n" + (110*'-').center(55))
        
        if(not inquestx == "list"):
            if (bkg == 1):
                print(mycolors.foreground.lightred + "\nThe -I parameter must have the word 'list' (no quotes) as argument!\n" + mycolors.reset)
            else:
                print(mycolors.foreground.red + "\nThe -I parameter must have the word 'list' (no quotes) as argument!\n" + mycolors.reset)
            exit(1)

        requestsession = requests.Session( )
        requestsession.headers.update({'Accept': 'application/json'})
        requestsession.headers.update({'Authorization':INQUESTAPI})
        inquestresponse = requestsession.get(inquest + '/list')
        inquesttext = json.loads(inquestresponse.text)

        if (bkg == 1):
            for i in inquesttext.keys():
                if (i == "data"):
                    if (inquesttext['data'] is not None):
                        for d in inquesttext['data']:
                            print("\n" + (110*'-').center(55), end=' ')
                            print('\n')
                            for k in d:
                                print(mycolors.foreground.lightgreen + "".ljust(0) + (k).rjust(12) + ": " + mycolors.reset  + (("\n" + " ".ljust(14)).join(textwrap.wrap(str(d[k]), width=80))), end="\n")

        if (bkg == 0):
            for i in inquesttext.keys():
                if (i == "data"):
                    if (inquesttext['data'] is not None):
                        for d in inquesttext['data']:
                            print("\n" + (110*'-').center(55), end=' ')
                            print('\n')
                            for k in d:
                                print(mycolors.foreground.purple + "".ljust(0) + (k).rjust(12) + ": " + mycolors.reset  + (("\n" + " ".ljust(14)).join(textwrap.wrap(str(d[k]), width=80))), end="\n")

    except ValueError as e:
        print(e)
        if (bkg == 1):
            print((mycolors.foreground.lightred + "\nError while connecting to InQuest!\n"))
        else:
            print((mycolors.foreground.lightred + "\nError while connecting to InQuest!\n"))






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
                                    print(mycolors.foreground.yellow + "\nsha256_hash: ".ljust(15) + mycolors.reset + d['sha256_hash'],end=' ')

                            if ("sha1_hash" in y):
                                if d['sha1_hash']:
                                    print(mycolors.foreground.yellow + "\nsha1_hash: ".ljust(15) + mycolors.reset + d['sha1_hash'], end=' ')

                            if ("md5_hash" in y):
                                if d['md5_hash']:
                                    print(mycolors.foreground.yellow + "\nmd5_hash: ".ljust(15) + mycolors.reset + d['md5_hash'], end=' ')

                            if ("first_seen" in y):
                                if d['first_seen']:
                                    print(mycolors.foreground.yellow + "\nfirst_seen: ".ljust(15) + mycolors.reset + d['first_seen'], end=' ')

                            if ("last_seen" in y):
                                if d['last_seen']:
                                    print(mycolors.foreground.yellow + "\nlast_seen: ".ljust(15) + mycolors.reset + d['last_seen'], end=' ')

                            if ("file_name" in y):
                                if d['file_name']:
                                    print(mycolors.foreground.yellow + "\nfile_name: ".ljust(15) + mycolors.reset + d['file_name'], end=' ')

                            if ("file_size" in y):
                                if d['file_size']:
                                    print(mycolors.foreground.yellow + "\nfile_size: ".ljust(15) + mycolors.reset + str(d['file_size']) + " bytes", end=' ')

                            if ("file_type" in y):
                                if d['file_type']:
                                    print(mycolors.foreground.yellow + "\nfile_type: ".ljust(15) + mycolors.reset + str(d['file_type']), end=' ')

                            if ("file_type_mime" in y):
                                if d['file_type_mime']:
                                    print(mycolors.foreground.yellow + "\nmime_type: ".ljust(15) + mycolors.reset + str(d['file_type_mime']), end=' ')
                            if ("origin_country" in y):
                                if d['origin_country']:
                                    print(mycolors.foreground.yellow + "\ncountry: ".ljust(15) + mycolors.reset + d['origin_country'], end=' ')

                            if ("imphash" in y):
                                if d['imphash']:
                                    print(mycolors.foreground.yellow + "\nimphash: ".ljust(15) + mycolors.reset + d['imphash'], end=' ')

                            if ("tlsh" in y):
                                if d['tlsh']:
                                    print(mycolors.foreground.yellow + "\ntlsh: ".ljust(15) + mycolors.reset + d['tlsh'], end=' ')

                            if ("reporter" in y):
                                if d['reporter']:
                                    print(mycolors.foreground.yellow + "\nreporter: ".ljust(15) + mycolors.reset + d['reporter'], end=' ')

                            if ("signature" in y):
                                if d['signature']:
                                    print(mycolors.foreground.yellow + "\nsignature: ".ljust(15) + mycolors.reset + d['signature'], end=' ')

                            if ("tags" in y):
                                if d['tags']:
                                    print(mycolors.foreground.yellow + "\ntags: ".ljust(15),end='') 
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
                                    print(mycolors.foreground.yellow + "\nioc: ".ljust(16) + mycolors.reset + d['ioc'],end=' ')

                            if ("id" in y):
                                if d['id']:
                                    print(mycolors.foreground.yellow + "\nid: ".ljust(16) + mycolors.reset + d['id'],end=' ')

                            if ("threat_type" in y):
                                if d['threat_type']:
                                    print(mycolors.foreground.yellow + "\nthreat_type: ".ljust(16) + mycolors.reset + d['threat_type'], end=' ')

                            if ("threat_type_desc" in y):
                                if d['threat_type_desc']:
                                    print(mycolors.foreground.yellow + "\nthreat_desc: ".ljust(16) + mycolors.reset + d['threat_type_desc'], end=' ')

                            if ("ioc_type" in y):
                                if d['ioc_type']:
                                    print(mycolors.foreground.yellow + "\nioc_type: ".ljust(16) + mycolors.reset + d['ioc_type'], end=' ')

                            if ("ioc_type_desc" in y):
                                if d['ioc_type_desc']:
                                    print(mycolors.foreground.yellow + "\nioc_desc: ".ljust(16) + mycolors.reset + d['ioc_type_desc'], end=' ')

                            if ("malware" in y):
                                if d['malware']:
                                    print(mycolors.foreground.yellow + "\nmalware: ".ljust(16) + mycolors.reset + d['malware'], end=' ')

                            if ("malware_printable" in y):
                                if d['malware_printable']:
                                    print(mycolors.foreground.yellow + "\nmalware_desc: ".ljust(16) + mycolors.reset + d['malware_printable'], end=' ')

                            if ("malware_alias" in y):
                                if d['malware_alias']:
                                    print(mycolors.foreground.yellow + "\nmalware_alias: ".ljust(16) + mycolors.reset + d['malware_alias'], end=' ')

                            if ("malware_malpedia" in y):
                                if d['malware_malpedia']:
                                    print(mycolors.foreground.yellow + "\nmalpedia: ".ljust(16) + mycolors.reset + d['malware_malpedia'], end=' ')

                            if ("confidence_level" in y):
                                if d['confidence_level']:
                                    print(mycolors.foreground.yellow + "\nconfidence: ".ljust(16) + mycolors.reset + str(d['confidence_level']), end=' ')

                            if ("first_seen" in y):
                                if d['first_seen']:
                                    print(mycolors.foreground.yellow + "\nfirst_seen: ".ljust(16) + mycolors.reset + str(d['first_seen']), end=' ')

                            if ("last_seen" in y):
                                if d['last_seen']:
                                    print(mycolors.foreground.yellow + "\nlast_seen: ".ljust(16) + mycolors.reset + str(d['last_seen']), end=' ')

                            if ("reporter" in y):
                                if d['reporter']:
                                    print(mycolors.foreground.yellow + "\nreporter: ".ljust(16) + mycolors.reset + str(d['reporter']), end=' ')

                            if ("reference" in y):
                                if d['reference']:
                                    print(mycolors.foreground.yellow + "\nreference: ".ljust(16) + mycolors.reset + d['reference'], end=' ')

                            if ("tags" in y):
                                if d['tags']:
                                    print(mycolors.foreground.yellow + "\ntags: ".ljust(16),end='') 
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
                                    print(mycolors.foreground.yellow + "\nioc: ".ljust(16) + mycolors.reset + d['ioc'],end=' ')

                            if ("id" in y):
                                if d['ioc']:
                                    print(mycolors.foreground.yellow + "\nid: ".ljust(16) + mycolors.reset + d['id'],end=' ')

                            if ("threat_type" in y):
                                if d['threat_type']:
                                    print(mycolors.foreground.yellow + "\nthreat_type: ".ljust(16) + mycolors.reset + d['threat_type'], end=' ')

                            if ("threat_type_desc" in y):
                                if d['threat_type_desc']:
                                    print(mycolors.foreground.yellow + "\nthreat_desc: ".ljust(16) + mycolors.reset + d['threat_type_desc'], end=' ')

                            if ("ioc_type" in y):
                                if d['ioc_type']:
                                    print(mycolors.foreground.yellow + "\nioc_type: ".ljust(16) + mycolors.reset + d['ioc_type'], end=' ')

                            if ("ioc_type_desc" in y):
                                if d['ioc_type_desc']:
                                    print(mycolors.foreground.yellow + "\nioc_desc: ".ljust(16) + mycolors.reset + d['ioc_type_desc'], end=' ')

                            if ("malware" in y):
                                if d['malware']:
                                    print(mycolors.foreground.yellow + "\nmalware: ".ljust(16) + mycolors.reset + d['malware'], end=' ')

                            if ("malware_printable" in y):
                                if d['malware_printable']:
                                    print(mycolors.foreground.yellow + "\nmalware_desc: ".ljust(16) + mycolors.reset + d['malware_printable'], end=' ')

                            if ("malware_alias" in y):
                                if d['malware_alias']:
                                    print(mycolors.foreground.yellow + "\nmalware_alias: ".ljust(16) + mycolors.reset + d['malware_alias'], end=' ')

                            if ("malware_malpedia" in y):
                                if d['malware_malpedia']:
                                    print(mycolors.foreground.yellow + "\nmalpedia: ".ljust(16) + mycolors.reset + d['malware_malpedia'], end=' ')

                            if ("confidence_level" in y):
                                if d['confidence_level']:
                                    print(mycolors.foreground.yellow + "\nconfidence: ".ljust(16) + mycolors.reset + str(d['confidence_level']), end=' ')

                            if ("first_seen" in y):
                                if d['first_seen']:
                                    print(mycolors.foreground.yellow + "\nfirst_seen: ".ljust(16) + mycolors.reset + str(d['first_seen']), end=' ')

                            if ("last_seen" in y):
                                if d['last_seen']:
                                    print(mycolors.foreground.yellow + "\nlast_seen: ".ljust(16) + mycolors.reset + str(d['last_seen']), end=' ')

                            if ("reporter" in y):
                                if d['reporter']:
                                    print(mycolors.foreground.yellow + "\nreporter: ".ljust(16) + mycolors.reset + str(d['reporter']), end=' ')

                            if ("reference" in y):
                                if d['reference']:
                                    print(mycolors.foreground.yellow + "\nreference: ".ljust(16) + mycolors.reset + d['reference'], end=' ')

                            if ("tags" in y):
                                if d['tags']:
                                    print(mycolors.foreground.yellow + "\ntags: ".ljust(16),end='') 
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
                print(mycolors.foreground.lightcyan + "Is available?: \t"  +  haustext.get('query_status').upper())
            else:
                print(mycolors.foreground.green + "Is available?: \t"  +  haustext.get('query_status').upper())
        else:
            if (bkg == 1):
                print(mycolors.foreground.lightcyan + 'Is availble?: Not available')
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
            print(mycolors.foreground.yellow + "Tag:\t\t%s" %  payloadtagx)
        else:
            print(mycolors.foreground.pink + "Tag:\t\t%s" %  payloadtagx)

        if 'urls' in haustext:
            if ('url_id' in haustext['urls']) is not None:
                print(mycolors.reset + "\nStatus".center(9) + " " * 2 + "FType".ljust(7) + " SHA256 Hash".center(64) + " " * 4 + "Virus Total".ljust(14) + ' ' * 2 + "URL to Payload".center(34))
                print("-" * 140 + "\n")
                for w in haustext['urls']:
                    if (bkg == 1):
                        if(w['url_status'] == 'online'):
                            print(mycolors.foreground.lightcyan + mycolors.reverse + w['url_status'] + " " + mycolors.reset, end=' ')
                        if(w['url_status'] == 'offline'):
                            print(mycolors.foreground.lightred + mycolors.reverse + w['url_status'] + mycolors.reset, end=' ')
                        if(w['url_status'] == ''):
                            print(mycolors.foreground.yellow + mycolors.reverse + "unknown" + mycolors.reset, end=' ')
                        if w['file_type']:
                            print(mycolors.foreground.lightcyan + ' ' * 2 + "%-6s" % w['file_type'] + mycolors.reset, end=' ')
                        else:
                            print(mycolors.foreground.lightcyan + ' ' * 2 + "%-6s" % "data" + mycolors.reset, end=' ')
                        if w['sha256_hash']:
                            print(mycolors.foreground.yellow + w['sha256_hash'] + mycolors.reset, end= ' ')
                        if w['virustotal']:
                            print(mycolors.foreground.lightcyan + ' ' * 2 + "%-9s" % w['virustotal'].get('result') + mycolors.reset, end='\t  ')
                        else:
                            print(mycolors.foreground.lightcyan + ' ' * 2 + "%-9s" % "Not Found" + mycolors.reset, end= '\t  ')
                        if (w['url']):
                            print(mycolors.foreground.lightred + (("\n" + " ".ljust(98)).join(textwrap.wrap(w['url'],width=35))), end="\n")
                        else:
                            print(mycolors.foreground.lightred + ' ' * 2 + "URL not provided".center(20) + mycolors.reset)

                    else:
                        if(w['url_status'] == 'online'):
                            print(mycolors.foreground.green + mycolors.reverse + w['url_status'] + " " + mycolors.reset, end=' ')
                        if(w['url_status'] == 'offline'):
                            print(mycolors.foreground.red + mycolors.reverse + w['url_status'] + mycolors.reset, end=' ')
                        if(w['url_status'] == ''):
                            print(mycolors.foreground.blue + mycolors.reverse + "unknown" + mycolors.reset, end=' ')
                        if w['file_type']:
                            print(mycolors.foreground.purple + ' ' * 2 + "%-6s" % w['file_type'] + mycolors.reset, end=' ')
                        else:
                            print(mycolors.foreground.purple + ' ' * 2 + "%-6s" % "data" + mycolors.reset, end=' ')
                        if w['sha256_hash']:
                            print(mycolors.foreground.red + w['sha256_hash'] + mycolors.reset, end= ' ')
                        if w['virustotal']:
                            print(mycolors.foreground.cyan + ' ' * 2 + "%-9s" % w['virustotal'].get('result') + mycolors.reset, end= ' ')
                        else:
                            print(mycolors.foreground.cyan + ' ' * 2 + "%-9s" % "Not Found" + mycolors.reset, end= ' ')
                        if (w['url']):
                            print(mycolors.foreground.green + (("\n" + " ".ljust(98)).join(textwrap.wrap(w['url'],width=35))), end="\n")
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
                print(mycolors.foreground.lightcyan + "Is available?: \t"  +  haustext.get('query_status').upper())
            else:
                print(mycolors.foreground.green + "Is available?: \t"  +  haustext.get('query_status').upper())
        else:
            if (bkg == 1):
                print(mycolors.foreground.lightcyan + 'Is availble?: Not available')
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
            print(mycolors.foreground.yellow + "Tag:\t\t%s" %  haustag)
        else:
            print(mycolors.foreground.pink + "Tag:\t\t%s" %  haustag)


        if 'urls' in haustext:
            if ('url_id' in haustext['urls']) is not None:
                print(mycolors.reset + "\nStatus".center(9) + " " * 6  +  " " * 2 + "Date Added".ljust(22) + " Threat".ljust(17) + " " * 28 + "Associated URL".ljust(80))
                print("-" * 130 + "\n")

                for w in haustext['urls']:
                    if (bkg == 1):
                        if(w['url_status'] == 'online'):
                            print(mycolors.foreground.lightcyan + mycolors.reverse + w['url_status'] + " " + mycolors.reset, end=' ')
                        if(w['url_status'] == 'offline'):
                            print(mycolors.foreground.lightred + mycolors.reverse + w['url_status'] + mycolors.reset, end=' ')
                        if(w['url_status'] == ''):
                            print(mycolors.foreground.yellow + mycolors.reverse + "unknown" + mycolors.reset, end=' ')
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
                                print(mycolors.foreground.yellow + ("\n" + "".ljust(51)).join(textwrap.wrap(w['url'],width=80)).ljust(80), end="\n")
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
                                print(mycolors.foreground.red + ("\n" + "".ljust(51)).join(textwrap.wrap(w['url'],width=80)).ljust(80), end="\n")
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
                                print(mycolors.foreground.lightcyan + haustext['urls'][i].get('url_status') + " " + mycolors.reset, end=' ')
                            if(haustext['urls'][i].get('url_status') == 'offline'):
                                print(mycolors.foreground.lightred + haustext['urls'][i].get('url_status') + mycolors.reset, end=' ')
                            if(haustext['urls'][i].get('url_status')  == ''):
                                print(mycolors.foreground.yellow + "unknown" + mycolors.reset, end=' ')
                            if 'tags' in haustext['urls'][i]:
                                print(mycolors.foreground.yellow, end='')
                                if haustext['urls'][i].get('tags') is not None:
                                    alltags = haustext['urls'][i].get('tags')
                                    for t in alltags:
                                        print("%s" % t, end=' ')
                                        l += len(t)
                                    print(" " * ((45 - l) - len(alltags)) , end=' ')
                                else:
                                    print(" " * 45, end=' ')
                            print(mycolors.reset + ("\n".ljust(55)).join(textwrap.wrap((haustext['urls'][i].get('url')).ljust(14), width=75)), end='\n')
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
                                    print(" " * ((45 - l) - len(alltags)) , end=' ')
                                else:
                                    print(" " * 45, end=' ')
                            print(mycolors.reset + ("\n".ljust(55)).join(textwrap.wrap((haustext['urls'][i].get('url')).ljust(14), width=75)), end='\n')
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
                            print(mycolors.foreground.lightcyan + haustext['payloads'][i].get('firstseen'), end=" ")
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


def alien_subscribed(url, arg1):

    requestALIENAPI()

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
                    print(mycolors.foreground.lightcyan + "INFORMATION: %d" % c)
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

    requestALIENAPI()
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
                    print(mycolors.foreground.lightcyan + "ASN:".ljust(13) + mycolors.reset + hatext['asn'], end='\n')
                if hatext['city']:
                    print(mycolors.foreground.lightcyan + "City:".ljust(13) + mycolors.reset + hatext['city'], end='\n')
                if hatext['country_name']:
                    print(mycolors.foreground.lightcyan + "Country:".ljust(13) + mycolors.reset + hatext['country_name'], end='\n')
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
                                        print(mycolors.foreground.lightcyan + "\nMalware:".ljust(13) + mycolors.reset)
                                        for z in hatext['pulse_info'][key][i]['malware_families']:
                                            print("".ljust(13) + z['display_name'])
                                    if 'tags' in hatext['pulse_info'][key][i]:
                                        print(mycolors.foreground.lightcyan + "Tags:".ljust(12) + mycolors.reset, end=' ')
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
                                print(mycolors.foreground.lightcyan + "\nModified:".ljust(14) + mycolors.reset + (hatext['pulse_info']['pulses'][i]['modified']), end='')
                            if "name" in (hatext['pulse_info']['pulses'][i]):
                                print(mycolors.foreground.lightcyan + "\nNews:".ljust(14) + mycolors.reset + (hatext['pulse_info']['pulses'][i]['name']), end='')
                            if "created" in (hatext['pulse_info']['pulses'][i]):
                                print(mycolors.foreground.lightcyan + "\nCreated:".ljust(14) + mycolors.reset + (hatext['pulse_info']['pulses'][i]['created']), end='')
                                break
                            else:
                                i = i + i

                        k = 0
                        print(mycolors.foreground.lightcyan + "\n\nDescription:" + mycolors.reset, end='')
                        while (k < len(hatext['pulse_info']['pulses'])):
                            for key in hatext['pulse_info']['pulses'][k]:
                                if (key == 'description'):
                                    if (hatext['pulse_info']['pulses'][k]['description']):
                                        print("\n".ljust(14) + mycolors.reset + ("\n".ljust(14)).join(textwrap.wrap(hatext['pulse_info']['pulses'][k]['description'],width=100)), end='\n')
                                        break
                            k = k + 1

                if hatext['pulse_info']:
                    if hatext['pulse_info']['references']:
                        print(mycolors.foreground.lightcyan + "\nReferences: ".ljust(14) + mycolors.reset, end=' ')
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

    requestALIENAPI()

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

    requestALIENAPI()

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

    requestALIENAPI()

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

    requestMALPEDIAAPI()

    try:

        resource = urlx
        requestsession = requests.Session( )
        requestsession.headers.update({'Content-Type': 'application/json'})
        requestsession.headers.update({'Authorization': 'apitoken ' + MALPEDIAAPI  })
        finalurl = '/'.join([resource, 'get', 'families'])
        haresponse = requestsession.get(url=finalurl)
        hatext = json.loads(haresponse.text)

        if(not '200' in str(haresponse)):
           print(mycolors.foreground.red + "\nThe search key couldn't be found on Malpedia.\n", mycolors.reset) 
           exit(1)

        if(bkg == 1):
            for key,value in hatext.items():
                print(mycolors.foreground.yellow + "Family:".ljust(13) + mycolors.reset + key)
                print(mycolors.foreground.lightcyan + "\nUpdated:".ljust(14) + mycolors.reset + value['updated'], end=' ')
                if (value['attribution']):
                    print(mycolors.foreground.lightcyan + "\nAttribution:".ljust(13), end=' ')
                    for i in value['attribution']:
                        print(mycolors.reset + str(i), end=' ')
                if (value['alt_names']):
                    print(mycolors.foreground.lightcyan + "\nAliases:".ljust(13), end=' ')
                    for i in value['alt_names']:
                        print(mycolors.reset + i, end=' ')
                if (value['common_name']):
                    print(mycolors.foreground.lightcyan + "\nCommon Name: ".ljust(13) + mycolors.reset + value['common_name'], end=' ')
                if (value['description']):
                    print(mycolors.foreground.lightcyan + "\nDescription: ".ljust(13) + mycolors.reset + ("\n".ljust(14)).join(textwrap.wrap(value['description'],width=110)), end=' ')

                if (value['urls']):
                    j = 0
                    for i in value['urls']:
                        if (j < 10):
                            print(mycolors.foreground.lightcyan + "\nURL_%d:".ljust(15) % j + mycolors.reset + ("\n".ljust(14)).join(textwrap.wrap(i,width=110)), end=' ')
                        if (j > 9 and j < 100):
                            print(mycolors.foreground.lightcyan + "\nURL_%d:".ljust(14) % j + mycolors.reset + ("\n".ljust(14)).join(textwrap.wrap(i,width=110)), end=' ')
                        if (j > 99):
                            print(mycolors.foreground.lightcyan + "\nURL_%d:".ljust(13) % j + mycolors.reset + ("\n".ljust(14)).join(textwrap.wrap(i,width=110)), end=' ')
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

    requestMALPEDIAAPI()

    try:

        resource = urlx
        requestsession = requests.Session( )
        requestsession.headers.update({'Content-Type': 'application/json'})
        requestsession.headers.update({'Authorization': 'apitoken ' + MALPEDIAAPI  })
        finalurl = '/'.join([resource, 'list', 'actors'])
        haresponse = requestsession.get(url=finalurl)
        hatext = json.loads(haresponse.text)

        if(not '200' in str(haresponse)):
           print(mycolors.foreground.red + "\nThe search key couldn't be found on Malpedia.\n", mycolors.reset) 
           exit(1)

        if(bkg == 1):
            print(mycolors.foreground.lightcyan + "\nActors:".ljust(13), end='\n'.ljust(11))
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

    requestMALPEDIAAPI()

    try:

        resource = urlx
        requestsession = requests.Session( )
        requestsession.headers.update({'Content-Type': 'application/json'})
        requestsession.headers.update({'Authorization': 'apitoken ' + MALPEDIAAPI  })
        finalurl = '/'.join([resource, 'list', 'samples'])
        haresponse = requestsession.get(url=finalurl)
        hatext = json.loads(haresponse.text)

        if(not '200' in str(haresponse)):
           print(mycolors.foreground.red + "\nThe search key couldn't be found on Malpedia.\n", mycolors.reset) 
           exit(1)

        if(bkg == 1):
            for key,value in hatext.items():
                print(mycolors.foreground.yellow + "Family:".ljust(11) + mycolors.reset + key, end=' ')
                for i in value:
                    for j in i.items():
                        for k in i.keys():
                            if (k == 'status'):
                                if (i['status']):
                                    print(mycolors.foreground.lightcyan + "\n\nStatus:".ljust(13) + mycolors.reset + str(i['status']), end='')
                            if (k == 'sha256'):
                                if (i['sha256']):
                                    print(mycolors.foreground.lightcyan + "\nHash:".ljust(12) + mycolors.reset + str(i['sha256']), end='')
                            if (k == 'version'):
                                if (i['version']):
                                    print(mycolors.foreground.lightcyan + "\nVersion:".ljust(12) + mycolors.reset + str(i['version']), end=' ')
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

    requestMALPEDIAAPI()

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
            print(mycolors.foreground.red + "\nThe search key couldn't be found on Malpedia.\n", mycolors.reset) 
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
                                print(mycolors.foreground.lightcyan + "\n\nSynonyms:".ljust(11), end=' ')
                                for x in value['synonyms']:
                                    print(mycolors.reset + str(x), end=' ')
                        if (key2 == 'refs'):
                            if (value['refs']):
                                for x in value['refs']:
                                    print(mycolors.foreground.lightcyan + "\nREFs:".ljust(11) + mycolors.reset + ("\n".ljust(11)).join(wrapper.wrap(str(x))).ljust(11), end=" ")
                if(key == 'families'):
                    for key3,value3 in value.items():
                        print("\n" + '-' * 112, end='')
                        print(mycolors.foreground.yellow + "\nFamily: ".ljust(11) + mycolors.reset  + key3)
                        if 'updated' in value3.keys():
                            if(value3['updated']):
                                print(mycolors.foreground.lightcyan + "Updated: ".ljust(10) + mycolors.reset + value3['updated' ])
                        if 'attribution' in value3.keys():
                            if(len(value3['attribution']) > 0):
                                print(mycolors.foreground.lightcyan + "Attrib.: ".ljust(9), end=' ')
                                for y in value3['attribution']:
                                    print(mycolors.reset + y, end=' ')
                        if 'alt_names' in value3.keys():
                            if(len(value3['alt_names']) > 0):
                                print(mycolors.foreground.lightcyan + "\nAliases: ".ljust(10), end=' ')
                                for y in value3['alt_names']:
                                    print(mycolors.reset + y, end=' ')
                        if 'common_name' in value3.keys():
                            if(value3['common_name']):
                                print(mycolors.foreground.lightcyan + "\nCommon: ".ljust(11) + mycolors.reset + value3['common_name' ], end=' ')
                        if 'sources' in value3.keys():
                            if(len(value3['sources']) > 0):
                                print(mycolors.foreground.lightcyan + "\nSources: ".ljust(11), end=' ')
                                for y in value3['sources']:
                                    print(mycolors.reset + y, end=' ')
                        if 'description' in value3.keys():
                            if value3['description']:
                                print(mycolors.foreground.lightcyan + "\nDescr.: ".ljust(11) + mycolors.reset + ("\n".ljust(11)).join(textwrap.wrap(str(value3['description']),width=100)), end=' ')
                        if 'urls' in value3.keys():
                            if(len(value3['urls']) > 0):
                                for y in value3['urls']:
                                    print(mycolors.foreground.lightcyan + "\nURLs: ".ljust(11) + mycolors.reset + ("\n".ljust(11)).join(wrapper.wrap(str(y))).ljust(11), end=" ")

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

    requestMALPEDIAAPI()

    try:

        resource = urlx
        requestsession = requests.Session( )
        requestsession.headers.update({'Content-Type': 'application/json'})
        requestsession.headers.update({'Authorization': 'apitoken ' + MALPEDIAAPI  })
        finalurl = '/'.join([resource, 'list', 'families'])
        haresponse = requestsession.get(url=finalurl)
        hatext = json.loads(haresponse.text)
        
        if(not '200' in str(haresponse)):
            print(mycolors.foreground.red + "\nThe search key couldn't be found on Malpedia.\n", mycolors.reset) 
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

    requestMALPEDIAAPI()

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
            print(mycolors.foreground.red + "\nThe search key couldn't be found on Malpedia.\n", mycolors.reset) 
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

    requestMALPEDIAAPI()

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
            print(mycolors.foreground.red + "\nThe search key couldn't be found on Malpedia.\n", mycolors.reset) 
            exit(1)

        if('200' in str(haresponse)):
            if (bkg == 1):
                open(myargs+".zip", 'wb').write(base64.b64decode(hatext['zipped']))
                print(mycolors.foreground.lightcyan + "\nSample successfuly downloaded from Malpedia!\n", mycolors.reset) 
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

    requestMALPEDIAAPI()

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
            print(mycolors.foreground.red + "\nThe search key couldn't be found on Malpedia.\n", mycolors.reset) 
            exit(1)

        if('200' in str(haresponse)):
            if (bkg == 1):
                open(myargs+".zip", 'wb').write(haresponse.content)
                print(mycolors.foreground.lightcyan + "\nA zip file named %s.zip containing Yara rules has been SUCCESSFULLY downloaded from Malpedia!\n" % myargs, mycolors.reset) 
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

    requestHAAPI()

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

    requestHAAPI()

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
        vtfinal = vtcheck(myhash, urlfilevt3, 0)
    
        if (bkg == 1):
            print((mycolors.foreground.yellow +  "%-70s" % package1), end=' ')
            print((mycolors.foreground.lightcyan +  "%-32s" % key1), end=' ')
            print((mycolors.reset + mycolors.foreground.lightcyan + "%8s" % vtfinal + mycolors.reset))
        else:
            print((mycolors.foreground.green + "%-70s" % package1), end=' ')
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
            print((mycolors.foreground.lightcyan + "%-70s" % package1), end=' ')
            print((mycolors.foreground.yellow + "%-34s" % key1), end=' ')
            print((mycolors.foreground.lightcyan + "%9s" % final), end='')
            if(avdetect == 'None'):
                print((mycolors.foreground.lightcyan + "%7s" % avdetect), end='')
            else:
                print((mycolors.foreground.lightcyan + "%6s%%" % avdetect), end='')
            print((mycolors.foreground.yellow + "%7s" % totalsignatures), end='')
            if(threatscore == 'None'):
                print((mycolors.foreground.lightred + "%12s" % threatscore), end='')
            else:
                print((mycolors.foreground.lightred + "%8s/100" % threatscore), end='')
            if (verdict == "malicious"):
                print((mycolors.foreground.lightred + "%20s" % verdict), end='\n')
            elif (verdict == "suspicious"):
                print((mycolors.foreground.yellow + "%20s" % verdict), end='\n')
            elif (verdict == "no specific threat"):
                print((mycolors.foreground.lightcyan + "%20s" % verdict), end='\n')
            else:
                verdict = 'not analyzed yet'
                print((mycolors.reset + "%20s" % verdict), end='\n')
        else:
            print((mycolors.foreground.cyan + "%-70s" % package1), end=' ')
            print((mycolors.foreground.green + "%-34s" % key1), end=' ')
            print((mycolors.foreground.cyan + "%9s" % final), end='')
            if (avdetect == 'None'):
                print((mycolors.foreground.purple + "%7s" % avdetect), end='')
            else:
                print((mycolors.foreground.purple + "%6s%%" % avdetect), end='')
            print((mycolors.foreground.green + "%7s" % totalsignatures), end='')
            if(threatscore == 'None'):
                print((mycolors.foreground.red + "%12s" % threatscore), end='')
            else:
                print((mycolors.foreground.red + "%8s/100" % threatscore), end='')
            if (verdict == "malicious"):
                print((mycolors.foreground.red + "%20s" % verdict), end='\n')
            elif (verdict == "suspicious"):
                print((mycolors.foreground.cyan + "%20s" % verdict), end='\n')
            elif (verdict == "no specific threat"):
                print((mycolors.foreground.green + "%20s" % verdict), end='\n')
            else:
                verdict = 'not analyzed yet'
                print((mycolors.reset + "%20s" % verdict), end='\n')


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
    vtfinal = vtcheck(key1, urlfilevt3, 0)
    if (bkg == 1):
        print((mycolors.foreground.yellow +  "%-70s" % package), end=' ')
        print((mycolors.foreground.lightcyan +  "%-32s" % key1), end=' ')
        print((mycolors.foreground.lightred + "%8s" % vtfinal + mycolors.reset))
    else:
        print((mycolors.foreground.green + "%-70s" % package), end=' ')
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
            for j in i.split("base.apk"):
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
        print("Package".center(70) + "Hash".center(34) + "Found?".center(12) + "AVdet".center(10) + "Sigs".center(5) + "Score".center(14) + "Verdict".center(14))
        print((162*'-').center(81))
        for key, value in dictAndroid.items():
            try:
                key1a = (key.split("==/",1)[1])
            except IndexError:
                key1a = key
            try:
                key1b = (key1a.split("-",1)[0]) 
            except IndexError:
                key1b = key1a
            checkandroidha(value, key1b)

    if(engine == 2):
        print(mycolors.reset + "\n")
        print("Package".center(70) +  "Hash".center(36) + "Virus Total".center(12))
        print((118*'-').center(59))
        for key, value in dictAndroid.items():
            try:
                key1a = (key.split("==/",1)[1])
            except IndexError:
                key1a = key
            try:
                key1b = (key1a.split("-",1)[0])
            except IndexError:
                key1b = key1a
            tm1 = tm1 + 1
            if tm1 % 4 == 0:
                time.sleep(61)
            checkandroidvt(value, key1b)

    if(engine == 3):
        print(mycolors.reset + "\n")
        print("Package".center(70) +  "Hash".center(36) + "Virus Total".center(12))
        print((118*'-').center(59))
        for key, value in dictAndroid.items():
            try:
                key1a = (key.split("==/",1)[1])
            except IndexError:
                key1a = key
            try:
                key1b = (key1a.split("-",1)[0])
            except IndexError:
                key1b = key1a
            checkandroidvtx(value, key1b)

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
            for j in i.split('base.apk'):
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
                newname = j[10:]

    except AttributeError:
        pass

    try:
        targetfile1 = newname.split('==/',1)[1]
        targetfile = targetfile1.split('-',1)[0]
        os.rename('base.apk', targetfile)
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
    targefile = ''

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
                newname = j[10:]

    except AttributeError:
        pass

    try:
        targetfile1 = newname.split('==/',1)[1]
        targetfile = targetfile1.split('-',1)[0]
        os.rename(r'base.apk',targetfile)
        myhash = sha256hash(targetfile)
        vtuploadfile(targetfile, urlfilevt3)
        if(bkg == 1):
            print(mycolors.foreground.yellow + "\tWaiting for 120 seconds...\n")
        if(bkg == 0):
            print(mycolors.foreground.purple + "\tWaiting for 120 seconds...\n")
        time.sleep(120)
        vthashwork(myhash, urlfilevt3, 1)


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
    vtpubpremiumx = 0
    malsharelist = 0
    malsharehash = ''
    hausoptionx = 0
    filecheckpoly = 0
    polycheck = 0
    androidoption = 0
    androidargx = ''
    metatype = 0
    alienvault = 0
    alienvaultargs = ''
    Q = 0
    T = 0 
    malpedia = 0
    malpediax = 0
    malpediaarg = ''
    malpediaargx = ''
    bazaar = 0
    bazaararg = ''
    triage = 0
    triagearg = ''
    virustotalarg = ''
    ipaddrvtx = ''
    ffpname = ''

    parser = argparse.ArgumentParser(prog=None, description="Malwoverview is a first response tool for threat hunting written by Alexandre Borges. This version is 5.3", usage= "python malwoverview.py -c <API configuration file> -d <directory> -o <0|1> -v <1-13> -V <virustotal arg> -a <1-15> -w <0|1> -A <filename> -l <1-7> -L <hash> -j <1-7> -J <URLhaus argument> -p <1-8> -P <polyswarm argument> -y <1-5> -Y <file name> -n <1-5> -N <argument> -m <1-8> -M <argument> -b <1-10> -B <arg> -x <1-7> -X <arg> -i <1-13> -I <INQUEST argument>")
    parser.add_argument('-c', '--config', dest='config', type=str, metavar = "CONFIG FILE", default = (USER_HOME_DIR + '.malwapi.conf'), help='Use a custom config file to specify API\'s.')
    parser.add_argument('-d', '--directory', dest='direct',type=str, metavar = "DIRECTORY", help='Specifies the directory containing malware samples to be checked against VIRUS TOTAL. Use the option -D to decide whether you are being using a public VT API or a Premium VT API.')
    parser.add_argument('-o', '--background', dest='backg', type=int,default = 1, metavar = "BACKGROUND", help='Adapts the output colors to a light background color terminal. The default is dark background color terminal.')
    parser.add_argument('-v', '--virustotal_option', dest='virustotaloption', type=int,default = 0, metavar = "VIRUSTOTAL", help='-v 1: given a file using -V option, it queries the VIRUS TOTAL database (API v.3) to get the report for the given file through -V option.; -v 2: it shows an antivirus report for a given file using -V option (API v.3); -v 3: equal to -v2, but the binary\'s IAT and EAT are also shown (API v.3); -v 4: it extracts the overlay; -v 5: submits an URL to VT scanning; -v 6: submits an IP address to Virus Total; -v 7: this options gets a report on the provided domain from Virus Total; -v 8: verifies a given hash against Virus Total; -v 9: submits a sample to VT (up to 32 MB). Use forward slash to specify the target file on Windows systems. Demands passing sample file with -V option; -v 10: verifies hashes from a provided file through option -V. This option uses public VT API v.3; -v 11: verifies hashes from a provided file through option -V. This option uses Premium API v.3; -v 12: it shows behaviour information of a sample given a hash through option -V. This option uses VT API v.3; -v 13: it submits LARGE files (above 32 MB) to VT using API v.3;')
    parser.add_argument('-V', '--virustotal_arg', dest='virustotalarg', type=str, metavar = "VIRUSTOTAL_ARG", help='Provides arguments for -v option.')
    parser.add_argument('-a', '--hybrid_option', dest='haoption', type=int,default = 0, metavar = "HYBRID_ANALYSIS", help='This parameter fetches reports from HYBRID ANALYSIS, download samples and submits samples to be analyzed. The possible values are: 1: gets a report for a given hash or sample from a Windows 7 32-bit environment; 2: gets a report for a given hash or sample from a Windows 7 32-bit environment (HWP Support); 3: gets a report for given hash or sample from a Windows 64-bit environment; 4: gets a report for a given hash or sample from an Android environment; 5: gets a report for a given hash or sample from a Linux 64-bit environment; 6: submits a sample to Windows 7 32-bit environment; 7. submits a sample to Windows 7 32-bit environment with HWP support environment; 8. submits a sample to Windows 7 64-bit environment ; 9. submits a sample to an Android environment ; 10. submits a sample to a Linux 64-bit environment; 11. downloads a sample from a Windows 7 32-bit environment; 12. downloads a sample from a Windows 7 32-bit HWP environment; 13. downloads a sample from a Windows 7 64-bit environment; 14. downloads a sample from an Android environment; 15. downloads a sample from a Linux 64-bit environment.')
    parser.add_argument('-A', '--ha_arg', dest='haarg', type=str, metavar = "SUBMIT_HA", help='Provides an argument for -a option from HYBRID ANALYSIS.')
    parser.add_argument('-D', '--vtpubpremium', dest='vtpubpremium', type=int,default = 0, metavar = "VT_PUBLIC_PREMIUM", help='This option must be used with -d option. Possible values: <0> it uses the Premium VT API v3 (default); <1> it uses the Public VT API v3.')
    parser.add_argument('-l', '--malsharelist', dest='malsharelist', type=int,default = 0, metavar = "MALSHARE_HASHES", help='This option performs download a sample and shows hashes of a specific type from the last 24 hours from MALSHARE repository. Possible values are: 1: Download a sample; 2: PE32 (default) ; 3: ELF ; 4: Java; 5: PDF ; 6: Composite(OLE); 7: List of hashes from past 24 hours.')
    parser.add_argument('-L', '--malshare_hash', dest='malsharehash', type=str, metavar = "MALSHARE_HASH_SEARCH", help='Provides a hash as argument for downloading a sample from MALSHARE repository.')
    parser.add_argument('-j', '--haus_option', dest='hausoption', type=int, default = 0,  metavar = "HAUS_OPTION", help='This option fetches information from URLHaus depending of the value passed as argument: 1: performs download of the given sample; 2: queries information about a provided hash ; 3: searches information about a given URL; 4: searches a malicious URL by a given tag (case sensitive); 5: searches for payloads given a tag; 6: retrives a list of downloadable links to recent payloads; 7: retrives a list of recent malicious URLs.')
    parser.add_argument('-J', '--haus_arg', dest='hausarg', type=str, metavar = "HAUS_ARG", help='Provides argument to -j option from URLHaus.')
    parser.add_argument('-p', '--poly_option', dest='polyoption', type=int,default = 0, metavar = "POLY_OPTION", help='(Only for Linux) This option is related to POLYSWARM operations: 1. searches information related to a given hash provided using -P option; 2. submits a sample provided by -P option to be analyzed by Polyswarm engine ; 3. Downloads a sample from Polyswarm by providing the hash throught option -P .Attention: Polyswarm enforces a maximum of 20 samples per month; 4. searches for similar samples given a sample file thought option -P; 5. searches for samples related to a provided IP address through option -P; 6. searches for samples related to a given domain provided by option -P; 7. searches for samples related to a provided URL throught option -P; 8. searches for samples related to a provided malware family given by option -P.')
    parser.add_argument('-P', '--poly_arg', dest='polyarg', type=str, metavar = "POLYSWARM_ARG", help='(Only for Linux) Provides an argument for -p option from POLYSWARM.')
    parser.add_argument('-y', '--android_option', dest='androidoption', type=int, default = 0, metavar = "ANDROID_OPTION", help='This ANDROID option has multiple possible values: <1>: Check all third-party APK packages from the USB-connected Android device against Hybrid Analysis using multithreads. Notes: the Android device does not need to be rooted and the system does need to have the adb tool in the PATH environment variable; <2>: Check all third-party APK packages from the USB-connected Android device against VirusTotal using Public API (slower because of 60 seconds delay for each 4 hashes). Notes: the Android device does not need to be rooted and the system does need to have adb tool in the PATH environment variable; <3>: Check all third-party APK packages from the USB-connected Android device against VirusTotal using multithreads (only for Private Virus API). Notes: the Android device does not need to be rooted and the system needs to have adb tool in the PATH environment variable; <4> Sends an third-party APK from your USB-connected Android device to Hybrid Analysis; 5. Sends an third-party APK from your USB-connected Android device to Virus-Total.')
    parser.add_argument('-Y', '--android_arg', dest='androidarg', type=str, metavar = "ANDROID_ARG", help='This option provides the argument for -y from ANDROID.')
    parser.add_argument('-n', '--alienvault', dest='alienvault', type=int, default = 0, metavar = "ALIENVAULT", help='Checks multiple information from ALIENVAULT. The possible values are: 1: Get the subscribed pulses ; 2: Get information about an IP address; 3: Get information about a domain; 4: Get information about a hash; 5: Get information about a URL.')
    parser.add_argument('-N', '--alienvaultargs', dest='alienvaultargs', type=str, metavar = "ALIENVAULT_ARGS", help='Provides argument to ALIENVAULT -n option.')
    parser.add_argument('-m', '--malpedia', dest='malpedia', type=int, default = 0, metavar = "MALPEDIA", help='This option is related to MALPEDIA and presents different meanings depending on the chosen value. Thus, 1: List meta information for all families ; 2: List all actors ID ; 3: List all available payloads organized by family from Malpedia; 4: Get meta information from an specific actor, so it is necessary to use the -M option. Additionally, try to confirm the correct actor ID by executing malwoverview with option -m 3; 5: List all families IDs; 6: Get meta information from an specific family, so it is necessary to use the -M option. Additionally, try to confirm the correct family ID by executing malwoverview with option -m 5; 7: Get a malware sample from malpedia (zip format -- password: infected). It is necessary to specify the requested hash by using -M option; 8: Get a zip file containing Yara rules for a specific family (get the possible families using -m 5), which must be specified by using -M option.')
    parser.add_argument('-M', '--malpediarg', dest='malpediaarg', type=str, metavar = "MALPEDIAARG", help='This option provides an argument to the -m option, which is related to MALPEDIA.')
    parser.add_argument('-b', '--bazaar', dest='bazaar', type=int, default = 0, metavar = "BAZAAR", help='Checks multiple information from MALWARE BAZAAR and THREATFOX. The possible values are: 1: (Bazaar) Query information about a malware hash sample ; 2: (Bazaar) Get information and a list of malware samples associated and according to a specific tag; 3: (Bazaar) Get a list of malware samples according to a given imphash; 4: (Bazaar) Query latest malware samples; 5: (Bazaar) Download a malware sample from Malware Bazaar by providing a SHA256 hash. The downloaded sample is zipped using the following password: infected; 6: (ThreatFox) Get current IOC dataset from last x days given by option -B (maximum of 7 days); 7: (ThreatFox) Search for the specified IOC on ThreatFox given by option -B; 8: (ThreatFox) Search IOCs according to the specified tag given by option -B; 9: (ThreatFox) Search IOCs according to the specified malware family provided by option -B; 10. (ThreatFox) List all available malware families.')
    parser.add_argument('-B', '--bazaararg', dest='bazaararg', type=str, metavar = "BAZAAR_ARG", help='Provides argument to -b MALWARE BAZAAR and THREAT FOX option. If you specified "-b 1" then the -B\'s argument must be a hash; If you specified "-b 2" then -B\'s argument must be a malware tag; If you specified "-b 3" then the argument must be a imphash; If you specified "-b 4", so the argument must be "100 or time", where "100" lists last "100 samples" and "time" lists last samples added to Malware Bazaar in the last 60 minutes; If you specified "-b 5" then the -B\'s argument must be a SHA256 hash; If you specified "-b 6", so the -B\'s value is the number of DAYS to filter IOCs. The maximum is 7 (days); If you used "-b 7" so the -B\'s argument is the IOC you want to search for; If you used "-b 8", so the -B\'s argument is the TAG you want search for; If you used "-b 9", so the -B argument is the malware family you want to search for;')
    parser.add_argument('-x', '--triage', dest='triage', type=int,default = 0, metavar = "TRIAGE", help='Provides information from TRIAGE according to the specified value: <1> this option gets sample\'s general information by providing an argument with -X option in the following possible formats: sha256:<value>, sha1:<value>, md5:<value>, family:<value>, score:<value>, tag:<value>, url:<value>, wallet:<value>, ip:<value>; <2> Get a sumary report for a given Triage ID (got from option -x 1) ; <3> Submit a sample for analysis ; <4> Submit a sample through a URL for analysis ; <5> Download sample specified by the Triage ID; <6> Download pcapng file from sample associated to given Triage ID; <7> Get a dynamic report for the given Triage ID (got from option -x 1);')
    parser.add_argument('-X', '--triagearg', dest='triagearg', type=str, metavar = "TRIAGE_ARG", help='Provides argument for options especified by -x option. Pay attention: the format of this argument depends on provided -x value.')
    parser.add_argument('-i', '--inquest', dest='inquest', type=int, default = 0, metavar = "INQUEST", help='Retrieves multiple information from INQUEST. The possible values are: 1: Downloads a sample; 2: Retrives information about a sample given a SHA256; 3: Retrieves information about a sample given a MD5 hash; 4: Gets the most recent list of threats. To this option, the -I argument must be "list" (lowercase and without double quotes) ; 5: Retrives threats related to a provided domain; 6. Retrieves a list of samples related to the given IP address; 7. Retrives a list of sample related to the given e-mail address; 8. Retrieves a list of samples related to the given filename; 9. Retrieves a list of samples related to a given URL; 10. Retrieves information about a specified IOC; 11. List a list of IOCs. Note: you must pass "list" (without double quotes) as argument to -I; 12. Check for a given keyword in the reputation database; 13. List artifacts in the reputation dabatabse. Note: you must pass "list" (without double quotes) as argument to -I.')
    parser.add_argument('-I', '--inquestarg', dest='inquestarg', type=str, metavar = "INQUEST_ARG", help='Provides argument to INQUEST -i option.')

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
        TRIAGEAPI = config_file['TRIAGE']['TRIAGEAPI']
        INQUESTAPI = config_file['INQUEST']['INQUESTAPI']

    except KeyError:
        pass


    optval = [0,1]
    optval1 = [0,1,2]
    optval2 = [0,1,2,3,4]
    optval3 = [0,1,2,3,4,5,6]
    optval4 = [0, 1, 2, 3]
    optval5 = [0, 1, 2, 3, 4, 5]
    optval6 = [0, 1, 2, 3, 4, 5, 6, 7, 8]
    optval7 = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10]
    optval8 = [0, 1, 2, 3, 4, 5, 6, 7]
    optval9 = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13]
    optval10 = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]
    repo = args.direct
    bkg = args.backg
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

    if (virustotaloptionx == 1):
        ffpname = virustotalargx
        filetemp = virustotalargx

    if (virustotaloptionx == 2):
        showreport = 1
        ffpname = virustotalargx
        filetemp = virustotalargx

    if (virustotaloptionx == 3):
        ie = 1
        ffpname = virustotalargx
        filetemp = virustotalargx

    if (virustotaloptionx == 4):
        ovrly = 1
        ffpname = virustotalargx
        filetemp = virustotalargx

    if (virustotaloptionx == 5):
        urltemp = virustotalargx

    if (virustotaloptionx == 6):
        ipaddrvtx = virustotalargx
    
    if (virustotaloptionx == 7):
        domaintemp = virustotalargx

    if (virustotaloptionx == 8):
        hashtemp = virustotalargx

    if (virustotaloptionx == 9):
        filetemp = virustotalargx
    
    if (virustotaloptionx == 10):
        hash_file = virustotalargx

    if (virustotaloptionx == 11):
        hash_file = virustotalargx
    
    if (virustotaloptionx == 12):
        hash_value = virustotalargx

    if (virustotaloptionx == 13):
        file_item = virustotalargx

    if (haoptionx == 1):
        ffpname = haargx

    if (haoptionx == 2):
        ffpname = haargx

    if (haoptionx == 3):
        ffpname = haargx

    if (haoptionx == 4):
        ffpname = haargx

    if (haoptionx == 5):
        ffpname = haargx

    if (haoptionx == 6):
        ffpname = haargx

    if (haoptionx == 7):
        ffpname = haargx

    if (haoptionx == 8):
        ffpname = haargx

    if (haoptionx == 9):
        ffpname = haargx
    
    if (haoptionx == 10):
        ffpname = haargx

    if (haoptionx == 11):
        filecheckha = 1

    if ((ha != 0) and (ha < 6)):
        xx = ha - 1
        Q = 1
    
    if (os.path.isfile(ffpname)):
        fprovided = 1
    else:
        fprovided = 0

    if ie == 1:
        if fprovided == 0:
            parser.print_help()
            print(mycolors.reset)
            exit(0)

    if (args.haoption) not in optval10:
        parser.print_help()
        print(mycolors.reset)
        exit(0)
    elif ie == 1:
        if fprovided == 0:
            parser.print_help()
            print(mycolors.reset)
            exit(0)

    if (showreport == 1):
        if (fprovided == 0 or virustotaloptionx == 0):
            parser.print_help()
            print(mycolors.reset)
            exit(0)

    if (args.alienvault) not in optval5:
        parser.print_help()
        print(mycolors.reset)
        exit(0)

    if (args.hausoption) not in optval8:
        parser.print_help()
        print(mycolors.reset)
        exit(0)

    if (args.polyoption) not in optval6:
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

    if (args.triage) not in optval8:
        parser.print_help()
        print(mycolors.reset)
        exit(0)
    
    if (args.inquest) not in optval9:
        parser.print_help()
        print(mycolors.reset)
        exit(0)

    if ((not virustotalargx) and (virustotaloptionx == 0) and (not args.direct) and (fprovided == 0) and (not urltemp) and (not hashtemp) and (not filetemp) and (not haargx) and (not domaintemp) and (mallist == 0) and (not args.malsharehash) and (args.hausoption == 0) and (polyoptionx == 0) and (not polyargx) and (androidoptionx == 0) and (not androidargx) and (alienx == 0) and (not alienargsx) and (not malpediaargx) and (malpediax == 0) and (bazaarx == 0) and (not bazaarargx) and (triagex == 0) and (not triageargx) and (inquestx ==  0) and (not inquestargx)):

        parser.print_help()
        print(mycolors.reset)
        exit(0)

    if (args.backg) not in optval:
        parser.print_help()
        print(mycolors.reset)
        sys.exit(0)

    if (args.malsharelist) not in optval8:
        parser.print_help()
        print(mycolors.reset)
        sys.exit(0)

    if (Q == 1):
        if ((virustotaloptionx == 0) and (haoptionx == 0)):
            parser.print_help()
            print(mycolors.reset)
            sys.exit(0)
    elif (Q == 1):
        if (not repo):
            parser.print_help()
            print(mycolors.reset)
            sys.exit(0)
    if (args.vtpubpremium) not in optval:
        parser.print_help()
        print(mycolors.reset)
        sys.exit(0)

    if (args.virustotaloption) not in optval9:
        parser.print_help()
        print(mycolors.reset)
        sys.exit(0)
    elif ovrly == 1:
        if fprovided == 0:
            parser.print_help()
            print(mycolors.reset)
            exit(0)

    if (windows == 1):
        init(convert = True)

    if (not urltemp):
        if (not args.direct):
            if (fprovided == 0 ):
                if (not hashtemp):
                    if (not filetemp):
                        if (not haargx):
                            if (not domaintemp):
                                if (args.malsharelist == 0):
                                    if (not args.malsharehash):
                                        if (not args.hausoption):
                                            if (args.androidoption == 0):
                                                if (not args.androidarg):
                                                    if (not ipaddrvtx):
                                                        if (args.alienvault == 0):
                                                            if (not args.alienvaultargs):
                                                                if (args.bazaar == 0):
                                                                    if (not args.bazaararg):
                                                                        if (not malpediaargx):
                                                                            if (malpediax == 0):
                                                                                if (triagex == 0):
                                                                                    if (not args.triagearg):
                                                                                        if (args.polyoption == 0):
                                                                                            if (virustotaloptionx == 0):
                                                                                                if (inquestx == 0):
                                                                                                    if (not args.inquestarg):
                                                                                                        parser.print_help()
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
   
    if (0 < haoptionx <= 10):
        if (haargx):
            if (os.path.isfile(haargx)) == True:
                filecheckha = 1

    if (polyoptionx == 1 or polyoptionx == 3):
        if ((len(polyargx)==32) or (len(polyargx)==40) or (len(polyargx)==64)):
            if (polyoptionx == 1):
                polyhashsearch(polyargx, 0)
            if (polyoptionx == 3):
                polyhashsearch(polyargx, 1)
            print(mycolors.reset)
            exit(0)

    if (polyoptionx == 2):
        if (os.path.isfile(polyargx)) == True:
            polyfile(polyargx)
            print(mycolors.reset)
            exit(0)
        elif (bkg == 0):
            print(mycolors.foreground.red + "\nYou didn't provided a valid file.\n")
            print(mycolors.reset)
            exit(1)
        else:
            print(mycolors.foreground.yellow + "\nYou didn't provided a valid file.\n")
            print(mycolors.reset)
            exit(1)

    if (polyoptionx >=4):
        polymetasearch(polyargx, polyoptionx)
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

    if (triagex == 1):
        argx = triageargx
        triageurlx = triageurl + "search?query="
        triage_search(argx, triageurlx)
        print(mycolors.reset)
        exit(0)

    if (triagex == 2):
        argx = triageargx
        triageurlx = triageurl
        triage_summary(argx, triageurlx)
        print(mycolors.reset)
        exit(0)

    if (triagex == 3):
        argx = triageargx
        triageurlx = triageurl
        triage_sample_submit(argx, triageurlx)
        print(mycolors.reset)
        exit(0)

    if (triagex == 4):
        argx = triageargx
        triageurlx = triageurl
        triage_url_sample_submit(argx, triageurlx)
        print(mycolors.reset)
        exit(0)

    if (triagex == 5):
        argx = triageargx
        triageurlx = triageurl
        triage_download(argx, triageurlx)
        print(mycolors.reset)
        exit(0)

    if (triagex == 6):
        argx = triageargx
        triageurlx = triageurl
        triage_download_pcap(argx, triageurlx)
        print(mycolors.reset)
        exit(0)

    if (triagex == 7):
        argx = triageargx
        triageurlx = triageurl
        triage_dynamic(argx, triageurlx)
        print(mycolors.reset)
        exit(0)
    
    if (inquestx == 1):
        argx = inquestargx
        inquesturlx = inquesturl
        inquest_download(argx, inquesturlx)
        print(mycolors.reset)
        exit(0)
    
    if (inquestx == 2):
        argx = inquestargx
        inquesturlx = inquesturl
        inquest_hash(argx, inquesturlx)
        print(mycolors.reset)
        exit(0)
    
    if (inquestx == 3):
        argx = inquestargx
        inquesturlx = inquesturl
        inquest_hash_md5(argx, inquesturlx)
        print(mycolors.reset)
        exit(0)
 
    if (inquestx == 4):
        argx = inquestargx
        inquesturlx = inquesturl
        inquest_list(argx, inquesturlx)
        print(mycolors.reset)
        exit(0)

    if (inquestx == 5):
        argx = inquestargx
        inquesturlx = inquesturl
        inquest_domain(argx, inquesturlx)
        print(mycolors.reset)
        exit(0)

    if (inquestx == 6):
        argx = inquestargx
        inquesturlx = inquesturl
        inquest_ip(argx, inquesturlx)
        print(mycolors.reset)
        exit(0)

    if (inquestx == 7):
        argx = inquestargx
        inquesturlx = inquesturl
        inquest_email(argx, inquesturlx)
        print(mycolors.reset)
        exit(0)

    if (inquestx == 8):
        argx = inquestargx
        inquesturlx = inquesturl
        inquest_filename(argx, inquesturlx)
        print(mycolors.reset)
        exit(0)

    if (inquestx == 9):
        argx = inquestargx
        inquesturlx = inquesturl
        inquest_url(argx, inquesturlx)
        print(mycolors.reset)
        exit(0)

    if (inquestx == 10):
        argx = inquestargx
        inquesturlx = inquesturl2
        inquest_ioc_search(argx, inquesturlx)
        print(mycolors.reset)
        exit(0)
 
    if (inquestx == 11):
        argx = inquestargx
        inquesturlx = inquesturl2
        inquest_ioc_list(argx, inquesturlx)
        print(mycolors.reset)
        exit(0)

    if (inquestx == 12):
        argx = inquestargx
        inquesturlx = inquesturl3
        inquest_rep_search(argx, inquesturlx)
        print(mycolors.reset)
        exit(0)
 
    if (inquestx == 13):
        argx = inquestargx
        inquesturlx = inquesturl3
        inquest_rep_list(argx, inquesturlx)
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

    if (polyoptionx == 2):
        if (filecheckpoly == 1):
            polyfile(polyargx)
            print(mycolors.reset)
            exit(0)

    if (virustotaloptionx == 1):
        if (filecheck == 1):
            filechecking_v3(virustotalargx, urlfilevt3, 0, 0, 0)
            print(mycolors.reset)
            exit(0)
    
    if (virustotaloptionx == 2):
        if (filecheck == 1):
            filechecking_v3(virustotalargx, urlfilevt3, 1, 0, 0)
            print(mycolors.reset)
            exit(0)
    
    if (virustotaloptionx == 3):
        if (filecheck == 1):
            filechecking_v3(virustotalargx, urlfilevt3, 1, 1, 0)
            print(mycolors.reset)
            exit(0)
    
    if (virustotaloptionx == 4):
        if (filecheck == 1):
            filechecking_v3(virustotalargx, urlfilevt3, 1, 0, 1)
            print(mycolors.reset)
            exit(0)
        
    if (virustotaloptionx == 5):
        if (urlcheck == 1):
            vturlwork(urltemp,urlurlvt3)
            print(mycolors.reset)
            exit(0)

    if (virustotaloptionx == 6):
        if (ipaddrvtx):
            vtipwork(ipaddrvtx, urlipvt3)
            print(mycolors.reset)
            exit(0)

    if (virustotaloptionx == 7):
        if (domaincheck == 1):
            vtdomainwork(domaintemp,urldomainvt3)
            print(mycolors.reset)
            exit(0)

    if (virustotaloptionx == 8):
        vthashwork(hashtemp, urlfilevt3, 1)
        print(mycolors.reset)
        exit(0)

    if (virustotaloptionx == 9):
        vtuploadfile(filetemp, urlfilevt3)
        print(mycolors.reset)
        exit(0)

    if (virustotaloptionx == 10):
        apitype = 1
        vtbatchcheck(hash_file, urlfilevt3, apitype)
        print(mycolors.reset)
        exit(0)

    if (virustotaloptionx == 11):
        apitype = 0
        vtbatchcheck(hash_file, urlfilevt3, apitype)
        print(mycolors.reset)
        exit(0)

    if (virustotaloptionx == 12):
        vtbehavior(hash_value, urlfilevt3)
        print(mycolors.reset)
        exit(0)

    if (virustotaloptionx == 13):
        vtlargefile(file_item, urlfilevt3)
        print(mycolors.reset)
        exit(0)

    if (haoptionx == 1):
        xx = 0
        if(filecheckha == 1):
            hashow(calchash(haargx))
        else:
            hashow(haargx)
        print(mycolors.reset)
        exit(0)
    
    if (haoptionx == 2):
        xx = 1
        if(filecheckha == 1):
            hashow(calchash(haargx))
        else:
            hashow(haargx)
        print(mycolors.reset)
        exit(0)

    if (haoptionx == 3):
        xx = 2
        if(filecheckha == 1):
            hashow(calchash(haargx))
        else:
            hashow(haargx)
        print(mycolors.reset)
        exit(0)

    if (haoptionx == 4):
        xx = 3
        if(filecheckha == 1):
            hashow(calchash(haargx))
        else:
            hashow(haargx)
        print(mycolors.reset)
        exit(0)

    if (haoptionx == 5):
        xx = 4
        if(filecheckha == 1):
            hashow(calchash(haargx))
        else:
            hashow(haargx)
        print(mycolors.reset)
        exit(0)

    if (haoptionx == 6):
        if (filecheckha == 1):
            xx = 0
            hafilecheck(haargx)
        else:
            if (bkg == 1):
                print(mycolors.foreground.lightred + "\nYou didn't provide a valid file!\n")
            if (bkg == 0):
                print(mycolors.foreground.red + "\nYou didn't provide a valid file!\n")
        print(mycolors.reset)
        exit(0)
    
    if (haoptionx == 7):
        if (filecheckha == 1):
            xx = 1
            hafilecheck(haargx)
        else:
            if (bkg == 1):
                print(mycolors.foreground.lightred + "\nYou didn't provide a valid file!\n")
            if (bkg == 0):
                print(mycolors.foreground.red + "\nYou didn't provide a valid file!\n")
        print(mycolors.reset)
        exit(0)
    
    if (haoptionx == 8):
        if (filecheckha == 1):
            xx = 2
            hafilecheck(haargx)
        else:
            if (bkg == 1):
                print(mycolors.foreground.lightred + "\nYou didn't provide a valid file!\n")
            if (bkg == 0):
                print(mycolors.foreground.red + "\nYou didn't provide a valid file!\n")
        print(mycolors.reset)
        exit(0)
    
    if (haoptionx == 9):
        if (filecheckha == 1):
            xx = 3
            hafilecheck(haargx)
        else:
            if (bkg == 1):
                print(mycolors.foreground.lightred + "\nYou didn't provide a valid file!\n")
            if (bkg == 0):
                print(mycolors.foreground.red + "\nYou didn't provide a valid file!\n")
        print(mycolors.reset)
        exit(0)
    
    if (haoptionx == 10):
        if (filecheckha == 1):
            xx = 4
            hafilecheck(haargx)
        else:
            if (bkg == 1):
                print(mycolors.foreground.lightred + "\nYou didn't provide a valid file!\n")
            if (bkg == 0):
                print(mycolors.foreground.red + "\nYou didn't provide a valid file!\n")
        print(mycolors.reset)
        exit(0)

    if (haoptionx == 11):
        xx = 0
        downhash(haargx)
        print(mycolors.reset)
        exit(0)
    
    if (haoptionx == 12):
        xx = 1
        downhash(haargx)
        print(mycolors.reset)
        exit(0)

    if (haoptionx == 13):
        xx = 2
        downhash(haargx)
        print(mycolors.reset)
        exit(0)

    if (haoptionx == 14):
        xx = 3
        downhash(haargx)
        print(mycolors.reset)
        exit(0)

    if (haoptionx == 15):
        xx = 4
        downhash(haargx)
        print(mycolors.reset)
        exit(0)

    if (mallist != 0 and mallist >= 2):
        malsharelastlist(maltype)
        print(mycolors.reset)
        exit(0)

    if (malhash and mallist == 1):
        if (malhash):
            if ((len(malhash)==32) or (len(malhash)==40) or (len(malhash)==64)):
                hashcheck = 1
        if (hashcheck == 1):
            malsharedown(malhash)
        print(mycolors.reset)
        exit(0)

    if (androidoptionx == 1):
        engine = 1
        checkandroid(engine)
        print(mycolors.reset)
        exit(0)

    if (androidoptionx == 2):
        engine = 2
        checkandroid(engine)
        print(mycolors.reset)
        exit(0)
    
    if (androidoptionx == 3):
        engine = 3
        checkandroid(engine)
        print(mycolors.reset)
        exit(0)
    
    if (androidoptionx == 4):
        xx = 3
        sendandroidha(androidargx)
        print(mycolors.reset)
        exit(0)
    
    if (androidoptionx == 5):
        sendandroidvt(androidargx)
        print(mycolors.reset)
        exit(0)

    if (hausoptionx == 1):
        if (len(hausargx)==64):
                hashcheck = 1
        if (hashcheck == 1):
            haussample(hausargx, hausd)
        print(mycolors.reset)
        exit(0)

    if (hausoptionx == 2):
        if ((len(hausargx)==32) or (len(hausargx)==64)):
            hashcheck = 1
        if (hashcheck == 1):
            haushashsearch(hausargx, hausph)
        print(mycolors.reset)
        exit(0)

    if (hausoptionx == 3):
        if (validators.url(hausargx)) == True:
            hauscheck = 1
        elif (bkg == 0): 
            print(mycolors.foreground.red + "\nYou didn't provided a valid URL.\n")
            print(mycolors.reset)
            exit(1)
        else:
            print(mycolors.foreground.yellow + "\nYou didn't provided a valid URL.\n")
            print(mycolors.reset)
            exit(1)

        if ((hausargx) and (hauscheck == 1)):
            urlhauscheck(hausargx, hausq)
            print(mycolors.reset)
            exit(0)

    if (hausoptionx == 4):
        haustagsearchroutine(hausargx, haust)
        print(mycolors.reset)
        exit(0)

    if (hausoptionx == 5):
        haussigsearchroutine(hausargx, haussig)
        print(mycolors.reset)
        exit(0)
    
    if(hausoptionx == 6):
        hauspayloadslist(hausp)
        print(mycolors.reset)
    
    if(hausoptionx == 7):
        hausgetbatch(hausb)
        print(mycolors.reset)

    if (repo is not None):
        repository = repo
        vtdirchecking(repository, urlfilevt3, vtpubpremiumx)
