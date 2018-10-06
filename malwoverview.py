#!/usr/bin/python

# Copyright (C)  2018 Alexandre Borges <ab@blackstormsecurity.com>
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


# Malwoverview.py: version 1.4.5

import os
import sys
import re
import pefile
import peutils
import magic
import optparse
import requests
import hashlib
import json
import time
from requests.auth import HTTPBasicAuth
from colorama import init, Fore, Back, Style

#VTAPI = '<----ENTER YOUR API HERE and UNCOMMENT THE LINE---->'
#HAAPI = '<----ENTER YOUR API HERE and UNCOMMENT THE LINE---->'
#HASECRET = '<----ENTER YOUR SECRET HERE and UNCOMMENT THE LINE---->'

haurl = 'https://www.hybrid-analysis.com'
url = 'https://www.virustotal.com/vtapi/v2/file/report'
param = 'params'
user_agent = {'Falcon Sandbox'}

F = []
H = []
final=''
tm = 0

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
        for entry in mype2.DIRECTORY_ENTRY_IMPORT:
          for imptab in entry.imports:
              x = hex(imptab.address), imptab.name
              I.append(x)
    return I

def listsections(fname):
   
    pe=pefile.PE(fname)
    for sect in pe.sections:
        print ("Sections: %8s" % filter(lambda k: '\x00' not in k, str(sect.Name))), 
        print ("%4.2f" % sect.get_entropy())

def impext(targetfile):
    
    if (bkg == 1):
        print (Fore.WHITE)
    else:
        print (Fore.BLACK)
    print ("\nImported Functions".ljust(40))
    print (110*'-').ljust(110) 
    IR = []
    IR = sorted(listimports(targetfile),key=keysort)
    dic={ }
    dic = dict(IR)
    d = iter(dic.items())
    IX = []
    for key,value in sorted(d, key=keysort):
        IX.append(str(value)) 
    Y = iter(IX)
            
    for i in Y:
        if i is None:
            break

        while (i == 'None'):
            i = next(Y, None)

        if i is None:
                break
        print (Fore.CYAN + "%-40s" % i),
        w = next(Y, None)
        if w is None:
            break
        if (w == 'None'):
            w = next(Y, None)
        if w is None:
            break
        print (Fore.GREEN + "%-40s" % w),
        t = next(Y, None)
        if t is None:
            break
        if (t == 'None'):
            t = next(Y, None)
        if t is None:
            break
        if (bkg == 1):
            print (Fore.YELLOW + "%-40s" % t)
        else:
            print (Fore.MAGENTA + "%-40s" % t )
           
    if (bkg == 1):
        print (Fore.WHITE)
    else:
        print (Fore.BLACK)
    print ("\n\nExported Functions".ljust(40))
    print (110*'-').ljust(110) 
    ER = []
    ER = sorted(listexports(targetfile),key=keysort)
    dic2={ }
    dic2 = dict(ER)
    d2 = iter(dic2.items())
    EX = []
    for key, value in sorted(d2, key=keysort):
        EX.append(str(value))
    Y2 = iter(EX)
    for i in Y2:
        if i is None:
            break
        while (i == 'None'):
            i = next(Y2, None)
        if i is None:
            break
        print (Fore.YELLOW + "%-40s" % i),
        w = next(Y2, None)
        if w is None:
            break
        if (w == 'None'):
            w = next(Y2, None)
        if w is None:
            break
        print (Fore.GREEN + "%-40s" % w),
        t = next(Y2, None)
        if t is None:
            break
        if (t == 'None'):
            t = next(Y2, None)
        if t is None:
            break
        if (bkg == 1):
            print (Fore.CYAN + "%-40s" % t)
        else:
            print (Fore.BLUE + "%-40s" % t)
                
def vtcheck(fname, url, param): 

    pos = ''
    total = ''
    vttext = ''
    response = ''
    
    try:

        resource=sha256hash(fname)
        params = {'apikey': VTAPI , 'resource': resource}
        response = requests.get(url, params=params)
        vttext = json.loads(response.text)
        rc = (vttext['response_code'])
        if (rc == 0):
            final = '   Not Found'
            return final 
        pos = str(vttext['positives'])
        total = str(vttext['total'])
        final = (pos + "/" + total)
        rc = str(vttext['response_code'])

        return final

    except ValueError:
        final = '     '
        return final

def vtshow(fname, url, param): 

    vttext = ''
    response = ''
   
    try:
        resource=sha256hash(fname)
        params = {'apikey': VTAPI , 'resource': resource}
        response = requests.get(url, params=params)
        vttext = json.loads(response.text)

        rc = (vttext['response_code'])
        if (rc == 0):
            final = 'Not Found'
            return final 

        if ('Avast' in vttext['scans']):
            print Fore.RED + "Avast:".ljust(13),vttext['scans']['Avast']['result']
    
        if ('Avira' in vttext['scans']):
            print "Avira:".ljust(13),vttext['scans']['Avira']['result']

        if ('BitDefender' in vttext['scans']):
            print "BitDefender:".ljust(13),vttext['scans']['BitDefender']['result']

        if ('ESET-NOD32' in vttext['scans']):
            print "ESET-NOD32:".ljust(13),vttext['scans']['ESET-NOD32']['result']
    
        if ('F-Secure' in vttext['scans']):
            print "F-Secure:".ljust(13),vttext['scans']['F-Secure']['result']
         
        if ('Fortinet' in vttext['scans']):
            print "Fortinet:".ljust(13),vttext['scans']['Fortinet']['result']

        if ("Kaspersky" in vttext['scans']):
            print "Kaspersky:".ljust(13),vttext['scans']['Kaspersky']['result']

        if ("MalwareBytes" in vttext['scans']):
            print "MalwareBytes:".ljust(13),vttext['scans']['MalwareBytes']['result']

        if ("McAfee" in vttext['scans']):
            print "McAfee:".ljust(13),vttext['scans']['McAfee']['result']

        if ("Microsoft" in vttext['scans']):
            print "Microsoft:".ljust(13),vttext['scans']['Microsoft']['result']

        if ("Panda" in vttext['scans']):
            print "Panda:".ljust(13),vttext['scans']['Panda']['result']

        if ("Sophos" in vttext['scans']):
            print "Sophos:".ljust(13),vttext['scans']['Sophos']['result']

        if ("Symantec" in vttext['scans']):
            print "Symantec:".ljust(13),vttext['scans']['Symantec']['result']

        if ("TrendMicro" in vttext['scans']):
            print "TrendMicro:".ljust(13),vttext['scans']['TrendMicro']['result']

        if ("Zone-Alarm" in vttext['scans']):
            print "Zone-Alarm:".ljust(13),vttext['scans']['Zone-Alarm']['result']

    except ValueError:
        print(Fore.RED + "Error while connecting to Virus Total!\n")

def hashow(fname): 

    hatext = ''
    haresponse = ''
    final = ''
   
    try:
      
        resource = sha256hash(fname)
        requestsession = requests.Session( )
        requestsession.headers.update({'User-Agent':user_agent})
        requestsession.auth = HTTPBasicAuth(HAAPI,HASECRET)
        finalurl = '/'.join([haurl,'api/scan', resource])
        haresponse = requestsession.get(url=finalurl)
        hatext = json.loads(haresponse.text)

        rc = str(hatext['response'])
        if (rc == "[]"):
            final = 'Malware sample was not found in Hybrid-Analysis repository.'
            print (Fore.RED + "\n" + final + "\n")
            return final

        if 'environmentDescription' in (hatext['response'][0]):
            envdesc = str(hatext['response'][0]['environmentDescription'])
        else:
            envdesc = '' 

        if 'type' in hatext['response'][0]:
            maltype = str(hatext['response'][0]['type'])
        else:
            maltype = ''

        if 'verdict' in hatext['response'][0]:
            verdict = str(hatext['response'][0]['verdict'])
        else:
            verdict = ''

        if 'threatlevel' in hatext['response'][0]:
            threatlevel = str(hatext['response'][0]['threatlevel'])
        else:
            threatlevel = ''

        if 'threatscore' in hatext['response'][0]:
            threatscore = str(hatext['response'][0]['threatscore'])
        else:
            threatscore = ''

        if 'avdetect' in hatext['response'][0]:
            avdetect = str(hatext['response'][0]['avdetect'])
        else:
            avdetect = ''

        if 'total_signatures' in hatext['response'][0]:
            totalsignatures = str(hatext['response'][0]['total_signatures'])
        else:
            totalsignatures = ''
       
        if 'submitname' in hatext['response'][0]:
            submitname = unicode(hatext['response'][0]['submitname'])
        else:
            submitname = ''
       
        if 'analysis_start_time' in hatext['response'][0]:
            analysistime = str(hatext['response'][0]['analysis_start_time'])
        else:
            analysistime = ''

        if 'size' in hatext['response'][0]:
            malsize = str(hatext['response'][0]['size'])
        else:
            malsize = ''

        if 'total_processes' in hatext['response'][0]:
            totalprocesses = str(hatext['response'][0]['total_processes'])
        else:
            totalprocess = ''

        if 'total_network_connections' in hatext['response'][0]:
            networkconnections =  str(hatext['response'][0]['total_network_connections'])
        else:
            networkconnection = ''

        if 'domains' in hatext['response'][0]:
            domains = (hatext['response'][0]['domains'])
        else:
            domains = ''

        if 'hosts' in hatext['response'][0]:
            hosts = (hatext['response'][0]['hosts'])
        else:
            hosts = ''

        if 'compromised_hosts' in hatext['response'][0]:
            compromised_hosts = (hatext['response'][0]['compromised_hosts'])
        else:
            compromised_hosts = ''

        if 'vxfamily' in hatext['response'][0]:
            vxfamily = str(hatext['response'][0]['vxfamily'])
        else:
            vxfamily = ''

        if 'type_short' in (hatext['response'][0]):
            typeshort = (hatext['response'][0]['type_short'])
        else:
            typeshort = ''

        if 'classification_tags' in hatext['response'][0]:
            classification = (hatext['response'][0]['classification_tags'])
        else:
            classification = ''
      
        if (bkg == 1):
            print (Fore.WHITE)
        else:
            print (Fore.BLACK)
        print ("\nHybrid-Analysis Summary Report:") 
        print (70*'-').ljust(70) 
        if (bkg == 1):
            print (Fore.CYAN)
        else:
            print (Fore.RED)
        print "Environment:".ljust(20),envdesc
        print "File Type:".ljust(20),maltype
        print "Verdict:".ljust(20),verdict
        print "Threat Level:".ljust(20),threatlevel
        print "Threat Score:".ljust(20),threatscore + '/100' 
        print "AV Detect".ljust(20),avdetect + '%'
        print "Total Signatures:".ljust(20),totalsignatures

        if (bkg == 1):
            print (Fore.YELLOW)
        else:
            print (Fore.CYAN)
        print "Submit Name:".ljust(20),submitname
        print "Analysis Time:".ljust(20),analysistime
        print "File Size:".ljust(20),malsize
        print "Total Processes:".ljust(20),totalprocesses
        print "Network Connections:".ljust(20),networkconnections
        
        print "\nDomains:"
        for i in domains:
            print "".ljust(20), i
       
        print "\nHosts:"
        for i in hosts:
            print "".ljust(20), i
       
        print "\nCompromised Hosts:"
        for i in compromised_hosts:
            print "".ljust(20), i
        
        if (bkg == 1):
            print (Fore.RED)
        else:
            print (Fore.CYAN)

        print "Vx Family:".ljust(20),vxfamily 
        print "File Type Short:    ",
        for i in typeshort:
            print i,
        
        print "\nClassification Tags:",
        for i in classification:
            print  i, 
       
        print "\n"

        rc = (hatext['response'])
        if (rc == 0):
            final = 'Not Found'
        return final 

    
    except ValueError as e:
        print e
        print(Fore.RED + "Error while connecting to Hybrid-Analysis!\n")

def overextract(fname):
    
    with open(fname, "rb") as o:
        r = o.read()
    pe = pefile.PE(fname)
    offset = pe.get_overlay_data_start_offset( )
    if offset == None:
       exit(0) 
    with open(fname + ".overlay", "wb") as t:
        t.write(r[offset:])
    print(Fore.RED + "\nOverlay extracted: %s.overlay\n"  % fname)

def keysort(item):
    return item[1]

def generalstatus(key):
    
    vtfinal = ''
    result = ' '
    ovr = ''
    entr = ''
    G = []

    if (vt==1):
        vtfinal = vtcheck(key, url, param)
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

if __name__ == "__main__":
        
    backg=0
    virustotal=0
    fprovided = 0
    fpname = ''
    repo = ''
    ovrly = 0
    showreport = 0
    gt = 0
    ie = 0
    ha = 0

    parser = optparse.OptionParser("malwoverview "+"-d <directory> -f <fullpath> -i <0|1> -b <0|1> -v <0|1> -a <0|1> -p <0|1> -s <0|1> -x <0|1> -w <|1>")
    parser.add_option('-d', dest='direct',type='string',help='specify directory containing malware samples.')
    parser.add_option('-f', dest='fpname',type='string',default = '', help='specify a full path to a file. Shows general information about the file (any filetype)')
    parser.add_option('-b', dest='backg', type='int',default = 0, help='(optional) adapts the output colors to black window.')
    parser.add_option('-i', dest='impsexts', type='int',default = 0, help='(optional) show imports and exports (it is used with -f option).')
    parser.add_option('-x', dest='over', type='int',default = 0, help='(optional) extract overlay (it is used with -f option).')
    parser.add_option('-s', dest='showvt', type='int',default = 0, help='(optional) show antivirus reports from the main players. This option is used with the -f option (any filetype).')
    parser.add_option('-v', dest='virustotal', type='int',default = 0, help='(optional) query Virus Total database for positives and totals.Thus, you need to edit the malwoverview.py and insert your VT API.')
    parser.add_option('-a', dest='hybridanalysis', type='int',default = 0, help='(optional) query Hybrid Analysis database for general report.Thus, you need to edit the malwoverview.py and insert your HA API and secret.')
    parser.add_option('-p', dest='pubkey', type='int',default = 0, help='(optional) use this option if you have a public Virus Total API. It forces a one minute wait every 4 malware samples, but allows obtaining a complete evaluation of the malware repository.')
    parser.add_option('-w', dest='win', type='int',default = 0, help='(optional) used when the OS is Microsoft Windows.')

    (options, args) = parser.parse_args()
    
    optval = [0,1]
    repo = options.direct
    bkg = options.backg
    vt = options.virustotal
    ffpname = options.fpname
    ovrly = options.over
    showreport = options.showvt
    gt = options.pubkey
    ie = options.impsexts
    ha = options.hybridanalysis
    windows = options.win

    if os.path.isfile(ffpname) == True:
        fprovided = 1
    else:
        fprovided = 0
    
    if (options.over) not in optval:
        print parser.usage
        exit(0)
    elif ovrly == 1:
        if fprovided == 0:
            print parser.usage
            exit(0)

    if (options.impsexts) not in optval:
        print parser.usage
        exit(0)
    elif ie == 1:
        if fprovided == 0:
            print parser.usage
            exit(0)

    if (options.hybridanalysis) not in optval:
        print parser.usage
        exit(0)
    elif ie == 1:
        if fprovided == 0:
            print parser.usage
            exit(0)

    if (options.showvt) not in optval: 
        print parser.usage
        exit(0)
    elif (showreport == 1):
        if (fprovided == 0 or vt == 0):
            print parser.usage
            exit(0)

    if (options.direct == None and fprovided == 0):
        print parser.usage
        exit(0)
    
    if (options.fpname == None):
        if (options.direct == None):
            print parser.usage
            exit(0)

    if (options.backg) not in optval:
        print parser.usage
        sys.exit(0)

    if (options.virustotal) not in optval:
        print parser.usage
        sys.exit(0)

    if (options.pubkey) not in optval:
        print parser.usage
        exit(0)

    if (options.win) not in optval:
        print parser.usage
        exit(0)

    
    if (windows == 1):
        init(convert = True)

    if (fprovided == 1):
        GS = []
        targetfile = ffpname
        mymd5hash=''
        mysha256hash=''
        dname = str(os.path.dirname(targetfile))
        if os.path.abspath(dname) == False:
            dname = os.path.abspath('.') + "/" + dname
        fname = os.path.basename(targetfile)
        magictype = ftype(targetfile)

        if re.match(r'^PE[0-9]{2}|^MS-DOS', magictype):
            fmype = pefile.PE(targetfile)
            mymd5hash = md5hash(targetfile)
            mysha256hash = sha256hash(targetfile)
            GS = generalstatus(targetfile)
            fimph = fmype.get_imphash()
            S = []
            if (bkg == 1):
                print (Fore.CYAN)
            else:
                print (Fore.BLUE)
            print ("\nFile Name:   %s" % targetfile)
            print ("File Type:   %s\n" % magictype)
            print ("MD5:         %s" % mymd5hash)
            print ("SHA256:      %s" % mysha256hash)
            print ("Imphash:     %s\n" % fimph)
            print (Fore.RED + "entropy: %8.2f" % GS[2])
            print ("Packed?: %10s" % GS[3])
            print ("Overlay?: %10s" % GS[1])
            print ("VirusTotal: %6s" % GS[0])
            print (Fore.YELLOW + "")
            listsections(targetfile)
            if (showreport == 1):
                if (bkg == 1):
                    print (Fore.WHITE)
                else:
                    print (Fore.BLACK)
                print("\nMain Antivirus Reports:")
                print (40*'-').ljust(40)
                vtshow(targetfile,url,param)

            if (ha == 1):
               hashow(targetfile) 
            
            if (ie == 1):
                impext(targetfile)
            
            print (Fore.BLACK + "")

            if (ovrly == 1):
                status_over = overextract(targetfile)

            exit(0)

        else:
            vtfinal = ''
            mymd5hash = md5hash(targetfile)
            mysha256hash = sha256hash(targetfile)
            print (Fore.YELLOW + "\nFile Name:   %s" % targetfile)
            print ("File Type:   %s" % magictype)
            print (Fore.CYAN + "MD5:         %s" % mymd5hash)
            print ("SHA256:      %s" % mysha256hash)
            if (vt==1):
                vtfinal = vtcheck(targetfile, url, param)
            print (Fore.RED + "VirusTotal: %6s\n" % vtfinal)
            if (showreport == 1):
                if (bkg == 1):
                    print (Fore.WHITE)
                else:
                    print (Fore.BLACK)
                print("\nMain Antivirus Reports:")
                print (40*'-').ljust(40)
                vtshow(targetfile,url,param)
            if (ha == 1):
                hashow(targetfile)
            exit(0)

    directory = repo
    if os.path.isabs(directory) == False:
        directory = os.path.abspath('.') + "/" + directory
    os.chdir(directory)
    
    for file in os.listdir(directory):

        filename = str(file)
        if os.path.isdir(filename) == True:
            continue
        targetfile = ftype(filename)
        if re.match(r'^PE[0-9]{2}|^MS-DOS', targetfile):
            mype = pefile.PE(filename)
            imph = mype.get_imphash()
            F.append(filename)
            H.append(imph)
        else:
            continue

    d = dict(zip(F,H))
    n = 30
    prev1 = 0
    prev2 = 0
    result = ""

    if (bkg == 1):
        print (Fore.WHITE + "\n")
    else:
        print "\n"

    print "FileName".center(32) +  "ImpHash".center(37) + "Packed?".center(9) + "Overlay?".center(10) + ".text_entropy".center(13) + "VT".center(8) 
    print (32*'-').center(32) +  (36*'-').center(35) + (11*'-').center(10) + (10*'-').ljust(10) + (13*'-').center(13) + (8*'-').center(8)


    for key,value in sorted(d.iteritems(), key=lambda (k,v):(v,k)):

        prev1 = value
        vtfinal=''

        if (vt==1):
            if (gt == 1):
                tm = tm + 1
                if tm % 4 == 0:
                    time.sleep(61)
                vtfinal = vtcheck(key, url, param)
            else:
                vtfinal = vtcheck(key, url, param)

        mype2 = pefile.PE(key)
        over = mype2.get_overlay_data_start_offset()
        if over == None:
            ovr =  ""
        else:
            ovr =  "OVERLAY"
        rf = mype2.write()
        entr = mype2.sections[0].entropy_H(rf)
        pack = packed(mype2)
        if pack == False:
            result = "no"
        elif pack == True:
            result = "PACKED"
        else:
            result = "Likely"
        
        if (bkg == 1):
            if ((prev2 == prev1) and (n < 37)):
                print("\033[%dm" % n + "%-32s" % key), 
                print("\033[%dm" % n + "  %-32s" % value), 
                print("\033[%dm" % n + "  %-6s" % result), 
                print("\033[%dm" % n + "  %7s" % ovr), 
                print("\033[%dm" % n + "      %4.2f" % entr), 
                if (vt == 1):
                    print("\033[%dm" % n + "  %8s" % vtfinal)
                else:
                    print("\033[%dm" % n + "  %8s" % '     ')
            else:
                if ((n > 36) and (prev1 != prev2)):
                    n = 30
                elif (n > 36):
                    n = 36
                n = n + 1
                print("\033[%dm" % n + "%-32s" % key), 
                print("\033[%dm" % n + "  %-32s" % value), 
                print("\033[%dm" % n + "  %-6s" % result), 
                print("\033[%dm" % n + "  %7s" % ovr), 
                print("\033[%dm" % n + "      %4.2f" % entr), 
                if (vt == 1):
                    print("\033[%dm" % n + "  %8s" % vtfinal)
                else:
                    print("\033[%dm" % n + "  %8s" % '     ')

                prev2 = value

        else:
            if ((prev2 == prev1) and (n < 36)):
                print("\033[%dm" % n + "%-32s" % key), 
                print("\033[%dm" % n + "  %-32s" % value), 
                print("\033[%dm" % n + "  %-6s" % result), 
                print("\033[%dm" % n + "  %7s" % ovr), 
                print("\033[%dm" % n + "      %4.2f" % entr), 
                if (vt == 1):
                    print("\033[%dm" % n + "  %8s" % vtfinal)
                else:
                    print("\033[%dm" % n + "  %8s" % '     ')
            else:
                if ((n > 35) and (prev1 != prev2)):
                    n = 29
                elif (n > 35):
                    n = 35
                n = n + 1
                print("\033[%dm" % n + "%-32s" % key), 
                print("\033[%dm" % n + "  %-32s" % value), 
                print("\033[%dm" % n + "  %-6s" % result), 
                print("\033[%dm" % n + "  %7s" % ovr), 
                print("\033[%dm" % n + "      %4.2f" % entr), 
                if (vt == 1):
                    print("\033[%dm" % n + "  %8s" % vtfinal)
                else:
                    print("\033[%dm" % n + "  %8s" % '     ')

                prev2 = value

