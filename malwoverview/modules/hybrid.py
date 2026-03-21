import malwoverview.modules.configvars as cv
import requests
from colorama import Fore
import geocoder
from malwoverview.utils.colors import mycolors, printr
from malwoverview.utils.hash import sha256hash
import json
import os
from urllib.parse import quote
from malwoverview.utils.session import create_session
from malwoverview.utils.cache import cached


class HybridAnalysisExtractor():
    haurl = 'https://www.hybrid-analysis.com/api/v2'

    def __init__(self, HAAPI):
        self.HAAPI = HAAPI

    def requestHAAPI(self):
        if (self.HAAPI == ''):
            print(mycolors.foreground.red + "\nTo be able to get/submit information from/to Hybrid Analysis, you must create the .malwapi.conf file under your user home directory (on Linux is $HOME\\.malwapi.conf and on Windows is in C:\\Users\\[username]\\.malwapi.conf) and insert the Hybrid Analysis API according to the format shown on the Github website." + mycolors.reset + "\n")
            exit(1)

    def downhash(self, filehash, user_agent='Falcon Sandbox'):
        haurl = HybridAnalysisExtractor.haurl

        hatext = ''
        haresponse = ''
        final = ''

        self.requestHAAPI()

        try:

            resource = filehash
            requestsession = create_session()
            requestsession.headers.update({'user-agent': user_agent})
            requestsession.headers.update({'api-key': self.HAAPI})
            requestsession.headers.update({'accept': 'application/gzip'})

            finalurl = '/'.join([haurl, 'overview', quote(resource, safe=''), 'sample'])

            haresponse = requestsession.get(url=finalurl, allow_redirects=False, stream=True, timeout=60)
            
            MAX_DOWNLOAD_SIZE = 500 * 1024 * 1024
            content = bytearray()
            for chunk in haresponse.iter_content(chunk_size=8192):
                if chunk:
                    content += chunk
                    if len(content) > MAX_DOWNLOAD_SIZE:
                        print(mycolors.foreground.red + "\nError: File too large (>500MB). Download aborted.\n" + mycolors.reset)
                        exit(1)

            try:

                hatext = haresponse.text

                rc = str(hatext)
                if 'message' in rc:
                    final = 'Malware sample is not available to download.'
                    if (cv.bkg == 1):
                        print((mycolors.foreground.lightred + "\n" + final + "\n"))
                    else:
                        print((mycolors.foreground.red + "\n" + final + "\n"))
                    print((mycolors.reset))
                    return final

                safe_filename = os.path.basename(resource) + '.gz'
                outputpath = os.path.join(cv.output_dir, safe_filename)
                with open(outputpath, 'wb') as f:
                    f.write(content)
                final = f'Sample downloaded to: {outputpath}'

                print((mycolors.reset))
                print((final + "\n"))
                return final

            except ValueError as e:
                print(e)
                if (cv.bkg == 1):
                    print((mycolors.foreground.lightred + "Error while downloading Hybrid-Analysis!\n"))
                else:
                    print((mycolors.foreground.red + "Error while downloading Hybrid-Analysis!\n"))
                printr()

        except ValueError as e:
            print(e)
            if (cv.bkg == 1):
                print((mycolors.foreground.lightred + "Error while connecting to Hybrid-Analysis!\n"))
            else:
                print((mycolors.foreground.red + "Error while connecting to Hybrid-Analysis!\n"))
            printr()

    def hashow(self, filehash, xx=0, user_agent='Falcon Sandbox'):
        haurl = HybridAnalysisExtractor.haurl

        hatext = ''
        haresponse = ''
        final = ''

        self.requestHAAPI()

        try:
            resource = filehash
            requestsession = create_session()
            requestsession.headers.update({'user-agent': user_agent})
            requestsession.headers.update({'api-key': self.HAAPI})
            requestsession.headers.update({'content-type': 'application/json'})

            if (xx == 0):
                finalurl = '/'.join([haurl, 'report', quote(resource, safe='') + ':100', 'summary'])
            elif (xx == 1):
                finalurl = '/'.join([haurl, 'report', quote(resource, safe='') + ':110', 'summary'])
            elif (xx == 2):
                finalurl = '/'.join([haurl, 'report', quote(resource, safe='') + ':120', 'summary'])
            elif (xx == 3):
                finalurl = '/'.join([haurl, 'report', quote(resource, safe='') + ':200', 'summary'])
            else:
                finalurl = '/'.join([haurl, 'report', quote(resource, safe='') + ':300', 'summary'])

            haresponse = requestsession.get(url=finalurl)
            hatext = json.loads(haresponse.text)

            rc = str(hatext)
            if 'Failed' in rc:
                final = 'Malware sample was not found in Hybrid-Analysis repository.'
                if (cv.bkg == 1):
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
                networkconnections = str(hatext['total_network_connections'])
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

            printr()
            print("\nHybrid-Analysis Summary Report:")
            print((70 * '-').ljust(70))
            if (cv.bkg == 1):
                print((mycolors.foreground.lightcyan))
            else:
                print((mycolors.foreground.red))
            print("Environment:".ljust(20), envdesc)
            print("File Type:".ljust(20), maltype)
            print("Verdict:".ljust(20), verdict)
            print("Threat Level:".ljust(20), threatlevel)
            print("Threat Score:".ljust(20), threatscore + '/100')
            print("AV Detect".ljust(20), avdetect + '%')
            print("Total Signatures:".ljust(20), totalsignatures)
            if (cv.bkg == 1):
                print((mycolors.foreground.yellow))
            else:
                print((mycolors.foreground.cyan))
            print("Submit Name:".ljust(20), submitname)
            print("Analysis Time:".ljust(20), analysistime)
            print("File Size:".ljust(20), malsize)
            print("Total Processes:".ljust(20), totalprocesses)
            print("Network Connections:".ljust(20), networkconnections)

            print("\nDomains:")
            for i in domains:
                print("".ljust(20), i)

            print("\nHosts:")
            for i in hosts:
                print("".ljust(20), i, "\t", "city: " + (geocoder.ip(i).city))

            print("\nCompromised Hosts:")
            for i in compromised_hosts:
                print("".ljust(20), i, "\t", "city: " + (geocoder.ip(i).city))

            if (cv.bkg == 1):
                print((mycolors.foreground.lightred))
            else:
                print((mycolors.foreground.cyan))

            print("Vx Family:".ljust(20), vxfamily)
            print("File Type Short:    ", end=' ')
            for i in typeshort:
                print(i, end=' ')

            print("\nClassification Tags:".ljust(20), end=' ')
            for i in classification:
                print(i, end=' ')

            if (cv.bkg == 1):
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

            if (cv.bkg == 1):
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
            printr()
            return final

        except ValueError as e:
            print(e)
            if (cv.bkg == 1):
                print((mycolors.foreground.lightred + "Error while connecting to Hybrid-Analysis!\n"))
            else:
                print((mycolors.foreground.red + "Error while connecting to Hybrid-Analysis!\n"))
            printr()

    def hafilecheck(self, filenameha, xx=0, user_agent='Falcon Sandbox'):
        if not os.path.isfile(filenameha):
            if (cv.bkg == 1):
                print(mycolors.foreground.lightred + "\nYou didn't provide a valid file!\n")
            else:
                print(mycolors.foreground.red + "\nYou didn't provide a valid file!\n")
            return False

        haurl = HybridAnalysisExtractor.haurl

        hatext = ''
        haresponse = ''
        resource = ''
        haenv = '100'
        job_id = ''

        self.requestHAAPI()

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

            mysha256hash = sha256hash(filenameha)

            if (cv.bkg == 1):
                print((mycolors.foreground.lightcyan + "\nSubmitted file: %s".ljust(20) % filenameha))
                print(("Submitted hash: %s".ljust(20) % mysha256hash))
                print(("Environment ID: %3s" % haenv))
                print((Fore.WHITE))
            else:
                print((mycolors.foreground.purple + "\nSubmitted file: %s".ljust(20) % filenameha))
                print(("Submitted hash: %s".ljust(20) % mysha256hash))
                print(("Environment ID: %3s" % haenv))
                print((Fore.BLACK))

            requestsession = create_session()
            requestsession.headers.update({'user-agent': user_agent})
            requestsession.headers.update({'api-key': self.HAAPI})
            requestsession.headers.update({'accept': 'application/json'})

            finalurl = '/'.join([haurl, 'submit', 'file'])

            with open(filenameha, 'rb') as file_handle:
                resource = {'file': (os.path.basename(filenameha), file_handle), 'environment_id': (None, haenv)}
                haresponse = requestsession.post(url=finalurl, files=resource)

            hatext = json.loads(haresponse.text)

            rc = str(hatext)

            job_id = str(hatext['job_id'])
            hash_received = str(hatext['sha256'])
            environment_id = str(hatext['environment_id'])

            if (job_id) in rc:
                if (cv.bkg == 1):
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
                if (cv.bkg == 1):
                    print((mycolors.foreground.lightred + "\nAn error occured while sending the file!"))
                    print((mycolors.reset + "\n"))
                else:
                    print((mycolors.foreground.red + "\nAn error occured while sending the file!"))
                    print((mycolors.reset + "\n"))
        except ValueError as e:
            print(e)
            if (cv.bkg == 1):
                print((mycolors.foreground.lightred + "Error while connecting to Hybrid-Analysis!\n"))
            else:
                print((mycolors.foreground.red + "Error while connecting to Hybrid-Analysis!\n"))
            print((mycolors.reset))

    def quickhashow(self, filehash, xx=0, user_agent='Falcon Sandbox'):
        haurl = HybridAnalysisExtractor.haurl

        hatext = ''
        haresponse = ''
        final = 'Yes'
        verdict = '-'
        avdetect = '0'
        totalsignatures = '-'
        threatscore = '-'
        totalprocesses = '-'
        networkconnections = '-'

        self.requestHAAPI()

        try:

            resource = filehash
            requestsession = create_session()
            requestsession.headers.update({'user-agent': user_agent})
            requestsession.headers.update({'api-key': self.HAAPI})
            requestsession.headers.update({'content-type': 'application/json'})

            if (xx == 0):
                finalurl = '/'.join([haurl, 'report', quote(resource, safe='') + ':100', 'summary'])
            elif (xx == 1):
                finalurl = '/'.join([haurl, 'report', quote(resource, safe='') + ':110', 'summary'])
            elif (xx == 2):
                finalurl = '/'.join([haurl, 'report', quote(resource, safe='') + ':120', 'summary'])
            elif (xx == 3):
                finalurl = '/'.join([haurl, 'report', quote(resource, safe='') + ':200', 'summary'])
            else:
                finalurl = '/'.join([haurl, 'report', quote(resource, safe='') + ':300', 'summary'])

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
                networkconnections = str(hatext['total_network_connections'])
            else:
                networkconnections = ''

            return (final, verdict, avdetect, totalsignatures, threatscore, totalprocesses, networkconnections)

        except ValueError as e:
            print(e)
            if (cv.bkg == 1):
                print((mycolors.foreground.lightred + "Error while connecting to Hybrid-Analysis!\n"))
            else:
                print((mycolors.foreground.red + "Error while connecting to Hybrid-Analysis!\n"))
            printr()

    def habatchcheck(self, filename, user_agent='Falcon Sandbox'):
        haurl = 'https://www.hybrid-analysis.com/api/v2'

        self.requestHAAPI()

        if not os.path.isfile(filename):
            if (cv.bkg == 1):
                print(mycolors.foreground.lightred + "\nFile not found: %s\n" % filename)
            else:
                print(mycolors.foreground.red + "\nFile not found: %s\n" % filename)
            printr()
            return

        try:
            with open(filename, 'r', encoding='utf-8', errors='ignore') as f:
                hashes = [line.strip() for line in f.readlines() if line.strip()]
        except Exception as e:
            if (cv.bkg == 1):
                print(mycolors.foreground.lightred + "\nError reading file: %s (%s)\n" % (filename, str(e)))
            else:
                print(mycolors.foreground.red + "\nError reading file: %s (%s)\n" % (filename, str(e)))
            printr()
            return

        print("\n")
        print((mycolors.reset + "Hybrid Analysis Batch Hash Check".center(100)), end='')
        print((mycolors.reset + "".center(28)), end='')
        print("\n" + (100 * '-').center(50))

        print(mycolors.reset + "\n%-68s %-22s %-14s %s" % ("Hash", "Verdict", "Threat Score", "AV Detect (%)"))
        print((120 * '-'))

        requestsession = create_session()
        requestsession.headers.update({'user-agent': user_agent})
        requestsession.headers.update({'api-key': self.HAAPI})
        requestsession.headers.update({'accept': 'application/json'})

        for h in hashes:
            try:
                h = h.strip()
                finalurl = '/'.join([haurl, 'overview', quote(h, safe=''), 'summary'])
                response = requestsession.get(url=finalurl, timeout=60)
                hatext = json.loads(response.text)

                verdict = ''
                threat_score = ''
                av_detect = ''

                rc = str(hatext)
                if 'message' not in rc and 'Failed' not in rc and hatext != 0:
                    verdict = str(hatext.get('verdict', '')) if hatext.get('verdict') else ''
                    threat_score = str(hatext.get('threat_score', '')) if hatext.get('threat_score') is not None else ''
                    multiscan = hatext.get('multiscan_result')
                    if multiscan is not None:
                        av_detect = str(multiscan)
                    elif hatext.get('av_detect') is not None:
                        av_detect = str(hatext.get('av_detect'))

                if (cv.bkg == 1):
                    print(mycolors.foreground.yellow + "%-68s " % h, end='')
                    print(mycolors.foreground.lightcyan + "%-22s " % verdict, end='')
                    print(mycolors.foreground.lightred + "%-14s " % threat_score.center(12), end='')
                    print(mycolors.foreground.pink + "%-14s" % av_detect.center(12))
                else:
                    print(mycolors.foreground.cyan + "%-68s " % h, end='')
                    print(mycolors.foreground.blue + "%-22s " % verdict, end='')
                    print(mycolors.foreground.red + "%-14s " % threat_score.center(12), end='')
                    print(mycolors.foreground.purple + "%-14s" % av_detect.center(12))

            except Exception as e:
                if (cv.bkg == 1):
                    print(mycolors.foreground.lightred + "%-68s error: %s" % (h, str(e)))
                else:
                    print(mycolors.foreground.red + "%-68s error: %s" % (h, str(e)))

        printr()

    def habatchdircheck(self, directory, user_agent='Falcon Sandbox'):
        haurl = 'https://www.hybrid-analysis.com/api/v2'

        self.requestHAAPI()

        if not os.path.isabs(directory):
            directory = os.path.abspath(directory)

        if not os.path.isdir(directory):
            if (cv.bkg == 1):
                print(mycolors.foreground.lightred + "\nDirectory not found: %s\n" % directory)
            else:
                print(mycolors.foreground.red + "\nDirectory not found: %s\n" % directory)
            printr()
            return

        files = []
        for filen in os.listdir(directory):
            filepath = os.path.join(directory, filen)
            if os.path.isfile(filepath):
                try:
                    h = sha256hash(filepath)
                    files.append((filen, h))
                except Exception:
                    pass

        if not files:
            print(mycolors.foreground.error(cv.bkg) + "\nNo files found in directory.\n" + mycolors.reset)
            printr()
            return

        print("\n")
        print((mycolors.reset + "Hybrid Analysis Directory Check".center(100)), end='')
        print((mycolors.reset + "".center(28)), end='')
        print("\n" + (100 * '-').center(50))

        print(mycolors.reset + "\n%-42s %-66s %-14s %-10s %s" % ("Filename", "Hash", "Verdict", "Threat Score", "AV Detect (%)"))
        print((148 * '-'))

        requestsession = create_session()
        requestsession.headers.update({'user-agent': user_agent})
        requestsession.headers.update({'api-key': self.HAAPI})
        requestsession.headers.update({'accept': 'application/json'})

        for fname, h in files:
            try:
                finalurl = '/'.join([haurl, 'overview', quote(h, safe=''), 'summary'])
                response = requestsession.get(url=finalurl, timeout=60)
                hatext = json.loads(response.text)

                verdict = ''
                threat_score = ''
                av_detect = ''

                rc = str(hatext)
                if 'message' not in rc and 'Failed' not in rc and hatext != 0:
                    verdict = str(hatext.get('verdict', '')) if hatext.get('verdict') else ''
                    threat_score = str(hatext.get('threat_score', '')) if hatext.get('threat_score') is not None else ''
                    multiscan = hatext.get('multiscan_result')
                    if multiscan is not None:
                        av_detect = str(multiscan)
                    elif hatext.get('av_detect') is not None:
                        av_detect = str(hatext.get('av_detect'))

                if (cv.bkg == 1):
                    print(mycolors.foreground.lightgreen + "%-42s " % fname[:40], end='')
                    print(mycolors.foreground.yellow + "%-66s " % h, end='')
                    print(mycolors.foreground.lightcyan + "%-14s " % verdict, end='')
                    print(mycolors.foreground.lightred + "%-10s " % threat_score.center(8), end='')
                    print(mycolors.foreground.pink + "%-10s" % av_detect.center(8))
                else:
                    print(mycolors.foreground.blue + "%-42s " % fname[:40], end='')
                    print(mycolors.foreground.cyan + "%-66s " % h, end='')
                    print(mycolors.foreground.blue + "%-14s " % verdict, end='')
                    print(mycolors.foreground.red + "%-10s " % threat_score.center(8), end='')
                    print(mycolors.foreground.purple + "%-10s" % av_detect.center(8))

            except Exception as e:
                if (cv.bkg == 1):
                    print(mycolors.foreground.lightred + "%-42s error: %s" % (fname[:40], str(e)))
                else:
                    print(mycolors.foreground.red + "%-42s error: %s" % (fname[:40], str(e)))

        printr()

    @cached("ha_hash")
    def _raw_hash_info(self, hash_value):
        try:
            haurl = 'https://www.hybrid-analysis.com/api/v2'
            requestsession = create_session()
            requestsession.headers.update({
                'api-key': self.HAAPI,
                'user-agent': 'Falcon Sandbox',
                'accept': 'application/json'
            })
            response = requestsession.get(haurl + '/overview/' + quote(hash_value, safe='') + '/summary')
            if response.status_code == 200:
                return response.json()
        except Exception:
            pass
        return None


"""
class quickHAThread(threading.Thread):
    def __init__(self, key):
        threading.Thread.__init__(self)
        self.key = key

    def run(self):
        key1 = self.key

        myhashdir = sha256hash(key1)
        (final, verdict, avdetect, totalsignatures, threatscore, totalprocesses, networkconnections) =  self.hybrid.quickhashow(myhashdir)

        if (cv.bkg == 1):
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
            print((mycolors.foreground.blue + "%7s" % totalsignatures), end='')
            if(threatscore == 'None'):
                print((mycolors.foreground.red + "%12s" % threatscore), end='')
            else:
                print((mycolors.foreground.red + "%8s/100" % threatscore), end='')
            print((mycolors.foreground.blue + "%6s" % totalprocesses), end='')
            print((mycolors.foreground.blue + "%6s" % networkconnections + mycolors.reset))
"""
