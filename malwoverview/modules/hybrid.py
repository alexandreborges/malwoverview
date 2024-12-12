import malwoverview.modules.configvars as cv
import requests
from colorama import Fore
import geocoder
from malwoverview.utils.colors import mycolors, printr
from malwoverview.utils.hash import sha256hash
import json
import os


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
            requestsession = requests.Session()
            requestsession.headers.update({'user-agent': user_agent})
            requestsession.headers.update({'api-key': self.HAAPI})
            requestsession.headers.update({'accept': 'application/gzip'})

            finalurl = '/'.join([haurl, 'overview', resource, 'sample'])

            haresponse = requestsession.get(url=finalurl, allow_redirects=True)

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

                outputpath = os.path.join(cv.output_dir, f'{resource}.gz')
                open(outputpath, 'wb').write(haresponse.content)
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
            requestsession = requests.Session()
            requestsession.headers.update({'user-agent': user_agent})
            requestsession.headers.update({'api-key': self.HAAPI})
            requestsession.headers.update({'content-type': 'application/json'})

            if (xx == 0):
                finalurl = '/'.join([haurl, 'report', resource + ':100', 'summary'])
            elif (xx == 1):
                finalurl = '/'.join([haurl, 'report', resource + ':110', 'summary'])
            elif (xx == 2):
                finalurl = '/'.join([haurl, 'report', resource + ':120', 'summary'])
            elif (xx == 3):
                finalurl = '/'.join([haurl, 'report', resource + ':200', 'summary'])
            else:
                finalurl = '/'.join([haurl, 'report', resource + ':300', 'summary'])

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

            resource = {'file': (os.path.basename(filenameha), open(filenameha, 'rb')), 'environment_id': (None, haenv)}

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

            requestsession = requests.Session()
            requestsession.headers.update({'user-agent': user_agent})
            requestsession.headers.update({'api-key': self.HAAPI})
            requestsession.headers.update({'accept': 'application/json'})

            finalurl = '/'.join([haurl, 'submit', 'file'])

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
            requestsession = requests.Session()
            requestsession.headers.update({'user-agent': user_agent})
            requestsession.headers.update({'api-key': self.HAAPI})
            requestsession.headers.update({'content-type': 'application/json'})

            if (xx == 0):
                finalurl = '/'.join([haurl, 'report', resource + ':100', 'summary'])
            elif (xx == 1):
                finalurl = '/'.join([haurl, 'report', resource + ':110', 'summary'])
            elif (xx == 2):
                finalurl = '/'.join([haurl, 'report', resource + ':120', 'summary'])
            elif (xx == 3):
                finalurl = '/'.join([haurl, 'report', resource + ':200', 'summary'])
            else:
                finalurl = '/'.join([haurl, 'report', resource + ':300', 'summary'])

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
            print((mycolors.foreground.green + "%7s" % totalsignatures), end='')
            if(threatscore == 'None'):
                print((mycolors.foreground.red + "%12s" % threatscore), end='')
            else:
                print((mycolors.foreground.red + "%8s/100" % threatscore), end='')
            print((mycolors.foreground.blue + "%6s" % totalprocesses), end='')
            print((mycolors.foreground.blue + "%6s" % networkconnections + mycolors.reset))
"""
