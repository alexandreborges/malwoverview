import modules.configvars as cv
from polyswarm_api.api import PolyswarmAPI
from utils.colors import mycolors, printr
from utils.hash import sha256hash
from utils.peinfo import ftype
import pefile
from requests.exceptions import RetryError
import re
import os


class PolyswarmExtractor():
    def __init__(self, POLYAPI):
        self.POLYAPI = POLYAPI

    def requestPOLYAPI(self):
        if self.POLYAPI == '':
            print(mycolors.foreground.red + "\nTo be able to get/submit information from/to Polyswarm, you must create the .malwapi.conf file under your user home directory (on Linux is $HOME\\.malwapi.conf and on Windows is in C:\\Users\\[username]\\.malwapi.conf) and insert the Polyswarm API according to the format shown on the Github website." + mycolors.reset + "\n")
            exit(1)

    def polymetasearch(self, poly, metainfo):
        self.requestPOLYAPI()
        polyswarm = PolyswarmAPI(key=self.POLYAPI)

        if (metainfo == 4):
            targetfile = poly
            dname = str(os.path.dirname(targetfile))
            if not os.path.abspath(dname):
                dname = os.path.abspath('.') + "/" + dname
            magictype = ftype(targetfile)

            try:
                if re.match(r'^PE[0-9]{2}|^MS-DOS', magictype):
                    fmype = pefile.PE(targetfile)
                    fimph = fmype.get_imphash()
                else:
                    if (cv.bkg == 1):
                        print(mycolors.foreground.lightred + "\nYou didn\'t provided a PE file")
                    else:
                        print(mycolors.foreground.red + "\nYou didn\'t provided a PE file")
                    printr()
                    exit(1)
            except (AttributeError, NameError):
                if (cv.bkg == 1):
                    print((mycolors.foreground.lightred + "\nThe file %s doesn't respect some PE format rules. Exiting...\n" % targetfile))
                else:
                    print((mycolors.foreground.red + "\nThe file %s doesn't respect some PE format rules. Exiting...\n" % targetfile))
                printr()
                exit(1)

        printr()
        print("POLYSWARM.NETWORK RESULTS")
        print('-' * 25, end="\n\n")

        try:
            if (metainfo == 4):
                metaresults = polyswarm.search_by_metadata("pefile.imphash:" + fimph)
                for x in metaresults:
                    if (cv.bkg == 1):
                        if (x.sha256):
                            print(mycolors.reset + "\nSHA256: " + mycolors.foreground.lightred + "%s" % x.sha256, end=' ')
                        else:
                            print(mycolors.reset + "\nSHA256: " + mycolors.foreground.lightred + "%s" + "None", end=' ')
                        if (x.md5):
                            print(mycolors.reset + "MD5: " + mycolors.foreground.lightcyan + "%s" % x.md5, end=' ')
                        else:
                            print(mycolors.reset + "MD5: " + mycolors.foreground.lightcyan + "%s" + "None", end=' ')
                    else:
                        if (x.sha256):
                            print(mycolors.reset + "\nSHA256: " + mycolors.foreground.red + "%s" % x.sha256, end=' ')
                        else:
                            print(mycolors.reset + "\nSHA256: " + mycolors.foreground.red + "%s" + "None", end=' ')
                        if (x.md5):
                            print(mycolors.reset + "MD5: " + mycolors.foreground.green + "%s" % x.md5, end=' ')
                        else:
                            print(mycolors.reset + "MD5: " + mycolors.foreground.green + "%s" + "None", end=' ')
                print(mycolors.reset + "\n")
                exit(0)

            if (metainfo == 5):
                metaresults = polyswarm.search_by_metadata("strings.ipv4:" + poly)
            if (metainfo == 6):
                metaresults = polyswarm.search_by_metadata("strings.domains:" + poly)
            if (metainfo == 7):
                poly = (r'"' + poly + r'"')
                metaresults = polyswarm.search_by_metadata("strings.urls:" + poly)
            if (metainfo == 8):
                poly = ('scan.latest_scan.*.metadata.malware_family:' + poly)
                metaresults = polyswarm.search_by_metadata(poly)
            for y in metaresults:
                if (cv.bkg == 1):
                    if (y.sha256):
                        print(mycolors.reset + "\nSHA256: " + mycolors.foreground.lightcyan + "%s" % y.sha256, end=' ')
                    else:
                        print(mycolors.reset + "Result: " + mycolors.foreground.yellow + "Sample not found!", end=' ')
                        exit(0)
                    score = next(polyswarm.search(y.sha256))
                    print(mycolors.reset + "Polyscore: " + mycolors.foreground.yellow + "%20s" % score.polyscore, end=' ')
                    if (str(y.scan.get('detections', {}).get('malicious'))) != 'None':
                        print(mycolors.reset + "scan: " + mycolors.foreground.yellow + "%s" % y.scan.get('detections', {}).get('malicious'), end=' ')
                        print("/ " + "%2s malicious" % y.scan.get('detections', {}).get('total'), end=' ')
                    else:
                        print(mycolors.reset + "scan: " + mycolors.foreground.pink + "not scanned yet", end=' ')
                else:
                    if (y.sha256):
                        print(mycolors.reset + "\nSHA256: " + mycolors.foreground.green + "%s" % y.sha256, end=' ')
                    else:
                        print(mycolors.reset + "scan: " + mycolors.foreground.purple + "Sample not found!", end=' ')
                        exit(0)
                    score = next(polyswarm.search(y.sha256))
                    print(mycolors.reset + "Polyscore: " + mycolors.foreground.red + "%20s" % score.polyscore, end=' ')
                    if (str(y.scan.get('detections', {}).get('malicious'))) != 'None':
                        print(mycolors.reset + "scan: " + mycolors.foreground.red + "%s" % y.scan.get('detections', {}).get('malicious'), end=' ')
                        print("/ " + "%2s malicious" % y.scan.get('detections', {}).get('total'), end=' ')
                    else:
                        print(mycolors.reset + "Result: " + mycolors.foreground.purple + "not scanned yet", end=' ')

            printr()
        except RetryError:
            if (cv.bkg == 1):
                print((mycolors.foreground.lightred + "\nAn error has ocurred during Polyswarm processing. Exiting...\n"))
            else:
                print((mycolors.foreground.red + "\nAn error has ocurred during Polyswarm processing. Exiting...\n"))
            printr()
            exit(1)
        except Exception:
            if (cv.bkg == 1):
                print((mycolors.foreground.lightred + "\nAn error has ocurred while connecting to Polyswarm.\n"))
            else:
                print((mycolors.foreground.red + "\nAn error has ocurred while connecting to Polyswarm.\n"))
            printr()
            exit(1)

    def polyfile(self, poly):
        if not (os.path.isfile(poly)):
            if (cv.bkg == 0):
                print(mycolors.foreground.red + "\nYou didn't provide a valid file.\n")
                printr()
                exit(1)
            else:
                print(mycolors.foreground.yellow + "\nYou didn't provide a valid file.\n")
                printr()
                exit(1)

        sha256 = ''
        filetype = ''
        extended = ''
        firstseen = ''
        score = 0

        self.requestPOLYAPI()

        polyswarm = PolyswarmAPI(key=self.POLYAPI)

        try:
            myhash = sha256hash(poly)
            instance = polyswarm.submit(poly)
            result = polyswarm.wait_for(instance)
            printr()
            print("POLYSWARM.NETWORK RESULTS")
            print('-' * 25, end="\n\n")
            for assertion in result.assertions:
                if (cv.bkg == 1):
                    print(mycolors.reset + "Engine: " + mycolors.foreground.lightcyan + "%-25s" % assertion.author_name, end='')
                    print(mycolors.reset + "\tVerdict:" + mycolors.foreground.lightred + " ", "Malicious" if assertion.verdict else "Clean")
                else:
                    print(mycolors.reset + "Engine: " + mycolors.foreground.green + "%-25s" % assertion.author_name, end='')
                    print(mycolors.reset + "\tVerdict:" + mycolors.foreground.red + " ", "Malicious" if assertion.verdict else "Clean")

            results = polyswarm.search(myhash)
            printr()
            for myhashes in results:
                if (myhashes.sha256):
                    sha256 = myhashes.sha256
                if (myhashes.mimetype):
                    filetype = myhashes.mimetype
                if (myhashes.extended_type):
                    extended = myhashes.extended_type
                if (myhashes.first_seen):
                    firstseen = myhashes.first_seen
                if (myhashes.polyscore):
                    score = myhashes.polyscore

            if (cv.bkg == 1):
                if (sha256):
                    print(mycolors.foreground.lightred + "\nSHA256: \t%s" % sha256)
                if (filetype):
                    print(mycolors.foreground.lightred + "File Type: \t%s" % filetype)
                if (extended):
                    print(mycolors.foreground.lightred + "Extended Info: \t%s" % extended)
                if (firstseen):
                    print(mycolors.foreground.lightred + "First seen: \t%s" % firstseen)
                if (score is not None):
                    print(mycolors.foreground.yellow + "\nPolyscore: \t%f" % score)
            else:
                if (sha256):
                    print(mycolors.foreground.cyan + "\nSHA256: \t%s" % sha256)
                if (filetype):
                    print(mycolors.foreground.cyan + "File Type: \t%s" % filetype)
                if (extended):
                    print(mycolors.foreground.cyan + "Extended Info: \t%s" % extended)
                if (firstseen):
                    print(mycolors.foreground.cyan + "First seen: \t%s" % firstseen)
                if (score is not None):
                    print(mycolors.foreground.red + "\nPolyscore: \t%f" % score)
            printr()
        except Exception:
            if (cv.bkg == 1):
                print((mycolors.foreground.lightred + "\nAn error has ocurred while connecting to Polyswarm.\n"))
            else:
                print((mycolors.foreground.red + "\nAn error has ocurred while connecting to Polyswarm.\n"))
            printr()
            exit(1)

    def polyhashsearch(self, poly, download):
        if len(poly) not in [32, 40, 64]:
            return False

        sha256 = ''
        filetype = ''
        extended = ''
        firstseen = ''
        score = 0
        down = download
        DOWN_DIR = '.'

        self.requestPOLYAPI()
        polyswarm = PolyswarmAPI(key=self.POLYAPI)

        try:
            results = polyswarm.search(poly)

            printr()
            print("POLYSWARM.NETWORK RESULTS")
            print('-' * 25, end="\n\n")
            printr()

            for myhashes in results:
                if not myhashes.assertions:
                    if (cv.bkg == 1):
                        print(mycolors.foreground.lightred + "This sample has not been scanned on Polyswarm yet!\n" + mycolors.reset)
                        exit(1)
                    else:
                        print(mycolors.foreground.red + "This sample has not been scanned on Polyswarmi yet!\n" + mycolors.reset)
                        exit(1)
                if (myhashes.sha256):
                    sha256 = myhashes.sha256
                if (myhashes.mimetype):
                    filetype = myhashes.mimetype
                if (myhashes.extended_type):
                    extended = myhashes.extended_type
                if (myhashes.first_seen):
                    firstseen = myhashes.first_seen
                if (myhashes.polyscore):
                    score = myhashes.polyscore
                results = myhashes.assertions
                for i in results:
                    if (cv.bkg == 1):
                        print(mycolors.foreground.lightcyan + "%s" % i)
                    else:
                        print(mycolors.foreground.green + "%s" % i)

            if (cv.bkg == 1):
                if (sha256):
                    print(mycolors.foreground.lightred + "\nSHA256: \t%s" % sha256)
                if (filetype):
                    print(mycolors.foreground.lightred + "File Type: \t%s" % filetype)
                if (extended):
                    print(mycolors.foreground.lightred + "Extended Info: \t%s" % extended)
                if (firstseen):
                    print(mycolors.foreground.lightred + "First seen: \t%s" % firstseen)
                if (score is not None):
                    print(mycolors.foreground.yellow + "\nPolyscore: \t%f" % score)
                if (down == 1):
                    polyswarm.download(DOWN_DIR, sha256)
                    print(mycolors.reset + "\n\nThe sample has been SAVED!")
            else:
                if (sha256):
                    print(mycolors.foreground.cyan + "\nSHA256: \t%s" % sha256)
                if (filetype):
                    print(mycolors.foreground.cyan + "File Type: \t%s" % filetype)
                if (extended):
                    print(mycolors.foreground.cyan + "Extended Info: \t%s" % extended)
                if (firstseen):
                    print(mycolors.foreground.cyan + "First seen: \t%s" % firstseen)
                if (score is not None):
                    print(mycolors.foreground.red + "\nPolyscore: \t%f" % score)
                if (down == 1):
                    polyswarm.download(DOWN_DIR, sha256)
                    print(mycolors.reset + "\n\nThe sample has been SAVED!")
            printr()
        except Exception:
            if (cv.bkg == 1):
                print((mycolors.foreground.yellow + "\nThis hash couldn't be found on Polyswarm.\n"))
            else:
                print((mycolors.foreground.red + "\nThis hash couldn't be found Polyswarm.\n"))
            printr()
            exit(1)
