import modules.configvars as cv
from utils.colors import mycolors, printr
import requests
import textwrap
import json


class InQuestExtractor():
    inquesturl = 'https://labs.inquest.net/api/dfi'
    inquesturl2 = 'https://labs.inquest.net/api/iocdb'
    inquesturl3 = 'https://labs.inquest.net/api/repdb'

    def __init__(self, INQUESTAPI):
        self.INQUESTAPI = INQUESTAPI

    def requestINQUESTAPI(self):
        if (self.INQUESTAPI == ''):
            print(mycolors.foreground.red + "\nTo be able to download samples from InQuest, you must create the .malwapi.conf file under your user home directory (on Linux is $HOME\\.malwapi.conf and on Windows is in C:\\Users\\[username]\\.malwapi.conf) and insert the InQuest API according to the format shown on the Github website." + mycolors.reset + "\n")
            exit(1)

    def inquest_download(self, inquestx):
        inquest = InQuestExtractor.inquesturl
        inquestresponse = ''

        self.requestINQUESTAPI()

        try:

            print("\n")
            print((mycolors.reset + "INQUEST DOWNLOAD REPORT".center(80)), end='')
            print((mycolors.reset + "".center(28)), end='')
            print("\n" + (86 * '-').center(43))

            if (not inquestx):
                if (cv.bkg == 1):
                    print(mycolors.foreground.lightred + "\nThe -I parameter with the provided SHA256 hash is required!\n" + mycolors.reset)
                else:
                    print(mycolors.foreground.red + "\nThe -I parameter with the provided SHA256 hash is required!\n" + mycolors.reset)
                exit(1)

            requestsession = requests.Session()
            requestsession.headers.update({'Accept': 'application/octet-stream'})
            requestsession.headers.update({'Authorization': self.INQUESTAPI})
            inquestresponse = requestsession.get(inquest + '/download?sha256=' + inquestx)

            if (inquestresponse.status_code == 400):
                inquesttext = json.loads(inquestresponse.text)

                if 'error' in inquesttext:
                    if inquesttext['error'] == "Supplied 'sha256' value is not a valid hash.":
                        if (cv.bkg == 1):
                            print(mycolors.foreground.lightred + "\nThe provided SHA256 hash is not valid!\n" + mycolors.reset)
                        else:
                            print(mycolors.foreground.red + "\nThe provided SHA256 hash is not valid!\n" + mycolors.reset)
                        exit(1)

            if (inquestresponse.status_code == 403 or inquestresponse.status_code == 500):
                inquesttext = json.loads(inquestresponse.text)

                if (cv.bkg == 1):
                    print(mycolors.foreground.lightred + "\nThe sample is not available for download!\n" + mycolors.reset)
                else:
                    print(mycolors.foreground.red + "\nThe sample is not available for download!\n" + mycolors.reset)
                exit(1)

            open(inquestx + '.bin', 'wb').write(inquestresponse.content)
            if (cv.bkg == 1):
                print("\n" + mycolors.foreground.yellow + "SAMPLE SAVED as: " + inquestx + ".bin" + mycolors.reset, end=' ')
            if (cv.bkg == 0):
                print("\n" + mycolors.foreground.blue + "SAMPLE SAVED as: " + inquestx + ".bin" + mycolors.reset, end=' ')

            print(mycolors.reset + "\n")
            exit(0)

        except ValueError as e:
            print(e)
            if (cv.bkg == 1):
                print((mycolors.foreground.lightred + "\nError while connecting to InQuest!\n"))
            else:
                print((mycolors.foreground.lightred + "\nError while connecting to InQuest!\n"))
            printr()

    def inquest_hash(self, inquestx):
        inquest = InQuestExtractor.inquesturl

        inquestresponse = ''

        self.requestINQUESTAPI()

        try:

            print("\n")
            print((mycolors.reset + "INQUEST SAMPLE REPORT".center(80)), end='')
            print((mycolors.reset + "".center(28)), end='')
            print("\n" + (86 * '-').center(43))

            if (not inquestx):
                if (cv.bkg == 1):
                    print(mycolors.foreground.lightred + "\nThe -I parameter with the provided SHA256 hash is required!\n" + mycolors.reset)
                else:
                    print(mycolors.foreground.red + "\nThe -I parameter with the provided SHA256 hash is required!\n" + mycolors.reset)
                exit(1)

            requestsession = requests.Session()
            requestsession.headers.update({'Accept': 'application/json'})
            requestsession.headers.update({'Authorization': self.INQUESTAPI})
            inquestresponse = requestsession.get(inquest + '/search/hash/sha256?hash=' + inquestx)
            inquesttext = json.loads(inquestresponse.text)

            if (inquestresponse.status_code == 400 or inquestresponse.status_code == 500):
                inquesttext = json.loads(inquestresponse.text)

                if 'error' in inquesttext:
                    if inquesttext['error'] == "The 'source' parameter must be one of md5, sha1, sha256, sha512":
                        if (cv.bkg == 1):
                            print(mycolors.foreground.lightred + "\nThe provided hash is not a SHA256 hash!\n" + mycolors.reset)
                        else:
                            print(mycolors.foreground.red + "\nThe provided hash is not a SHA256 hash!\n" + mycolors.reset)
                        exit(1)

                if inquesttext['error'] == "Invalid SHA256 hash supplied.":
                    if (cv.bkg == 1):
                        print(mycolors.foreground.lightred + "\nThe provided SHA256 hash is not valid!\n" + mycolors.reset)
                    else:
                        print(mycolors.foreground.red + "\nThe provided SHA256 hash is not valid!\n" + mycolors.reset)
                    exit(1)

            if (cv.bkg == 1):
                for i in inquesttext.keys():
                    if (i == "data"):
                        if (inquesttext['data'] is not None):
                            for d in inquesttext['data']:
                                y = d.keys()
                                if ("sha256" in y):
                                    if d['sha256']:
                                        print(mycolors.foreground.lightcyan + "\nsha256: ".ljust(20) + mycolors.reset + d['sha256'], end=' ')

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
                                                print(mycolors.foreground.yellow + "".ljust(19) + k + ":\t" + mycolors.reset + (("\n" + " ".ljust(32)).join(textwrap.wrap(str(j[k]), width=80))), end="\n")
                                print('\n')

            if (cv.bkg == 0):
                for i in inquesttext.keys():
                    if (i == "data"):
                        if (inquesttext['data'] is not None):
                            for d in inquesttext['data']:
                                y = d.keys()
                                if ("sha256" in y):
                                    if d['sha256']:
                                        print(mycolors.foreground.blue + "\nsha256: ".ljust(20) + mycolors.reset + d['sha256'], end=' ')

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
                                                print(mycolors.foreground.cyan + "".ljust(19) + k + ":\t" + mycolors.reset + (("\n" + " ".ljust(32)).join(textwrap.wrap(str(j[k]), width=80))), end="\n")
                                print('\n')

        except ValueError as e:
            print(e)
            if (cv.bkg == 1):
                print((mycolors.foreground.lightred + "\nError while connecting to InQuest!\n"))
            else:
                print((mycolors.foreground.lightred + "\nError while connecting to InQuest!\n"))

    def inquest_hash_md5(self, inquestx):
        inquest = InQuestExtractor.inquesturl

        inquestresponse = ''

        self.requestINQUESTAPI()

        try:

            print("\n")
            print((mycolors.reset + "INQUEST SAMPLE REPORT".center(80)), end='')
            print((mycolors.reset + "".center(28)), end='')
            print("\n" + (86 * '-').center(43))

            if (not inquestx):
                if (cv.bkg == 1):
                    print(mycolors.foreground.lightred + "\nThe -I parameter with the provided SHA256 hash is required!\n" + mycolors.reset)
                else:
                    print(mycolors.foreground.red + "\nThe -I parameter with the provided SHA256 hash is required!\n" + mycolors.reset)
                exit(1)

            requestsession = requests.Session()
            requestsession.headers.update({'Accept': 'application/json'})
            requestsession.headers.update({'Authorization': self.INQUESTAPI})
            inquestresponse = requestsession.get(inquest + '/search/hash/md5?hash=' + inquestx)
            inquesttext = json.loads(inquestresponse.text)

            if (inquestresponse.status_code == 400 or inquestresponse.status_code == 500):
                inquesttext = json.loads(inquestresponse.text)

                if 'error' in inquesttext:
                    if inquesttext['error'] == "The 'source' parameter must be one of md5, sha1, sha256, sha512":
                        if (cv.bkg == 1):
                            print(mycolors.foreground.lightred + "\nThe provided hash is not a MD5 hash!\n" + mycolors.reset)
                        else:
                            print(mycolors.foreground.red + "\nThe provided hash is not a MD5 hash!\n" + mycolors.reset)
                        exit(1)

                if inquesttext['error'] == "Invalid MD5 hash supplied.":
                    if (cv.bkg == 1):
                        print(mycolors.foreground.lightred + "\nThe provided MD5 hash is not valid!\n" + mycolors.reset)
                    else:
                        print(mycolors.foreground.red + "\nThe provided MD5 hash is not valid!\n" + mycolors.reset)
                    exit(1)

            if (cv.bkg == 1):
                for i in inquesttext.keys():
                    if (i == "data"):
                        if (inquesttext['data'] is not None):
                            for d in inquesttext['data']:
                                y = d.keys()
                                if ("sha256" in y):
                                    if d['sha256']:
                                        print(mycolors.foreground.lightcyan + "\nsha256: ".ljust(20) + mycolors.reset + d['sha256'], end=' ')

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
                                                print(mycolors.foreground.yellow + "".ljust(19) + k + ":\t" + mycolors.reset + (("\n" + " ".ljust(32)).join(textwrap.wrap(str(j[k]), width=80))), end="\n")
                                print('\n')

            if (cv.bkg == 0):
                for i in inquesttext.keys():
                    if (i == "data"):
                        if (inquesttext['data'] is not None):
                            for d in inquesttext['data']:
                                y = d.keys()
                                if ("sha256" in y):
                                    if d['sha256']:
                                        print(mycolors.foreground.blue + "\nsha256: ".ljust(20) + mycolors.reset + d['sha256'], end=' ')

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
                                                print(mycolors.foreground.cyan + "".ljust(19) + k + ":\t" + mycolors.reset + (("\n" + " ".ljust(32)).join(textwrap.wrap(str(j[k]), width=80))), end="\n")
                                print('\n')

        except ValueError as e:
            print(e)
            if (cv.bkg == 1):
                print((mycolors.foreground.lightred + "\nError while connecting to InQuest!\n"))
            else:
                print((mycolors.foreground.lightred + "\nError while connecting to InQuest!\n"))

    def inquest_list(self, inquestx):
        inquest = InQuestExtractor.inquesturl

        inquestresponse = ''

        self.requestINQUESTAPI()

        try:

            print("\n")
            print((mycolors.reset + "INQUEST LIST REPORT".center(110)), end='')
            print((mycolors.reset + "".center(28)), end='')
            print("\n" + (110 * '-').center(55))

            if (not inquestx == "list"):
                if (cv.bkg == 1):
                    print(mycolors.foreground.lightred + "\nThe word 'list' (no single quotes) must be provided as -I parameter!\n" + mycolors.reset)
                else:
                    print(mycolors.foreground.red + "\nThe word 'list' (no single quotes) must be provided as -I parameter!\n" + mycolors.reset)
                exit(1)

            requestsession = requests.Session()
            requestsession.headers.update({'Accept': 'application/json'})
            requestsession.headers.update({'Authorization': self.INQUESTAPI})
            inquestresponse = requestsession.get(inquest + "/" + inquestx)
            inquesttext = json.loads(inquestresponse.text)

            if (cv.bkg == 1):
                for i in inquesttext.keys():
                    if (i == "data"):
                        if (inquesttext['data'] is not None):
                            for d in inquesttext['data']:
                                y = d.keys()
                                print("\n" + (110 * '-').center(55), end=' ')
                                if ("sha256" in y):
                                    if d['sha256']:
                                        print(mycolors.foreground.lightblue + "\nsha256: ".ljust(20) + mycolors.reset + d['sha256'], end=' ')

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
                                                print(mycolors.foreground.orange + "".ljust(19) + k + ":\t" + mycolors.reset + (("\n" + " ".ljust(32)).join(textwrap.wrap(str(j[k]), width=80))), end="\n")

            if (cv.bkg == 0):
                for i in inquesttext.keys():
                    if (i == "data"):
                        if (inquesttext['data'] is not None):
                            for d in inquesttext['data']:
                                y = d.keys()
                                print("\n" + (110 * '-').center(55), end=' ')
                                if ("sha256" in y):
                                    if d['sha256']:
                                        print(mycolors.foreground.red + "\nsha256: ".ljust(20) + mycolors.reset + d['sha256'], end=' ')

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
                                                print(mycolors.foreground.blue + "".ljust(19) + k + ":\t" + mycolors.reset + (("\n" + " ".ljust(32)).join(textwrap.wrap(str(j[k]), width=80))), end="\n")

        except ValueError as e:
            print(e)
            if (cv.bkg == 1):
                print((mycolors.foreground.lightred + "\nError while connecting to InQuest!\n"))
            else:
                print((mycolors.foreground.lightred + "\nError while connecting to InQuest!\n"))

    def inquest_domain(self, inquestx):
        inquest = InQuestExtractor.inquesturl

        inquestresponse = ''

        self.requestINQUESTAPI()

        try:

            print("\n")
            print((mycolors.reset + "INQUEST DOMAIN SEARCH REPORT".center(110)), end='')
            print((mycolors.reset + "".center(28)), end='')
            print("\n" + (110 * '-').center(55))

            if (not inquestx):
                if (cv.bkg == 1):
                    print(mycolors.foreground.lightred + "\nThe -I parameter with the provided domain is required!\n" + mycolors.reset)
                else:
                    print(mycolors.foreground.red + "\nThe -I parameter with the provided domain is required!\n" + mycolors.reset)
                exit(1)

            requestsession = requests.Session()
            requestsession.headers.update({'Accept': 'application/json'})
            requestsession.headers.update({'Authorization': self.INQUESTAPI})
            inquestresponse = requestsession.get(inquest + '/search/ioc/domain?keyword=' + inquestx)
            inquesttext = json.loads(inquestresponse.text)

            if (cv.bkg == 1):
                for i in inquesttext.keys():
                    if (i == "data"):
                        if (inquesttext['data'] is not None):
                            for d in inquesttext['data']:
                                y = d.keys()
                                print("\n" + (110 * '-').center(55), end='\n')
                                if ("sha256" in y):
                                    if d['sha256']:
                                        print(mycolors.foreground.lightblue + "\nsha256: ".ljust(20) + mycolors.reset + d['sha256'], end=' ')

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
                                                print(mycolors.foreground.lightgreen + "".ljust(19) + k + ":\t" + mycolors.reset + (("\n" + " ".ljust(32)).join(textwrap.wrap(str(j[k]), width=80))), end="\n")

            if (cv.bkg == 0):
                for i in inquesttext.keys():
                    if (i == "data"):
                        if (inquesttext['data'] is not None):
                            for d in inquesttext['data']:
                                y = d.keys()
                                print("\n" + (110 * '-').center(55), end='\n')
                                if ("sha256" in y):
                                    if d['sha256']:
                                        print(mycolors.foreground.blue + "\nsha256: ".ljust(20) + mycolors.reset + d['sha256'], end=' ')

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
                                                print(mycolors.foreground.purple + "".ljust(19) + k + ":\t" + mycolors.reset + (("\n" + " ".ljust(32)).join(textwrap.wrap(str(j[k]), width=80))), end="\n")

        except ValueError as e:
            print(e)
            if (cv.bkg == 1):
                print((mycolors.foreground.lightred + "\nError while connecting to InQuest!\n"))
            else:
                print((mycolors.foreground.lightred + "\nError while connecting to InQuest!\n"))

    def inquest_ip(self, inquestx):
        inquest = InQuestExtractor.inquesturl

        inquestresponse = ''

        self.requestINQUESTAPI()

        try:

            print("\n")
            print((mycolors.reset + "INQUEST IP ADDRESS SEARCH REPORT".center(110)), end='')
            print((mycolors.reset + "".center(28)), end='')
            print("\n" + (110 * '-').center(55))

            if (not inquestx):
                if (cv.bkg == 1):
                    print(mycolors.foreground.lightred + "\nThe -I parameter with the provided IP address is required!\n" + mycolors.reset)
                else:
                    print(mycolors.foreground.red + "\nThe -I parameter with the provided IP address is required!\n" + mycolors.reset)
                exit(1)

            requestsession = requests.Session()
            requestsession.headers.update({'Accept': 'application/json'})
            requestsession.headers.update({'Authorization': self.INQUESTAPI})
            inquestresponse = requestsession.get(inquest + '/search/ioc/ip?keyword=' + inquestx)
            inquesttext = json.loads(inquestresponse.text)

            if (cv.bkg == 1):
                for i in inquesttext.keys():
                    if (i == "data"):
                        if (inquesttext['data'] is not None):
                            for d in inquesttext['data']:
                                y = d.keys()
                                print("\n" + (110 * '-').center(55), end='\n')
                                if ("sha256" in y):
                                    if d['sha256']:
                                        print(mycolors.foreground.orange + "\nsha256: ".ljust(20) + mycolors.reset + d['sha256'], end=' ')

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
                                                print(mycolors.foreground.lightcyan + "".ljust(19) + k + ":\t" + mycolors.reset + (("\n" + " ".ljust(32)).join(textwrap.wrap(str(j[k]), width=80))), end="\n")

            if (cv.bkg == 0):
                for i in inquesttext.keys():
                    if (i == "data"):
                        if (inquesttext['data'] is not None):
                            for d in inquesttext['data']:
                                y = d.keys()
                                print("\n" + (110 * '-').center(55), end='\n')
                                if ("sha256" in y):
                                    if d['sha256']:
                                        print(mycolors.foreground.cyan + "\nsha256: ".ljust(20) + mycolors.reset + d['sha256'], end=' ')

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
                                                print(mycolors.foreground.purple + "".ljust(19) + k + ":\t" + mycolors.reset + (("\n" + " ".ljust(32)).join(textwrap.wrap(str(j[k]), width=80))), end="\n")

        except ValueError as e:
            print(e)
            if (cv.bkg == 1):
                print((mycolors.foreground.lightred + "\nError while connecting to InQuest!\n"))
            else:
                print((mycolors.foreground.lightred + "\nError while connecting to InQuest!\n"))

    def inquest_email(self, inquestx):
        inquest = InQuestExtractor.inquesturl

        inquestresponse = ''

        self.requestINQUESTAPI()

        try:

            print("\n")
            print((mycolors.reset + "INQUEST IOC SEARCH REPORT".center(110)), end='')
            print((mycolors.reset + "".center(28)), end='')
            print("\n" + (110 * '-').center(55))

            if (not inquestx):
                if (cv.bkg == 1):
                    print(mycolors.foreground.lightred + "\nThe -I parameter with the provided email address is required!\n" + mycolors.reset)
                else:
                    print(mycolors.foreground.red + "\nThe -I parameter with the provided email address is required!\n" + mycolors.reset)
                exit(1)

            requestsession = requests.Session()
            requestsession.headers.update({'Accept': 'application/json'})
            requestsession.headers.update({'Authorization': self.INQUESTAPI})
            inquestresponse = requestsession.get(inquest + '/search/ioc/email?keyword=' + inquestx)
            inquesttext = json.loads(inquestresponse.text)

            if (cv.bkg == 1):
                for i in inquesttext.keys():
                    if (i == "data"):
                        if (inquesttext['data'] is not None):
                            for d in inquesttext['data']:
                                y = d.keys()
                                print("\n" + (110 * '-').center(55), end='\n')
                                if ("sha256" in y):
                                    if d['sha256']:
                                        print(mycolors.foreground.lightgreen + "\nsha256: ".ljust(20) + mycolors.reset + d['sha256'], end=' ')

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
                                                print(mycolors.foreground.yellow + "".ljust(19) + k + ":\t" + mycolors.reset + (("\n" + " ".ljust(32)).join(textwrap.wrap(str(j[k]), width=80))), end="\n")

            if (cv.bkg == 0):
                for i in inquesttext.keys():
                    if (i == "data"):
                        if (inquesttext['data'] is not None):
                            for d in inquesttext['data']:
                                y = d.keys()
                                print("\n" + (110 * '-').center(55), end='\n')
                                if ("sha256" in y):
                                    if d['sha256']:
                                        print(mycolors.foreground.purple + "\nsha256: ".ljust(20) + mycolors.reset + d['sha256'], end=' ')

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
                                                print(mycolors.foreground.green + "".ljust(19) + k + ":\t" + mycolors.reset + (("\n" + " ".ljust(32)).join(textwrap.wrap(str(j[k]), width=80))), end="\n")

            print("\n")

        except ValueError as e:
            print(e)
            if (cv.bkg == 1):
                print((mycolors.foreground.lightred + "\nError while connecting to InQuest!\n"))
            else:
                print((mycolors.foreground.lightred + "\nError while connecting to InQuest!\n"))

    def inquest_filename(self, inquestx):
        inquest = InQuestExtractor.inquesturl
        inquestresponse = ''

        self.requestINQUESTAPI()

        try:

            print("\n")
            print((mycolors.reset + "INQUEST IOC SEARCH REPORT".center(110)), end='')
            print((mycolors.reset + "".center(28)), end='')
            print("\n" + (110 * '-').center(55))

            if (not inquestx):
                if (cv.bkg == 1):
                    print(mycolors.foreground.lightred + "\nThe -I parameter with the provided filename is required!\n" + mycolors.reset)
                else:
                    print(mycolors.foreground.red + "\nThe -I parameter with the provided filename is required!\n" + mycolors.reset)
                exit(1)

            requestsession = requests.Session()
            requestsession.headers.update({'Accept': 'application/json'})
            requestsession.headers.update({'Authorization': self.INQUESTAPI})
            inquestresponse = requestsession.get(inquest + '/search/ioc/filename?keyword=' + inquestx)
            inquesttext = json.loads(inquestresponse.text)

            if (cv.bkg == 1):
                for i in inquesttext.keys():
                    if (i == "data"):
                        if (inquesttext['data'] is not None):
                            for d in inquesttext['data']:
                                y = d.keys()
                                print("\n" + (110 * '-').center(55), end='\n')
                                if ("sha256" in y):
                                    if d['sha256']:
                                        print(mycolors.foreground.lightred + "\nsha256: ".ljust(20) + mycolors.reset + d['sha256'], end=' ')

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
                                                print(mycolors.foreground.lightblue + "".ljust(19) + k + ":\t" + mycolors.reset + (("\n" + " ".ljust(32)).join(textwrap.wrap(str(j[k]), width=80))), end="\n")

            if (cv.bkg == 0):
                for i in inquesttext.keys():
                    if (i == "data"):
                        if (inquesttext['data'] is not None):
                            for d in inquesttext['data']:
                                y = d.keys()
                                print("\n" + (110 * '-').center(55), end='\n')
                                if ("sha256" in y):
                                    if d['sha256']:
                                        print(mycolors.foreground.red + "\nsha256: ".ljust(20) + mycolors.reset + d['sha256'], end=' ')

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
                                                print(mycolors.foreground.blue + "".ljust(19) + k + ":\t" + mycolors.reset + (("\n" + " ".ljust(32)).join(textwrap.wrap(str(j[k]), width=80))), end="\n")

            print("\n")

        except ValueError as e:
            print(e)
            if (cv.bkg == 1):
                print((mycolors.foreground.lightred + "\nError while connecting to InQuest!\n"))
            else:
                print((mycolors.foreground.lightred + "\nError while connecting to InQuest!\n"))

    def inquest_url(self, inquestx):
        inquest = InQuestExtractor.inquesturl

        inquestresponse = ''

        self.requestINQUESTAPI()

        try:

            print("\n")
            print((mycolors.reset + "INQUEST URL SEARCH REPORT".center(110)), end='')
            print((mycolors.reset + "".center(28)), end='')
            print("\n" + (110 * '-').center(55))

            if (not inquestx):
                if (cv.bkg == 1):
                    print(mycolors.foreground.lightred + "\nThe -I parameter with the provided URL is required!\n" + mycolors.reset)
                else:
                    print(mycolors.foreground.red + "\nThe -I parameter with the provided URL is required!\n" + mycolors.reset)
                exit(1)

            requestsession = requests.Session()
            requestsession.headers.update({'Accept': 'application/json'})
            requestsession.headers.update({'Authorization': self.INQUESTAPI})
            inquestresponse = requestsession.get(inquest + '/search/ioc/url?keyword=' + inquestx)
            inquesttext = json.loads(inquestresponse.text)

            if (cv.bkg == 1):
                for i in inquesttext.keys():
                    if (i == "data"):
                        if (inquesttext['data'] is not None):
                            for d in inquesttext['data']:
                                y = d.keys()
                                print("\n" + (110 * '-').center(55), end='\n')
                                if ("sha256" in y):
                                    if d['sha256']:
                                        print(mycolors.foreground.lightcyan + "\nsha256: ".ljust(20) + mycolors.reset + d['sha256'], end=' ')

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
                                                print(mycolors.foreground.lightred + "".ljust(19) + k + ":\t" + mycolors.reset + (("\n" + " ".ljust(32)).join(textwrap.wrap(str(j[k]), width=80))), end="\n")

            if (cv.bkg == 0):
                for i in inquesttext.keys():
                    if (i == "data"):
                        if (inquesttext['data'] is not None):
                            for d in inquesttext['data']:
                                y = d.keys()
                                print("\n" + (110 * '-').center(55), end='\n')
                                if ("sha256" in y):
                                    if d['sha256']:
                                        print(mycolors.foreground.red + "\nsha256: ".ljust(20) + mycolors.reset + d['sha256'], end=' ')

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
                                                print(mycolors.foreground.purple + "".ljust(19) + k + ":\t" + mycolors.reset + (("\n" + " ".ljust(32)).join(textwrap.wrap(str(j[k]), width=80))), end="\n")

            print("\n")

        except ValueError as e:
            print(e)
            if (cv.bkg == 1):
                print((mycolors.foreground.lightred + "\nError while connecting to InQuest!\n"))
            else:
                print((mycolors.foreground.lightred + "\nError while connecting to InQuest!\n"))

    def inquest_ioc_search(self, inquestx):
        inquest = InQuestExtractor.inquesturl2

        inquestresponse = ''

        self.requestINQUESTAPI()

        try:

            print("\n")
            print((mycolors.reset + "INQUEST IOC SEARCH REPORT".center(110)), end='')
            print((mycolors.reset + "".center(28)), end='')
            print("\n" + (110 * '-').center(55))

            if (not inquestx):
                if (cv.bkg == 1):
                    print(mycolors.foreground.lightred + "\nThe -I parameter must have an IOC as argument!\n" + mycolors.reset)
                else:
                    print(mycolors.foreground.red + "\nThe -I parameter must have an IOC as argument!\n" + mycolors.reset)
                exit(1)

            requestsession = requests.Session()
            requestsession.headers.update({'Accept': 'application/json'})
            requestsession.headers.update({'Authorization': self.INQUESTAPI})
            inquestresponse = requestsession.get(inquest + '/search?keyword=' + inquestx)
            inquesttext = json.loads(inquestresponse.text)

            if (inquestresponse.status_code == 400 or inquestresponse.status_code == 500):
                inquesttext = json.loads(inquestresponse.text)

                if 'error' in inquesttext:
                    if inquesttext['error'] == "The 'keyword' parameter must be at least 3 bytes long.":
                        if (cv.bkg == 1):
                            print(mycolors.foreground.lightred + "\nThe -B parameter must be at least 3 bytes long!\n" + mycolors.reset)
                        else:
                            print(mycolors.foreground.red + "\nThe -B parameter must be at least 3 byte long!\n" + mycolors.reset)
                        exit(1)

            if (cv.bkg == 1):
                for i in inquesttext.keys():
                    if (i == "data"):
                        if (inquesttext['data'] is not None):
                            for d in inquesttext['data']:
                                print("\n" + (110 * '-').center(55), end='\n\n')
                                for k in d:
                                    print(mycolors.foreground.lightcyan + "".ljust(0) + k + ":\t" + mycolors.reset + (("\n" + " ".ljust(0)).join(textwrap.wrap(str(d[k]), width=80))), end="\n")

            if (cv.bkg == 0):
                for i in inquesttext.keys():
                    if (i == "data"):
                        if (inquesttext['data'] is not None):
                            for d in inquesttext['data']:
                                print("\n" + (110 * '-').center(55), end='\n\n')
                                for k in d:
                                    print(mycolors.foreground.cyan + "".ljust(0) + k + ":\t" + mycolors.reset + (("\n" + " ".ljust(0)).join(textwrap.wrap(str(d[k]), width=80))), end="\n")

        except ValueError as e:
            print(e)
            if (cv.bkg == 1):
                print((mycolors.foreground.lightred + "\nError while connecting to InQuest!\n"))
            else:
                print((mycolors.foreground.lightred + "\nError while connecting to InQuest!\n"))

    def inquest_ioc_list(self, inquestx):
        inquest = InQuestExtractor.inquesturl2

        inquestresponse = ''

        self.requestINQUESTAPI()

        try:

            print("\n")
            print((mycolors.reset + "INQUEST IOC SEARCH REPORT".center(110)), end='')
            print((mycolors.reset + "".center(28)), end='')
            print("\n" + (110 * '-').center(55))

            if (not inquestx == "list"):
                if (cv.bkg == 1):
                    print(mycolors.foreground.lightred + "\nThe -I parameter must have the word 'list' (no quotes) as argument!\n" + mycolors.reset)
                else:
                    print(mycolors.foreground.red + "\nThe -I parameter must have the word 'list' (no quotes) as argument!\n" + mycolors.reset)
                exit(1)

            requestsession = requests.Session()
            requestsession.headers.update({'Accept': 'application/json'})
            requestsession.headers.update({'Authorization': self.INQUESTAPI})
            inquestresponse = requestsession.get(inquest + '/list')
            inquesttext = json.loads(inquestresponse.text)

            if (cv.bkg == 1):
                for i in inquesttext.keys():
                    if (i == "data"):
                        if (inquesttext['data'] is not None):
                            for d in inquesttext['data']:
                                print("\n" + (110 * '-').center(55), end='\n\n')
                                for k in d:
                                    print(mycolors.foreground.yellow + "".ljust(0) + k + ":\t" + mycolors.reset + (("\n" + " ".ljust(0)).join(textwrap.wrap(str(d[k]), width=80))), end="\n")

            if (cv.bkg == 0):
                for i in inquesttext.keys():
                    if (i == "data"):
                        if (inquesttext['data'] is not None):
                            for d in inquesttext['data']:
                                print("\n" + (110 * '-').center(55), end='\n\n')
                                for k in d:
                                    print(mycolors.foreground.purple + "".ljust(0) + k + ":\t" + mycolors.reset + (("\n" + " ".ljust(0)).join(textwrap.wrap(str(d[k]), width=80))), end="\n")

        except ValueError as e:
            print(e)
            if (cv.bkg == 1):
                print((mycolors.foreground.lightred + "\nError while connecting to InQuest!\n"))
            else:
                print((mycolors.foreground.lightred + "\nError while connecting to InQuest!\n"))

    def inquest_rep_search(self, inquestx):
        inquest = InQuestExtractor.inquesturl3

        inquestresponse = ''

        self.requestINQUESTAPI()

        try:

            print("\n")
            print((mycolors.reset + "INQUEST REPUTATION SEARCH REPORT".center(110)), end='')
            print((mycolors.reset + "".center(28)), end='')
            print("\n" + (110 * '-').center(55), end='\n')

            if (not inquestx):
                if (cv.bkg == 1):
                    print(mycolors.foreground.lightred + "\nThe -I parameter must have an IOC as argument!\n" + mycolors.reset)
                else:
                    print(mycolors.foreground.red + "\nThe -I parameter must have an IOC as argument!\n" + mycolors.reset)
                exit(1)

            requestsession = requests.Session()
            requestsession.headers.update({'Accept': 'application/json'})
            requestsession.headers.update({'Authorization': self.INQUESTAPI})
            inquestresponse = requestsession.get(inquest + '/search?keyword=' + inquestx)
            inquesttext = json.loads(inquestresponse.text)

            if (inquestresponse.status_code == 400 or inquestresponse.status_code == 500):
                inquesttext = json.loads(inquestresponse.text)

                if 'error' in inquesttext:
                    if inquesttext['error'] == "The 'keyword' parameter must be at least 3 bytes long.":
                        if (cv.bkg == 1):
                            print(mycolors.foreground.lightred + "\nThe -B parameter must be at least 3 bytes long!\n" + mycolors.reset)
                        else:
                            print(mycolors.foreground.red + "\nThe -B parameter must be at least 3 byte long!\n" + mycolors.reset)
                        exit(1)

            if (cv.bkg == 1):
                for i in inquesttext.keys():
                    if (i == "data"):
                        if (inquesttext['data'] is not None):
                            for d in inquesttext['data']:
                                print("\n" + (110 * '-').center(55), end=' ')
                                print('\n')
                                for k in d:
                                    print(mycolors.foreground.lightred + "".ljust(0) + (k).rjust(12) + ": " + mycolors.reset + (("\n" + " ".ljust(16)).join(textwrap.wrap(str(d[k]), width=80))), end="\n")

            if (cv.bkg == 0):
                for i in inquesttext.keys():
                    if (i == "data"):
                        if (inquesttext['data'] is not None):
                            for d in inquesttext['data']:
                                print("\n" + (110 * '-').center(55), end=' ')
                                print('\n')
                                for k in d:
                                    print(mycolors.foreground.red + "".ljust(0) + (k).rjust(12) + ": " + mycolors.reset + (("\n" + " ".ljust(16)).join(textwrap.wrap(str(d[k]), width=80))), end="\n")

        except ValueError as e:
            print(e)
            if (cv.bkg == 1):
                print((mycolors.foreground.lightred + "\nError while connecting to InQuest!\n"))
            else:
                print((mycolors.foreground.lightred + "\nError while connecting to InQuest!\n"))

    def inquest_rep_list(self, inquestx):
        inquest = InQuestExtractor.inquesturl3

        inquestresponse = ''

        self.requestINQUESTAPI()

        try:

            print("\n")
            print((mycolors.reset + "INQUEST REPUTATION LIST REPORT".center(110)), end='')
            print((mycolors.reset + "".center(28)), end='')
            print("\n" + (110 * '-').center(55))

            if (not inquestx == "list"):
                if (cv.bkg == 1):
                    print(mycolors.foreground.lightred + "\nThe -I parameter must have the word 'list' (no quotes) as argument!\n" + mycolors.reset)
                else:
                    print(mycolors.foreground.red + "\nThe -I parameter must have the word 'list' (no quotes) as argument!\n" + mycolors.reset)
                exit(1)

            requestsession = requests.Session()
            requestsession.headers.update({'Accept': 'application/json'})
            requestsession.headers.update({'Authorization': self.INQUESTAPI})
            inquestresponse = requestsession.get(inquest + '/list')
            inquesttext = json.loads(inquestresponse.text)

            if (cv.bkg == 1):
                for i in inquesttext.keys():
                    if (i == "data"):
                        if (inquesttext['data'] is not None):
                            for d in inquesttext['data']:
                                print("\n" + (110 * '-').center(55), end=' ')
                                print('\n')
                                for k in d:
                                    print(mycolors.foreground.lightgreen + "".ljust(0) + (k).rjust(12) + ": " + mycolors.reset + (("\n" + " ".ljust(14)).join(textwrap.wrap(str(d[k]), width=80))), end="\n")

            if (cv.bkg == 0):
                for i in inquesttext.keys():
                    if (i == "data"):
                        if (inquesttext['data'] is not None):
                            for d in inquesttext['data']:
                                print("\n" + (110 * '-').center(55), end=' ')
                                print('\n')
                                for k in d:
                                    print(mycolors.foreground.purple + "".ljust(0) + (k).rjust(12) + ": " + mycolors.reset + (("\n" + " ".ljust(14)).join(textwrap.wrap(str(d[k]), width=80))), end="\n")

        except ValueError as e:
            print(e)
            if (cv.bkg == 1):
                print((mycolors.foreground.lightred + "\nError while connecting to InQuest!\n"))
            else:
                print((mycolors.foreground.lightred + "\nError while connecting to InQuest!\n"))
