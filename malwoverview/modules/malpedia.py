import malwoverview.modules.configvars as cv
from malwoverview.utils.colors import mycolors, printr
import requests
import textwrap
import base64
import json
import os

class MalpediaExtractor():
    malpediaurl = 'https://malpedia.caad.fkie.fraunhofer.de/api'

    def __init__(self, MALPEDIAAPI):
        self.MALPEDIAAPI = MALPEDIAAPI

    def requestMALPEDIAAPI(self):
        if (self.MALPEDIAAPI == ''):
            print(mycolors.foreground.red + "\nTo be able to get information from Malpedia, you must create the .malwapi.conf file under your user home directory (on Linux is $HOME\\.malwapi.conf and on Windows is in C:\\Users\\[username]\\.malwapi.conf) and insert the Malpedia API according to the format shown on the Github website." + mycolors.reset + "\n")
            exit(1)

    def malpedia_actors(self):
        urlx = MalpediaExtractor.malpediaurl

        hatext = ''
        haresponse = ''

        self.requestMALPEDIAAPI()

        try:

            resource = urlx
            requestsession = requests.Session()
            requestsession.headers.update({'Content-Type': 'application/json'})
            requestsession.headers.update({'Authorization': 'apitoken ' + self.MALPEDIAAPI})
            finalurl = '/'.join([resource, 'list', 'actors'])
            haresponse = requestsession.get(url=finalurl)
            hatext = json.loads(haresponse.text)

            if ('200' not in str(haresponse)):
                print(mycolors.foreground.red + "\nThe search key couldn't be found on Malpedia.\n", mycolors.reset)
                exit(1)

            if (cv.bkg == 1):
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

            if (cv.bkg == 0):
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
            if (cv.bkg == 1):
                print((mycolors.foreground.lightred + "Error while connecting to Malpedia!\n"))
            else:
                print((mycolors.foreground.red + "Error while connecting to Malpedia!\n"))
            printr()

    def malpedia_payloads(self):
        urlx = MalpediaExtractor.malpediaurl

        hatext = ''
        haresponse = ''

        self.requestMALPEDIAAPI()

        try:

            resource = urlx
            requestsession = requests.Session()
            requestsession.headers.update({'Content-Type': 'application/json'})
            requestsession.headers.update({'Authorization': 'apitoken ' + self.MALPEDIAAPI})
            finalurl = '/'.join([resource, 'list', 'samples'])
            haresponse = requestsession.get(url=finalurl)
            hatext = json.loads(haresponse.text)

            if ('200' not in str(haresponse)):
                print(mycolors.foreground.red + "\nThe search key couldn't be found on Malpedia.\n", mycolors.reset)
                exit(1)

            if (cv.bkg == 1):
                for key, value in hatext.items():
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

            if (cv.bkg == 0):
                for key, value in hatext.items():
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
            if (cv.bkg == 1):
                print((mycolors.foreground.lightred + "Error while connecting to Malpedia!\n"))
            else:
                print((mycolors.foreground.red + "Error while connecting to Malpedia!\n"))
            printr()

    def malpedia_get_actor(self, arg1):
        urlx = MalpediaExtractor.malpediaurl

        hatext = ''
        haresponse = ''
        myargs = arg1
        wrapper = textwrap.TextWrapper(width=100)

        self.requestMALPEDIAAPI()

        try:
            resource = urlx
            requestsession = requests.Session()
            requestsession.headers.update({'Content-Type': 'application/json'})
            requestsession.headers.update({'Authorization': 'apitoken ' + self.MALPEDIAAPI})
            finalurl = '/'.join([resource, 'get', 'actor', myargs])
            haresponse = requestsession.get(url=finalurl)
            hatext = json.loads(haresponse.text)

            if (cv.bkg == 1):
                if ('Not found.' in str(hatext)):
                    print(mycolors.foreground.yellow + "\nInformation about this actor couldn't be found on Malpedia.\n", mycolors.reset)
                    exit(1)

            if (cv.bkg == 0):
                if ('Not found.' in str(hatext)):
                    print(mycolors.foreground.cyan + "\nInformation about this actor couldn't be found on Malpedia.\n", mycolors.reset)
                    exit(1)

            if ('200' not in str(haresponse)):
                print(mycolors.foreground.red + "\nThe search key couldn't be found on Malpedia.\n", mycolors.reset)
                exit(1)

            if (cv.bkg == 1):
                if (hatext['value']):
                    print(mycolors.foreground.yellow + "\nActor:".ljust(11) + mycolors.reset + hatext['value'], end=' ')
                if (hatext['description']):
                    print(mycolors.foreground.yellow + "\n\nOverview: ".ljust(11) + mycolors.reset + ("\n".ljust(11)).join(textwrap.wrap(str(hatext['description']), width=100)), end=' ')
                for key, value in hatext.items():
                    if (key == 'meta'):
                        for key2, value2 in value.items():
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
                    if (key == 'families'):
                        for key3, value3 in value.items():
                            print("\n" + '-' * 112, end='')
                            print(mycolors.foreground.yellow + "\nFamily: ".ljust(11) + mycolors.reset + key3)
                            if 'updated' in value3.keys():
                                if (value3['updated']):
                                    print(mycolors.foreground.lightcyan + "Updated: ".ljust(10) + mycolors.reset + value3['updated'])
                            if 'attribution' in value3.keys():
                                if (len(value3['attribution']) > 0):
                                    print(mycolors.foreground.lightcyan + "Attrib.: ".ljust(9), end=' ')
                                    for y in value3['attribution']:
                                        print(mycolors.reset + y, end=' ')
                            if 'alt_names' in value3.keys():
                                if (len(value3['alt_names']) > 0):
                                    print(mycolors.foreground.lightcyan + "\nAliases: ".ljust(10), end=' ')
                                    for y in value3['alt_names']:
                                        print(mycolors.reset + y, end=' ')
                            if 'common_name' in value3.keys():
                                if (value3['common_name']):
                                    print(mycolors.foreground.lightcyan + "\nCommon: ".ljust(11) + mycolors.reset + value3['common_name'], end=' ')
                            if 'sources' in value3.keys():
                                if (len(value3['sources']) > 0):
                                    print(mycolors.foreground.lightcyan + "\nSources: ".ljust(11), end=' ')
                                    for y in value3['sources']:
                                        print(mycolors.reset + y, end=' ')
                            if 'description' in value3.keys():
                                if value3['description']:
                                    print(mycolors.foreground.lightcyan + "\nDescr.: ".ljust(11) + mycolors.reset + ("\n".ljust(11)).join(textwrap.wrap(str(value3['description']), width=100)), end=' ')
                            if 'urls' in value3.keys():
                                if (len(value3['urls']) > 0):
                                    for y in value3['urls']:
                                        print(mycolors.foreground.lightcyan + "\nURLs: ".ljust(11) + mycolors.reset + ("\n".ljust(11)).join(wrapper.wrap(str(y))).ljust(11), end=" ")

            if (cv.bkg == 0):
                if (hatext['value']):
                    print(mycolors.foreground.red + "\nActor:".ljust(11) + mycolors.reset + hatext['value'], end=' ')
                if (hatext['description']):
                    print(mycolors.foreground.red + "\n\nOverview: ".ljust(11) + mycolors.reset + ("\n".ljust(11)).join(textwrap.wrap(str(hatext['description']), width=100)), end=' ')
                for key, value in hatext.items():
                    if (key == 'meta'):
                        for key2, value2 in value.items():
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
                    if (key == 'families'):
                        for key3, value3 in value.items():
                            print("\n" + '-' * 112, end='')
                            print(mycolors.foreground.red + "\nFamily: ".ljust(11) + mycolors.reset + key3)
                            if 'updated' in value3.keys():
                                if (value3['updated']):
                                    print(mycolors.foreground.green + "Updated: ".ljust(10) + mycolors.reset + value3['updated'])
                            if 'attribution' in value3.keys():
                                if (len(value3['attribution']) > 0):
                                    print(mycolors.foreground.green + "Attrib.: ".ljust(9), end=' ')
                                    for y in value3['attribution']:
                                        print(mycolors.reset + y, end=' ')
                            if 'alt_names' in value3.keys():
                                if (len(value3['alt_names']) > 0):
                                    print(mycolors.foreground.green + "\nAliases: ".ljust(10), end=' ')
                                    for y in value3['alt_names']:
                                        print(mycolors.reset + y, end=' ')
                            if 'common_name' in value3.keys():
                                if (value3['common_name']):
                                    print(mycolors.foreground.green + "\nCommon: ".ljust(11) + mycolors.reset + value3['common_name'], end=' ')
                            if 'sources' in value3.keys():
                                if (len(value3['sources']) > 0):
                                    print(mycolors.foreground.green + "\nSources: ".ljust(11), end=' ')
                                    for y in value3['sources']:
                                        print(mycolors.reset + y, end=' ')
                            if 'description' in value3.keys():
                                if value3['description']:
                                    print(mycolors.foreground.green + "\nDescr.: ".ljust(11) + mycolors.reset + ("\n".ljust(11)).join(textwrap.wrap(str(value3['description']), width=100)), end=' ')
                            if 'urls' in value3.keys():
                                if (len(value3['urls']) > 0):
                                    for y in value3['urls']:
                                        print(mycolors.foreground.green + "\nURLs: ".ljust(11) + mycolors.reset + ("\n".ljust(11)).join(wrapper.wrap(str(y))).ljust(11), end=" ")

        except ValueError as e:
            print(e)
            if (cv.bkg == 1):
                print((mycolors.foreground.lightred + "Error while connecting to Malpedia!\n"))
            else:
                print((mycolors.foreground.red + "Error while connecting to Malpedia!\n"))
            printr()

    def malpedia_families(self):
        urlx = MalpediaExtractor.malpediaurl

        hatext = ''
        haresponse = ''
        # wrapper = textwrap.TextWrapper(width=100)

        self.requestMALPEDIAAPI()

        try:
            resource = urlx
            requestsession = requests.Session()
            requestsession.headers.update({'Content-Type': 'application/json'})
            requestsession.headers.update({'Authorization': 'apitoken ' + self.MALPEDIAAPI})
            finalurl = '/'.join([resource, 'list', 'families'])
            haresponse = requestsession.get(url=finalurl)
            hatext = json.loads(haresponse.text)

            if ('200' not in str(haresponse)):
                print(mycolors.foreground.red + "\nThe search key couldn't be found on Malpedia.\n", mycolors.reset)
                exit(1)

            if (cv.bkg == 1):
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

            if (cv.bkg == 0):
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
            if (cv.bkg == 1):
                print((mycolors.foreground.lightred + "Error while connecting to Malpedia!\n"))
            else:
                print((mycolors.foreground.red + "Error while connecting to Malpedia!\n"))
            printr()

    def malpedia_get_family(self, arg1):
        urlx = MalpediaExtractor.malpediaurl

        hatext = ''
        haresponse = ''
        myargs = arg1
        # wrapper = textwrap.TextWrapper(width=100)

        self.requestMALPEDIAAPI()

        try:

            resource = urlx
            requestsession = requests.Session()
            requestsession.headers.update({'Content-Type': 'application/json'})
            requestsession.headers.update({'Authorization': 'apitoken ' + self.MALPEDIAAPI})
            finalurl = '/'.join([resource, 'get', 'family', myargs])
            haresponse = requestsession.get(url=finalurl)
            hatext = json.loads(haresponse.text)

            if (cv.bkg == 1):
                if ('Not found.' in str(hatext)):
                    print(mycolors.foreground.yellow + "\nInformation about this family couldn't be found on Malpedia.\n", mycolors.reset)
                    exit(1)

            if (cv.bkg == 0):
                if ('Not found.' in str(hatext)):
                    print(mycolors.foreground.cyan + "\nInformation about this family couldn't be found on Malpedia.\n", mycolors.reset)
                    exit(1)

            if ('200' not in str(haresponse)):
                print(mycolors.foreground.red + "\nThe search key couldn't be found on Malpedia.\n", mycolors.reset)
                exit(1)

            if (cv.bkg == 1):
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
                    print(mycolors.foreground.yellow + "\nDescription: ".ljust(13) + mycolors.reset + ("\n".ljust(14)).join(textwrap.wrap(hatext['description'], width=110)), end='\n')

                if (hatext['urls']):
                    j = 0
                    for i in hatext['urls']:
                        if (j < 10):
                            print(mycolors.foreground.yellow + "\nURL_%d:".ljust(15) % j + mycolors.reset + ("\n".ljust(14)).join(textwrap.wrap(i, width=110)), end=' ')
                        if (j > 9 and j < 100):
                            print(mycolors.foreground.yellow + "\nURL_%d:".ljust(14) % j + mycolors.reset + ("\n".ljust(14)).join(textwrap.wrap(i, width=110)), end=' ')
                        if (j > 99):
                            print(mycolors.foreground.yellow + "\nURL_%d:".ljust(13) % j + mycolors.reset + ("\n".ljust(14)).join(textwrap.wrap(i, width=110)), end=' ')
                        j = j + 1

            if (cv.bkg == 0):
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
                    print(mycolors.foreground.cyan + "\nDescription: ".ljust(13) + mycolors.reset + ("\n".ljust(14)).join(textwrap.wrap(hatext['description'], width=110)), end='\n')

                if (hatext['urls']):
                    j = 0
                    for i in hatext['urls']:
                        if (j < 10):
                            print(mycolors.foreground.cyan + "\nURL_%d:".ljust(15) % j + mycolors.reset + ("\n".ljust(14)).join(textwrap.wrap(i, width=110)), end=' ')
                        if (j > 9 and j < 100):
                            print(mycolors.foreground.cyan + "\nURL_%d:".ljust(14) % j + mycolors.reset + ("\n".ljust(14)).join(textwrap.wrap(i, width=110)), end=' ')
                        if (j > 99):
                            print(mycolors.foreground.cyan + "\nURL_%d:".ljust(13) % j + mycolors.reset + ("\n".ljust(14)).join(textwrap.wrap(i, width=110)), end=' ')
                        j = j + 1

        except ValueError as e:
            print(e)
            if (cv.bkg == 1):
                print((mycolors.foreground.lightred + "Error while connecting to Malpedia!\n"))
            else:
                print((mycolors.foreground.red + "Error while connecting to Malpedia!\n"))
            printr()

    def malpedia_get_sample(self, arg1):
        if len(arg1) not in [32, 64]:
            return False

        urlx = MalpediaExtractor.malpediaurl

        hatext = ''
        haresponse = ''
        myargs = arg1

        self.requestMALPEDIAAPI()

        try:
            resource = urlx
            requestsession = requests.Session()
            requestsession.headers.update({'Content-Type': 'application/json'})
            requestsession.headers.update({'Authorization': 'apitoken ' + self.MALPEDIAAPI})
            finalurl = '/'.join([resource, 'get', 'sample', myargs, 'zip'])
            haresponse = requestsession.get(url=finalurl)
            hatext = json.loads(haresponse.text)

            if (cv.bkg == 1):
                if ('Not found.' in str(hatext)):
                    print(mycolors.foreground.yellow + "\nThis sample couldn't be found on Malpedia.\n", mycolors.reset)
                    exit(1)

            if (cv.bkg == 0):
                if ('Not found.' in str(hatext)):
                    print(mycolors.foreground.cyan + "\nThis sample couldn't be found on Malpedia.\n", mycolors.reset)
                    exit(1)

            if ('200' not in str(haresponse)):
                print(mycolors.foreground.red + "\nThe search key couldn't be found on Malpedia.\n", mycolors.reset)
                exit(1)

            if ('200' in str(haresponse)):
                outputpath = os.path.join(cv.output_dir, myargs + ".zip")
                open(outputpath, 'wb').write(base64.b64decode(hatext['zipped']))
                if (cv.bkg == 1):
                    print(mycolors.foreground.lightcyan + f"\nSample downloaded to: {outputpath}\n", mycolors.reset)
                else:
                    print(mycolors.foreground.green + f"\nSample downloaded to: {outputpath}\n", mycolors.reset)
                exit(0)

        except ValueError as e:
            print(e)
            if (cv.bkg == 1):
                print((mycolors.foreground.lightred + "Error while connecting to Malpedia!\n"))
            else:
                print((mycolors.foreground.red + "Error while connecting to Malpedia!\n"))
            printr()

    def malpedia_get_yara(self, arg1):
        urlx = MalpediaExtractor.malpediaurl

        hatext = ''
        haresponse = ''
        myargs = arg1

        self.requestMALPEDIAAPI()

        try:
            resource = urlx
            requestsession = requests.Session()
            requestsession.headers.update({'Content-Type': 'application/json'})
            requestsession.headers.update({'Authorization': 'apitoken ' + self.MALPEDIAAPI})
            finalurl = '/'.join([resource, 'get', 'yara', myargs, 'zip'])
            haresponse = requestsession.get(url=finalurl)

            if (cv.bkg == 1):
                if ('Not found.' in str(hatext)):
                    print(mycolors.foreground.yellow + "\nThe Yara rule for this family couldn't be found on Malpedia.\n", mycolors.reset)
                    exit(1)

            if (cv.bkg == 0):
                if ('Not found.' in str(hatext)):
                    print(mycolors.foreground.cyan + "\nThe Yara rule for this family couldn't be found on Malpedia.\n", mycolors.reset)
                    exit(1)

            if ('200' not in str(haresponse)):
                print(mycolors.foreground.red + "\nThe search key couldn't be found on Malpedia.\n", mycolors.reset)
                exit(1)

            if ('200' in str(haresponse)):
                outputpath = os.path.join(cv.output_dir, myargs + ".zip")
                if (cv.bkg == 1):
                    open(outputpath, 'wb').write(haresponse.content)
                    print(mycolors.foreground.lightcyan + "\nA zip file named %s.zip containing Yara rules has been SUCCESSFULLY downloaded from Malpedia!\n" % myargs, mycolors.reset)
                else:
                    open(outputpath, 'wb').write(haresponse.content)
                    print(mycolors.foreground.green + "\nA zip file named %s.zip containing Yara rules has been SUCCESSFULLY downloaded from Malpedia!\n" % myargs, mycolors.reset)
                    exit(0)
        except ValueError as e:
            print(e)
            if (cv.bkg == 1):
                print((mycolors.foreground.lightred + "Error while connecting to Malpedia!\n"))
            else:
                print((mycolors.foreground.red + "Error while connecting to Malpedia!\n"))
            printr()
