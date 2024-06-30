import malwoverview.modules.configvars as cv
import requests
import json
from malwoverview.utils.colors import mycolors, printr


class ThreatFoxExtractor():
    urlthreatfox = 'https://threatfox-api.abuse.ch/api/v1/'

    def __init__(self):
        pass

    def threatfox_listiocs(self, bazaarx):
        bazaar = ThreatFoxExtractor.urlthreatfox

        bazaartext = ''
        bazaarresponse = ''
        params = ''

        try:
            print("\n")
            print((mycolors.reset + "THREATFOX REPORT".center(100)), end='')
            print((mycolors.reset + "".center(28)), end='')
            print("\n" + (100 * '-').center(50))

            requestsession = requests.Session()
            requestsession.headers.update({'accept': 'application/json'})
            params = {'query': "get_iocs", 'days': int(bazaarx)}

            bazaarresponse = requestsession.post(
                url=bazaar,
                data=json.dumps(params)
            )
            bazaartext = json.loads(bazaarresponse.text)

            if (cv.bkg == 1):
                for i in bazaartext.keys():
                    if (i == "data"):
                        if (bazaartext['data'] is not None):
                            for d in bazaartext['data']:
                                y = d.keys()
                                print("\n" + (90 * '-').center(45), end=' ')
                                if ("ioc" in y):
                                    if d['ioc']:
                                        print(mycolors.foreground.yellow + "\nioc: ".ljust(16) + mycolors.reset + d['ioc'], end=' ')

                                if ("id" in y):
                                    if d['id']:
                                        print(mycolors.foreground.yellow + "\nid: ".ljust(16) + mycolors.reset + d['id'], end=' ')

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
                                        print(mycolors.foreground.yellow + "\ntags: ".ljust(16), end='')
                                        for t in d['tags']:
                                            print(mycolors.reset + t, end=' ')

            if (cv.bkg == 0):
                for i in bazaartext.keys():
                    if (i == "data"):
                        if (bazaartext['data'] is not None):
                            for d in bazaartext['data']:
                                y = d.keys()
                                print("\n" + (90 * '-').center(45), end=' ')
                                if ("ioc" in y):
                                    if d['ioc']:
                                        print(mycolors.foreground.red + "\nioc: ".ljust(16) + mycolors.reset + d['ioc'], end=' ')

                                if ("id" in y):
                                    if d['id']:
                                        print(mycolors.foreground.red + "\nid: ".ljust(16) + mycolors.reset + d['id'], end=' ')

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
                                        print(mycolors.foreground.red + "\ntags: ".ljust(16), end='')
                                        for t in d['tags']:
                                            print(mycolors.reset + t, end=' ')

            printr()
            exit(0)
        except ValueError as e:
            print(e)
            if (cv.bkg == 1):
                print((mycolors.foreground.lightred + "\nError while connecting to ThreatFox!\n"))
            else:
                print((mycolors.foreground.lightred + "\nError while connecting to ThreatFox!\n"))
            printr()

    def threatfox_searchiocs(self, bazaarx):
        bazaar = ThreatFoxExtractor.urlthreatfox

        bazaartext = ''
        bazaarresponse = ''
        params = ''

        try:
            print("\n")
            print((mycolors.reset + "THREATFOX REPORT".center(100)), end='')
            print((mycolors.reset + "".center(28)), end='')
            print("\n" + (100 * '-').center(50))

            requestsession = requests.Session()
            requestsession.headers.update({'accept': 'application/json'})
            params = {'query': "search_ioc", 'search_term': bazaarx}
            bazaarresponse = requestsession.post(url=bazaar, data=json.dumps(params))
            bazaartext = json.loads(bazaarresponse.text)

            if bazaartext['query_status'] == "no_result":
                if (cv.bkg == 1):
                    print(mycolors.foreground.lightred + "\nYour search did not yield any result!\n" + mycolors.reset)
                else:
                    print(mycolors.foreground.red + "\nYour search did not yield any result!\n" + mycolors.reset)
                exit(1)

            if bazaartext['query_status'] == "illegal_search_term":
                if (cv.bkg == 1):
                    print(mycolors.foreground.lightred + "\nThe search term you have provided is not valid!\n" + mycolors.reset)
                else:
                    print(mycolors.foreground.red + "\nThe search term you have provided is not valid!\n" + mycolors.reset)
                exit(1)

            if (cv.bkg == 1):
                for i in bazaartext.keys():
                    if (i == "data"):
                        if (bazaartext['data'] is not None):
                            for d in bazaartext['data']:
                                y = d.keys()
                                print("\n" + (90 * '-').center(45), end=' ')
                                if ("ioc" in y):
                                    if d['ioc']:
                                        print(mycolors.foreground.yellow + "\nioc: ".ljust(16) + mycolors.reset + d['ioc'], end=' ')

                                if ("id" in y):
                                    if d['ioc']:
                                        print(mycolors.foreground.yellow + "\nid: ".ljust(16) + mycolors.reset + d['id'], end=' ')

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
                                        print(mycolors.foreground.yellow + "\ntags: ".ljust(16), end='')
                                        for t in d['tags']:
                                            print(mycolors.reset + t, end=' ')

            if (cv.bkg == 0):
                for i in bazaartext.keys():
                    if (i == "data"):
                        if (bazaartext['data'] is not None):
                            for d in bazaartext['data']:
                                y = d.keys()
                                print("\n" + (90 * '-').center(45), end=' ')
                                if ("ioc" in y):
                                    if d['ioc']:
                                        print(mycolors.foreground.red + "\nioc: ".ljust(16) + mycolors.reset + d['ioc'], end=' ')

                                if ("id" in y):
                                    if d['ioc']:
                                        print(mycolors.foreground.red + "\nid: ".ljust(16) + mycolors.reset + d['id'], end=' ')

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
                                        print(mycolors.foreground.red + "\ntags: ".ljust(16), end='')
                                        for t in d['tags']:
                                            print(mycolors.reset + t, end=' ')

            printr()
            exit(0)

        except ValueError as e:
            print(e)
            if (cv.bkg == 1):
                print((mycolors.foreground.lightred + "\nError while connecting to ThreatFox!\n"))
            else:
                print((mycolors.foreground.lightred + "\nError while connecting to ThreatFox!\n"))
            printr()

    def threatfox_searchtags(self, bazaarx):
        bazaar = ThreatFoxExtractor.urlthreatfox

        bazaartext = ''
        bazaarresponse = ''
        params = ''

        try:

            print("\n")
            print((mycolors.reset + "THREATFOX REPORT".center(100)), end='')
            print((mycolors.reset + "".center(28)), end='')
            print("\n" + (100 * '-').center(50))

            requestsession = requests.Session()
            requestsession.headers.update({'accept': 'application/json'})
            params = {'query': "taginfo", 'tag': bazaarx}
            bazaarresponse = requestsession.post(url=bazaar, data=json.dumps(params))
            bazaartext = json.loads(bazaarresponse.text)

            if bazaartext['query_status'] == "no_result":
                if (cv.bkg == 1):
                    print(mycolors.foreground.lightred + "\nYour search did not yield any result!\n" + mycolors.reset)
                else:
                    print(mycolors.foreground.red + "\nYour search did not yield any result!\n" + mycolors.reset)
                exit(1)

            if bazaartext['query_status'] == "illegal_search_term":
                if (cv.bkg == 1):
                    print(mycolors.foreground.lightred + "\nThe search term you have provided is not valid!\n" + mycolors.reset)
                else:
                    print(mycolors.foreground.red + "\nThe search term you have provided is not valid!\n" + mycolors.reset)
                exit(1)

            if bazaartext['query_status'] == "illegal_tag":
                if (cv.bkg == 1):
                    print(mycolors.foreground.lightred + "\nThe tag you have provided is not valid!\n" + mycolors.reset)
                else:
                    print(mycolors.foreground.red + "\nThe tag you have provided is not valid!\n" + mycolors.reset)
                exit(1)

            if (cv.bkg == 1):
                for i in bazaartext.keys():
                    if (i == "data"):
                        if (bazaartext['data'] is not None):
                            for d in bazaartext['data']:
                                y = d.keys()
                                print("\n" + (90 * '-').center(45), end=' ')
                                if ("ioc" in y):
                                    if d['ioc']:
                                        print(mycolors.foreground.lightcyan + "\nioc: ".ljust(16) + mycolors.reset + d['ioc'], end=' ')

                                if ("id" in y):
                                    if d['ioc']:
                                        print(mycolors.foreground.lightcyan + "\nid: ".ljust(16) + mycolors.reset + d['id'], end=' ')

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
                                        print(mycolors.foreground.lightcyan + "\ntags: ".ljust(16), end='')
                                        for t in d['tags']:
                                            print(mycolors.reset + t, end=' ')

            if (cv.bkg == 0):
                for i in bazaartext.keys():
                    if (i == "data"):
                        if (bazaartext['data'] is not None):
                            for d in bazaartext['data']:
                                y = d.keys()
                                print("\n" + (90 * '-').center(45), end=' ')
                                if ("ioc" in y):
                                    if d['ioc']:
                                        print(mycolors.foreground.cyan + "\nioc: ".ljust(16) + mycolors.reset + d['ioc'], end=' ')

                                if ("id" in y):
                                    if d['ioc']:
                                        print(mycolors.foreground.cyan + "\nid: ".ljust(16) + mycolors.reset + d['id'], end=' ')

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
                                        print(mycolors.foreground.cyan + "\ntags: ".ljust(16), end='')
                                        for t in d['tags']:
                                            print(mycolors.reset + t, end=' ')

            printr()
            exit(0)

        except ValueError as e:
            print(e)
            if (cv.bkg == 1):
                print((mycolors.foreground.lightred + "\nError while connecting to ThreatFox!\n"))
            else:
                print((mycolors.foreground.lightred + "\nError while connecting to ThreatFox!\n"))
            printr()

    def threatfox_searchmalware(self, bazaarx):
        bazaar = ThreatFoxExtractor.urlthreatfox

        bazaartext = ''
        bazaarresponse = ''
        params = ''

        try:

            print("\n")
            print((mycolors.reset + "THREATFOX REPORT".center(100)), end='')
            print((mycolors.reset + "".center(28)), end='')
            print("\n" + (100 * '-').center(50))

            requestsession = requests.Session()
            requestsession.headers.update({'accept': 'application/json'})
            params = {'query': "malwareinfo", 'malware': bazaarx}
            bazaarresponse = requestsession.post(url=bazaar, data=json.dumps(params))
            bazaartext = json.loads(bazaarresponse.text)

            if bazaartext['query_status'] == "no_result":
                if (cv.bkg == 1):
                    print(mycolors.foreground.lightred + "\nYour search did not yield any result!\n" + mycolors.reset)
                else:
                    print(mycolors.foreground.red + "\nYour search did not yield any result!\n" + mycolors.reset)
                exit(1)

            if bazaartext['query_status'] == "illegal_search_term":
                if (cv.bkg == 1):
                    print(mycolors.foreground.lightred + "\nThe search term you have provided is not valid!\n" + mycolors.reset)
                else:
                    print(mycolors.foreground.red + "\nThe search term you have provided is not valid!\n" + mycolors.reset)
                exit(1)

            if (cv.bkg == 1):
                for i in bazaartext.keys():
                    if (i == "data"):
                        if (bazaartext['data'] is not None):
                            for d in bazaartext['data']:
                                y = d.keys()
                                print("\n" + (90 * '-').center(45), end=' ')
                                if ("ioc" in y):
                                    if d['ioc']:
                                        print(mycolors.foreground.lightcyan + "\nioc: ".ljust(16) + mycolors.reset + d['ioc'], end=' ')

                                if ("id" in y):
                                    if d['ioc']:
                                        print(mycolors.foreground.lightcyan + "\nid: ".ljust(16) + mycolors.reset + d['id'], end=' ')

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
                                        print(mycolors.foreground.lightcyan + "\ntags: ".ljust(16), end='')
                                        for t in d['tags']:
                                            print(mycolors.reset + t, end=' ')

            if (cv.bkg == 0):
                for i in bazaartext.keys():
                    if (i == "data"):
                        if (bazaartext['data'] is not None):
                            for d in bazaartext['data']:
                                y = d.keys()
                                print("\n" + (90 * '-').center(45), end=' ')
                                if ("ioc" in y):
                                    if d['ioc']:
                                        print(mycolors.foreground.green + "\nioc: ".ljust(16) + mycolors.reset + d['ioc'], end=' ')

                                if ("id" in y):
                                    if d['ioc']:
                                        print(mycolors.foreground.green + "\nid: ".ljust(16) + mycolors.reset + d['id'], end=' ')

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
                                        print(mycolors.foreground.green + "\ntags: ".ljust(16), end='')
                                        for t in d['tags']:
                                            print(mycolors.reset + t, end=' ')

            printr()
            exit(0)

        except ValueError as e:
            print(e)
            if (cv.bkg == 1):
                print((mycolors.foreground.lightred + "\nError while connecting to ThreatFox!\n"))
            else:
                print((mycolors.foreground.lightred + "\nError while connecting to ThreatFox!\n"))
            printr()

    def threatfox_listmalware(self):
        bazaar = ThreatFoxExtractor.urlthreatfox

        bazaartext = ''
        bazaarresponse = ''
        params = ''

        try:

            print("\n")
            print((mycolors.reset + "THREATFOX REPORT".center(100)), end='')
            print((mycolors.reset + "".center(28)), end='')
            print("\n" + (100 * '-').center(50))

            requestsession = requests.Session()
            requestsession.headers.update({'accept': 'application/json'})
            params = {'query': "malware_list"}
            bazaarresponse = requestsession.post(url=bazaar, data=json.dumps(params))
            bazaartext = json.loads(bazaarresponse.text)

            if bazaartext['query_status'] == "no_result":
                if (cv.bkg == 1):
                    print(mycolors.foreground.lightred + "\nYour search did not yield any result!\n" + mycolors.reset)
                else:
                    print(mycolors.foreground.red + "\nYour search did not yield any result!\n" + mycolors.reset)
                exit(1)

            if (cv.bkg == 1):
                for i in bazaartext.keys():
                    if (i == "data"):
                        if (bazaartext['data'] is not None):
                            for d in bazaartext['data']:
                                for reference, info in bazaartext['data'].items():
                                    print("\n" + (80 * '-').center(40), end=' ')
                                    print(mycolors.foreground.yellow + "\nmalware_family: ".ljust(16) + mycolors.reset + reference, end=' ')
                                    for key in info:
                                        print(mycolors.reset + "\n".ljust(17) + "%-18s" % key + ': ', end='')
                                        print(info[key], end='')
                                break

            if (cv.bkg == 0):
                for i in bazaartext.keys():
                    if (i == "data"):
                        if (bazaartext['data'] is not None):
                            for d in bazaartext['data']:
                                for reference, info in bazaartext['data'].items():
                                    print("\n" + (80 * '-').center(40), end=' ')
                                    print(mycolors.foreground.purple + "\nmalware_family: ".ljust(16) + mycolors.reset + reference, end=' ')
                                    for key in info:
                                        print(mycolors.reset + "\n".ljust(17) + "%-18s" % key + ': ', end='')
                                        print(info[key], end='')
                                break

            printr()
            exit(0)

        except ValueError as e:
            print(e)
            if (cv.bkg == 1):
                print((mycolors.foreground.lightred + "\nError while connecting to ThreatFox!\n"))
            else:
                print((mycolors.foreground.lightred + "\nError while connecting to ThreatFox!\n"))
            printr()
