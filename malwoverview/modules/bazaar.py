import malwoverview.modules.configvars as cv
from malwoverview.utils.colors import mycolors, printr
import requests
import json
import os
from malwoverview.utils.session import create_session
from malwoverview.utils.hash import sha256hash
from malwoverview.utils.cache import cached

class BazaarExtractor():
    urlbazaar = 'https://mb-api.abuse.ch/api/v1/'

    def __init__(self, BAZAARAPI):
        self.BAZAARAPI = BAZAARAPI

    def requestBAZAARAPI(self):
        if (self.BAZAARAPI == ''):
            print(mycolors.foreground.red + "\nTo be able to get/submit information from/to Malware Bazaar, you must create the .malwapi.conf file under your user home directory (on Linux is $HOME\\.malwapi.conf and on Windows is in C:\\Users\\[username]\\.malwapi.conf) and insert the Malware Bazaar API (Auth-Key) according to the format shown on the Github website." + mycolors.reset + "\n")
            exit(1)

    def bazaar_tag(self, bazaarx):
        bazaar = BazaarExtractor.urlbazaar
        bazaartext = ''
        bazaarresponse = ''
        params = ''

        self.requestBAZAARAPI()

        try:
            print("\n")
            print((mycolors.reset + "MALWARE BAZAAR REPORT".center(100)), end='')
            print((mycolors.reset + "".center(28)), end='')
            print("\n" + (100 * '-').center(50))

            requestsession = create_session()
            requestsession.headers.update({'accept': 'application/json'})
            requestsession.headers.update({'Auth-Key': self.BAZAARAPI})
            params = {'query': 'get_taginfo', "tag": bazaarx, "limit": 50}
            bazaarresponse = requestsession.post(bazaar, data=params)
            bazaartext = json.loads(bazaarresponse.text)

            if bazaartext['query_status'] == "tag_not_found":
                if (cv.bkg == 1):
                    print(mycolors.foreground.lightred + "\nThe provided tag was not found!\n" + mycolors.reset)
                else:
                    print(mycolors.foreground.red + "\nThe provided tag was not found!\n" + mycolors.reset)
                exit(1)

            if bazaartext['query_status'] == "illegal_tag":
                if (cv.bkg == 1):
                    print(mycolors.foreground.lightred + "\nThe provided tag is not valid!\n" + mycolors.reset)
                else:
                    print(mycolors.foreground.red + "\nThe provided tag is not valid!\n" + mycolors.reset)
                exit(1)

            if bazaartext['query_status'] == "no_results":
                if (cv.bkg == 1):
                    print(mycolors.foreground.lightred + "\nYour query yield no results!\n" + mycolors.reset)
                else:
                    print(mycolors.foreground.red + "\nYour query yield no results!\n" + mycolors.reset)
                exit(1)

            if (cv.bkg == 1):
                for i in bazaartext.keys():
                    if (i == "data"):
                        if (bazaartext['data'] is not None):
                            for d in bazaartext['data']:
                                y = d.keys()
                                print("\n" + (90 * '-').center(45), end=' ')
                                if ("sha256_hash" in y):
                                    if d['sha256_hash']:
                                        print(mycolors.foreground.lightcyan + "\nsha256_hash: ".ljust(15) + mycolors.reset + d['sha256_hash'], end=' ')

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
                                        print(mycolors.foreground.lightcyan + "\ntags: ".ljust(15), end='')
                                        for t in d['tags']:
                                            print(mycolors.reset + t, end=' ')

            if (cv.bkg == 0):
                for i in bazaartext.keys():
                    if (i == "data"):
                        if (bazaartext['data'] is not None):
                            for d in bazaartext['data']:
                                y = d.keys()
                                print("\n" + (90 * '-').center(45), end=' ')
                                if ("sha256_hash" in y):
                                    if d['sha256_hash']:
                                        print(mycolors.foreground.blue + "\nsha256_hash: ".ljust(15) + mycolors.reset + d['sha256_hash'], end=' ')

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
                                        print(mycolors.foreground.blue + "\ntags: ".ljust(15), end='')
                                        for t in d['tags']:
                                            print(mycolors.reset + t, end=' ')

            printr()
            exit(0)

        except ValueError as e:
            print(e)
            if (cv.bkg == 1):
                print((mycolors.foreground.lightred + "\nError while connecting to Malware Bazaar!\n"))
            else:
                print((mycolors.foreground.lightred + "\nError while connecting to Malware Bazaar!\n"))
            printr()

    def bazaar_imphash(self, bazaarx):
        bazaar = BazaarExtractor.urlbazaar
        bazaartext = ''
        params = ''

        self.requestBAZAARAPI()

        try:

            print("\n")
            print((mycolors.reset + "MALWARE BAZAAR REPORT".center(100)), end='')
            print((mycolors.reset + "".center(28)), end='')
            print("\n" + (100 * '-').center(50))

            requestsession = create_session()
            requestsession.headers.update({'accept': 'application/json'})
            requestsession.headers.update({'Auth-Key': self.BAZAARAPI})
            params = {'query': 'get_imphash', "imphash": bazaarx, "limit": 50}
            bazaarresponse = requestsession.post(bazaar, data=params)
            bazaartext = json.loads(bazaarresponse.text)

            if bazaartext['query_status'] == "imphash_not_found":
                if (cv.bkg == 1):
                    print(mycolors.foreground.lightred + "\nThe provided imphash was not found!\n" + mycolors.reset)
                else:
                    print(mycolors.foreground.red + "\nThe provided imphash was not found!\n" + mycolors.reset)
                exit(1)

            if bazaartext['query_status'] == "illegal_imphash":
                if (cv.bkg == 1):
                    print(mycolors.foreground.lightred + "\nThe provided imphash is not valid!\n" + mycolors.reset)
                else:
                    print(mycolors.foreground.red + "\nThe provided imphash is not valid!\n" + mycolors.reset)
                exit(1)

            if bazaartext['query_status'] == "no_results":
                if (cv.bkg == 1):
                    print(mycolors.foreground.lightred + "\nYour query yield no results!\n" + mycolors.reset)
                else:
                    print(mycolors.foreground.red + "\nYour query yield no results!\n" + mycolors.reset)
                exit(1)

            if (cv.bkg == 1):
                for i in bazaartext.keys():
                    if (i == "data"):
                        if (bazaartext['data'] is not None):
                            for d in bazaartext['data']:
                                y = d.keys()
                                print("\n" + (90 * '-').center(45), end=' ')
                                if ("sha256_hash" in y):
                                    if d['sha256_hash']:
                                        print(mycolors.foreground.pink + "\nsha256_hash: ".ljust(15) + mycolors.reset + d['sha256_hash'], end=' ')

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
                                        print(mycolors.foreground.pink + "\ntags: ".ljust(15), end='')
                                        for t in d['tags']:
                                            print(mycolors.reset + t, end=' ')

            if (cv.bkg == 0):
                for i in bazaartext.keys():
                    if (i == "data"):
                        if (bazaartext['data'] is not None):
                            for d in bazaartext['data']:
                                y = d.keys()
                                print("\n" + (90 * '-').center(45), end=' ')
                                if ("sha256_hash" in y):
                                    if d['sha256_hash']:
                                        print(mycolors.foreground.purple + "\nsha256_hash: ".ljust(15) + mycolors.reset + d['sha256_hash'], end=' ')

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
                                        print(mycolors.foreground.purple + "\ntags: ".ljust(15), end='')
                                        for t in d['tags']:
                                            print(mycolors.reset + t, end=' ')

            printr()
            exit(0)

        except ValueError as e:
            print(e)
            if (cv.bkg == 1):
                print((mycolors.foreground.lightred + "\nError while connecting to Malware Bazaar!\n"))
            else:
                print((mycolors.foreground.lightred + "\nError while connecting to Malware Bazaar!\n"))
            printr()

    def bazaar_lastsamples(self, bazaarx):
        bazaar = BazaarExtractor.urlbazaar

        bazaartext = ''
        bazaarresponse = ''
        params = ''

        self.requestBAZAARAPI()

        try:
            print("\n")
            print((mycolors.reset + "MALWARE BAZAAR REPORT".center(100)), end='')
            print((mycolors.reset + "".center(28)), end='')
            print("\n" + (100 * '-').center(50))

            requestsession = create_session()
            requestsession.headers.update({'accept': 'application/json'})
            requestsession.headers.update({'Auth-Key': self.BAZAARAPI})
            params = {'query': 'get_recent', "selector": bazaarx}
            bazaarresponse = requestsession.post(bazaar, data=params)
            bazaartext = json.loads(bazaarresponse.text)

            if bazaartext['query_status'] == "unknown_selector":
                if (cv.bkg == 1):
                    print(mycolors.foreground.lightred + "\nYou didn't provide a valid selector!\n" + mycolors.reset)
                else:
                    print(mycolors.foreground.red + "\nYour search did not yield any result!\n" + mycolors.reset)
                exit(1)

            if bazaartext['query_status'] == "no_results":
                if (cv.bkg == 1):
                    print(mycolors.foreground.lightred + "\nThe query yield no results!\n" + mycolors.reset)
                else:
                    print(mycolors.foreground.red + "\nThe query yield no results!\n" + mycolors.reset)
                exit(1)

            if (cv.bkg == 1):
                for i in bazaartext.keys():
                    if (i == "data"):
                        if (bazaartext['data'] is not None):
                            for d in bazaartext['data']:
                                y = d.keys()
                                print("\n" + (90 * '-').center(45), end=' ')
                                if ("sha256_hash" in y):
                                    if d['sha256_hash']:
                                        print(mycolors.foreground.yellow + "\nsha256_hash: ".ljust(15) + mycolors.reset + d['sha256_hash'], end=' ')

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
                                        print(mycolors.foreground.yellow + "\ntags: ".ljust(15), end='')
                                        for t in d['tags']:
                                            print(mycolors.reset + t, end=' ')

            if (cv.bkg == 0):
                for i in bazaartext.keys():
                    if (i == "data"):
                        if (bazaartext['data'] is not None):
                            for d in bazaartext['data']:
                                y = d.keys()
                                print("\n" + (90 * '-').center(45), end=' ')
                                if ("sha256_hash" in y):
                                    if d['sha256_hash']:
                                        print(mycolors.foreground.cyan + "\nsha256_hash: ".ljust(15) + mycolors.reset + d['sha256_hash'], end=' ')

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
                                        print(mycolors.foreground.cyan + "\ntags: ".ljust(15), end='')
                                        for t in d['tags']:
                                            print(mycolors.reset + t, end=' ')

            printr()
            exit(0)

        except ValueError as e:
            print(e)
            if (cv.bkg == 1):
                print((mycolors.foreground.lightred + "\nError while connecting to Malware Bazaar!\n"))
            else:
                print((mycolors.foreground.lightred + "\nError while connecting to Malware Bazaar!\n"))
            printr()

    def bazaar_download(self, bazaarx):
        bazaar = BazaarExtractor.urlbazaar

        bazaartext = ''
        bazaarresponse = ''
        params = ''
        resource = bazaarx

        self.requestBAZAARAPI()

        try:
            print("\n")
            print((mycolors.reset + "MALWARE BAZAAR REPORT".center(100)), end='')
            print((mycolors.reset + "".center(28)), end='')
            print("\n" + (100 * '-').center(50))

            requestsession = create_session()
            requestsession.headers.update({'accept': 'application/gzip'})
            requestsession.headers.update({'Auth-Key': self.BAZAARAPI})
            params = {'query': 'get_file', "sha256_hash": bazaarx}
            bazaarresponse = requestsession.post(bazaar, data=params, allow_redirects=False, stream=True, timeout=60)
            
            MAX_DOWNLOAD_SIZE = 500 * 1024 * 1024
            content = bytearray()
            for chunk in bazaarresponse.iter_content(chunk_size=8192):
                if chunk:
                    content += chunk
                    if len(content) > MAX_DOWNLOAD_SIZE:
                        print(mycolors.foreground.red + "\nError: File too large (>500MB). Download aborted.\n" + mycolors.reset)
                        exit(1)
            bazaartext = content.decode('utf-8', errors='ignore')

            if "illegal_sha256_hash" in bazaartext:
                if (cv.bkg == 1):
                    print(mycolors.foreground.lightred + "\nYou didn't provide a valid sha256 hash!\n" + mycolors.reset)
                else:
                    print(mycolors.foreground.red + "\nYou didn't provide a valid selector!\n" + mycolors.reset)
                exit(1)

            if "file_not_found" in bazaartext:
                if (cv.bkg == 1):
                    print(mycolors.foreground.lightred + "\nNo malware samples found for the provided sha256 hash!\n" + mycolors.reset)
                else:
                    print(mycolors.foreground.red + "\nNo malware samples found for the provided sha256 hash!\n" + mycolors.reset)
                exit(1)

            safe_filename = os.path.basename(resource) + '.zip'
            outputpath = os.path.join(cv.output_dir, safe_filename)
            with open(outputpath, 'wb') as f:
                f.write(content)
            final = f'\nSample downloaded to: {outputpath}'

            if (cv.bkg == 1):
                print((mycolors.foreground.yellow + final + "\n"))
            else:
                print((mycolors.foreground.green + final + "\n"))

            printr()
            exit(0)

        except ValueError as e:
            print(e)
            if (cv.bkg == 1):
                print((mycolors.foreground.lightred + "Error while connecting to Malware Bazaar!\n"))
            else:
                print((mycolors.foreground.lightred + "Error while connecting to Malware Bazaar!\n"))
            printr()

    def bazaar_hash(self, bazaarx):
        bazaar = BazaarExtractor.urlbazaar

        bazaartext = ''
        bazaarresponse = ''
        params = ''

        self.requestBAZAARAPI()

        try:
            print("\n")
            print((mycolors.reset + "MALWARE BAZAAR REPORT".center(100)), end='')
            print((mycolors.reset + "".center(28)), end='')
            print("\n" + (100 * '-').center(50))

            requestsession = create_session()
            requestsession.headers.update({'accept': 'application/json'})
            requestsession.headers.update({'Auth-Key': self.BAZAARAPI})
            params = {'query': 'get_info', "hash": bazaarx}
            bazaarresponse = requestsession.post(bazaar, data=params)
            bazaartext = json.loads(bazaarresponse.text)

            if bazaartext['query_status'] == "hash_not_found":
                if (cv.bkg == 1):
                    print(mycolors.foreground.lightred + "\nThe provided hash was not found!\n" + mycolors.reset)
                else:
                    print(mycolors.foreground.red + "\nThe provided hash was not found!\n" + mycolors.reset)
                exit(1)

            if bazaartext['query_status'] == "illegal_hash":
                if (cv.bkg == 1):
                    print(mycolors.foreground.lightred + "\nThe provided hash is not valid!\n" + mycolors.reset)
                else:
                    print(mycolors.foreground.red + "\nThe provided hash is not valid!\n" + mycolors.reset)
                exit(1)

            if (cv.bkg == 1):
                for i in bazaartext.keys():
                    if (i == "data"):
                        if (bazaartext['data'] is not None):
                            for d in bazaartext['data']:
                                y = d.keys()
                                if ("sha256_hash" in y):
                                    if d['sha256_hash']:
                                        print(mycolors.foreground.lightcyan + "\nsha256_hash: ".ljust(15) + mycolors.reset + d['sha256_hash'], end=' ')

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
                                    print(mycolors.foreground.lightcyan + "\noleinformation: ".ljust(15), end='')
                                    for t in d['oleinformation']:
                                        print(mycolors.reset + t, end=' ')

                                if ("delivery_method" in y):
                                    if d['delivery_method']:
                                        print(mycolors.foreground.lightcyan + "\ndelivery: ".ljust(15) + mycolors.reset + d['delivery_method'], end=' ')

                                if ("tags" in y):
                                    if d['tags']:
                                        print(mycolors.foreground.lightcyan + "\ntags: ".ljust(15), end='')
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
                                                print(mycolors.foreground.yellow + "\nTriage sigs: ".ljust(15) + mycolors.reset, end='\n')
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

            if (cv.bkg == 0):
                for i in bazaartext.keys():
                    if (i == "data"):
                        if (bazaartext['data'] is not None):
                            for d in bazaartext['data']:
                                y = d.keys()
                                if ("sha256_hash" in y):
                                    if d['sha256_hash']:
                                        print(mycolors.foreground.green + "\nsha256_hash: ".ljust(15) + mycolors.reset + d['sha256_hash'], end=' ')

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
                                    print(mycolors.foreground.green + "\noleinformation: ".ljust(15), end='')
                                    for t in d['oleinformation']:
                                        print(mycolors.reset + t, end=' ')

                                if ("delivery_method" in y):
                                    if d['delivery_method']:
                                        print(mycolors.foreground.green + "\ndelivery: ".ljust(15) + mycolors.reset + d['delivery_method'], end=' ')

                                if ("tags" in y):
                                    if d['tags']:
                                        print(mycolors.foreground.green + "\ntags: ".ljust(15), end='')
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
                                                print(mycolors.foreground.red + "\nTriage sigs: ".ljust(15) + mycolors.reset, end='\n')
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

            printr()
            exit(0)

        except ValueError as e:
            print(e)
            if (cv.bkg == 1):
                print((mycolors.foreground.lightred + "\nError while connecting to Malware Bazaar!\n"))
            else:
                print((mycolors.foreground.lightred + "\nError while connecting to Malware Bazaar!\n"))
            printr()

    def bazaar_batchcheck(self, filename):
        bazaar = 'https://mb-api.abuse.ch/api/v1/'

        self.requestBAZAARAPI()

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

        print(mycolors.reset + "\n%-66s %-6s %-11s %s" % ("Hash", "Type", "Signature", "Tags"))
        print((110 * '-'))

        requestsession = create_session()
        requestsession.headers.update({'accept': 'application/json'})
        requestsession.headers.update({'Auth-Key': self.BAZAARAPI})

        for h in hashes:
            try:
                params = {'query': 'get_info', 'hash': h}
                response = requestsession.post(bazaar, data=params, timeout=60)
                bazaartext = json.loads(response.text)

                file_type = ''
                signature = ''
                tags = ''

                if bazaartext.get('query_status') == 'ok' and bazaartext.get('data'):
                    sample = bazaartext['data'][0]
                    file_type = str(sample.get('file_type', '')) if sample.get('file_type') else ''
                    signature = str(sample.get('signature', '')) if sample.get('signature') else ''
                    tags_list = sample.get('tags', [])
                    tags = ', '.join(tags_list[:4]) if tags_list else ''

                if (cv.bkg == 1):
                    print(mycolors.foreground.yellow + "%-66s " % h, end='')
                    print(mycolors.foreground.lightcyan + "%-6s " % file_type, end='')
                    print(mycolors.foreground.lightred + "%-11s " % signature, end='')
                    print(mycolors.foreground.pink + "%s" % tags)
                else:
                    print(mycolors.foreground.cyan + "%-66s " % h, end='')
                    print(mycolors.foreground.blue + "%-6s " % file_type, end='')
                    print(mycolors.foreground.red + "%-11s " % signature, end='')
                    print(mycolors.foreground.purple + "%s" % tags)

            except Exception as e:
                if (cv.bkg == 1):
                    print(mycolors.foreground.lightred + "%-66s error: %s" % (h, str(e)))
                else:
                    print(mycolors.foreground.red + "%-66s error: %s" % (h, str(e)))

        printr()

    def bazaar_dircheck(self, directory):
        bazaar = 'https://mb-api.abuse.ch/api/v1/'

        self.requestBAZAARAPI()

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

        print(mycolors.reset + "\n%-42s %-66s %-6s %-11s %s" % ("Filename", "Hash", "Type", "Signature", "Tags"))
        print((150 * '-'))

        requestsession = create_session()
        requestsession.headers.update({'accept': 'application/json'})
        requestsession.headers.update({'Auth-Key': self.BAZAARAPI})

        for fname, h in files:
            try:
                params = {'query': 'get_info', 'hash': h}
                response = requestsession.post(bazaar, data=params, timeout=60)
                bazaartext = json.loads(response.text)

                file_type = ''
                signature = ''
                tags = ''

                if bazaartext.get('query_status') == 'ok' and bazaartext.get('data'):
                    sample = bazaartext['data'][0]
                    file_type = str(sample.get('file_type', '')) if sample.get('file_type') else ''
                    signature = str(sample.get('signature', '')) if sample.get('signature') else ''
                    tags_list = sample.get('tags', [])
                    tags = ', '.join(tags_list[:4]) if tags_list else ''

                if (cv.bkg == 1):
                    print(mycolors.foreground.lightgreen + "%-42s " % fname[:40], end='')
                    print(mycolors.foreground.yellow + "%-66s " % h, end='')
                    print(mycolors.foreground.lightcyan + "%-6s " % file_type, end='')
                    print(mycolors.foreground.lightred + "%-11s " % signature, end='')
                    print(mycolors.foreground.pink + "%s" % tags)
                else:
                    print(mycolors.foreground.blue + "%-42s " % fname[:40], end='')
                    print(mycolors.foreground.cyan + "%-66s " % h, end='')
                    print(mycolors.foreground.blue + "%-6s " % file_type, end='')
                    print(mycolors.foreground.red + "%-11s " % signature, end='')
                    print(mycolors.foreground.purple + "%s" % tags)

            except Exception as e:
                if (cv.bkg == 1):
                    print(mycolors.foreground.lightred + "%-42s error: %s" % (fname[:40], str(e)))
                else:
                    print(mycolors.foreground.red + "%-42s error: %s" % (fname[:40], str(e)))

        printr()

    @cached("bazaar_hash")
    def _raw_hash_info(self, hash_value):
        try:
            bazaar = 'https://mb-api.abuse.ch/api/v1/'
            requestsession = create_session()
            requestsession.headers.update({'Auth-Key': self.BAZAARAPI})
            params = {'query': 'get_info', 'hash': hash_value}
            response = requestsession.post(bazaar, data=params, timeout=60)
            if response.status_code == 200:
                data = response.json()
                if data.get('query_status') == 'ok' and data.get('data'):
                    return data['data'][0]
        except Exception:
            pass
        return None
