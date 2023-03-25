import modules.configvars as cv
import requests
import textwrap
from colorama import Fore
import validators
from utils.colors import mycolors, printr
from utils.utils import urltoip
import json
import sys


class URLHausExtractor():
    hauss = 'https://urlhaus.abuse.ch/api/'
    hausq = 'https://urlhaus-api.abuse.ch/v1/url/'
    hausb = 'https://urlhaus-api.abuse.ch/v1/urls/recent/'
    hausp = 'https://urlhaus-api.abuse.ch/v1/payloads/recent/'
    hausph = 'https://urlhaus-api.abuse.ch/v1/payload/'
    hausd = 'https://urlhaus-api.abuse.ch/v1/download/'
    haust = 'https://urlhaus-api.abuse.ch/v1/tag/'
    haussig = 'https://urlhaus-api.abuse.ch/v1/signature/'

    def __init__(self, HAUSSUBMITAPI):
        self.HAUSSUBMITAPI = HAUSSUBMITAPI

    def requestHAUSSUBMITAPI(self):
        if (self.HAUSSUBMITAPI == ''):
            print(mycolors.foreground.red + "\nTo be able to get/submit information from/to URLHaus, you must create the .malwapi.conf file under your user home directory (on Linux is $HOME\\.malwapi.conf and on Windows is in C:\\Users\\[username]\\.malwapi.conf) and insert the URLHaus API according to the format shown on the Github website." + mycolors.reset + "\n")
            exit(1)

    def haussigsearchroutine(self, payloadtagx):
        haus = URLHausExtractor.haussig
        haustext = ''
        hausresponse = ''
        params = ''

        try:
            print("\n")
            print((mycolors.reset + "URLHaus Report".center(126)), end='')
            print((mycolors.reset + "".center(28)), end='')
            print("\n" + (126 * '-').center(59))

            requestsession9 = requests.Session()
            requestsession9.headers.update({'accept': 'application/json'})
            params = {"signature": payloadtagx}
            hausresponse = requestsession9.post(haus, data=params)
            haustext = json.loads(hausresponse.text)

            if 'query_status' in haustext:
                if (cv.bkg == 1):
                    print(mycolors.foreground.lightcyan + "Is available?: \t" + haustext.get('query_status').upper())
                else:
                    print(mycolors.foreground.green + "Is available?: \t" + haustext.get('query_status').upper())
            else:
                if (cv.bkg == 1):
                    print(mycolors.foreground.lightcyan + 'Is availble?: Not available')
                else:
                    print(mycolors.foreground.green + 'Is available?: Not available')

            if 'firstseen' in haustext:
                if haustext.get('firstseen') is not None:
                    if (cv.bkg == 1):
                        print(mycolors.foreground.lightcyan + "First Seen: \t" + haustext.get('firstseen'))
                    else:
                        print(mycolors.foreground.cyan + "First Seen: \t" + haustext.get('firstseen'))
                else:
                    if (cv.bkg == 1):
                        print(mycolors.foreground.lightcyan + 'First Seen: ')
                    else:
                        print(mycolors.foreground.cyan + 'First Seen: ')

            if 'lastseen' in haustext:
                if haustext.get('lastseen') is not None:
                    if (cv.bkg == 1):
                        print(mycolors.foreground.lightcyan + "Last Seen: \t" + haustext.get('lastseen'))
                    else:
                        print(mycolors.foreground.cyan + "Last Seen: \t" + haustext.get('lastseen'))
                else:
                    if (cv.bkg == 1):
                        print(mycolors.foreground.lightcyan + 'Last Seen: ')
                    else:
                        print(mycolors.foreground.cyan + 'Last Seen: ')

            if 'url_count' in haustext:
                if haustext.get('url_count') is not None:
                    if (cv.bkg == 1):
                        print(mycolors.foreground.lightred + "URL count: \t" + haustext.get('url_count'))
                    else:
                        print(mycolors.foreground.red + "URL count: \t" + haustext.get('url_count'))
                else:
                    if (cv.bkg == 1):
                        print(mycolors.foreground.lightred + 'URL count: ')
                    else:
                        print(mycolors.foreground.red + 'URL count: ')

            if 'payload_count' in haustext:
                if haustext.get('payload_count') is not None:
                    if (cv.bkg == 1):
                        print(mycolors.foreground.lightred + "Payload count: \t" + haustext.get('payload_count'))
                    else:
                        print(mycolors.foreground.red + "Payload count: \t" + haustext.get('payload_count'))
                else:
                    if (cv.bkg == 1):
                        print(mycolors.foreground.lightred + 'Payload count: ')
                    else:
                        print(mycolors.foreground.red + 'Payload count: ')

            if (cv.bkg == 1):
                print(mycolors.foreground.yellow + "Tag:\t\t%s" % payloadtagx)
            else:
                print(mycolors.foreground.pink + "Tag:\t\t%s" % payloadtagx)

            if 'urls' in haustext:
                if ('url_id' in haustext['urls']) is not None:
                    print(mycolors.reset + "\nStatus".center(9) + " " * 2 + "FType".ljust(7) + " SHA256 Hash".center(64) + " " * 4 + "Virus Total".ljust(14) + ' ' * 2 + "URL to Payload".center(34))
                    print("-" * 140 + "\n")
                    for w in haustext['urls']:
                        if (cv.bkg == 1):
                            if (w['url_status'] == 'online'):
                                print(mycolors.foreground.lightcyan + mycolors.reverse + w['url_status'] + " " + mycolors.reset, end=' ')
                            if (w['url_status'] == 'offline'):
                                print(mycolors.foreground.lightred + mycolors.reverse + w['url_status'] + mycolors.reset, end=' ')
                            if (w['url_status'] == ''):
                                print(mycolors.foreground.yellow + mycolors.reverse + "unknown" + mycolors.reset, end=' ')
                            if w['file_type']:
                                print(mycolors.foreground.lightcyan + ' ' * 2 + "%-6s" % w['file_type'] + mycolors.reset, end=' ')
                            else:
                                print(mycolors.foreground.lightcyan + ' ' * 2 + "%-6s" % "data" + mycolors.reset, end=' ')
                            if w['sha256_hash']:
                                print(mycolors.foreground.yellow + w['sha256_hash'] + mycolors.reset, end=' ')
                            if w['virustotal']:
                                print(mycolors.foreground.lightcyan + ' ' * 2 + "%-9s" % w['virustotal'].get('result') + mycolors.reset, end='\t  ')
                            else:
                                print(mycolors.foreground.lightcyan + ' ' * 2 + "%-9s" % "Not Found" + mycolors.reset, end='\t  ')
                            if (w['url']):
                                print(mycolors.foreground.lightred + (("\n" + " ".ljust(98)).join(textwrap.wrap(w['url'], width=35))), end="\n")
                            else:
                                print(mycolors.foreground.lightred + ' ' * 2 + "URL not provided".center(20) + mycolors.reset)

                        else:
                            if (w['url_status'] == 'online'):
                                print(mycolors.foreground.green + mycolors.reverse + w['url_status'] + " " + mycolors.reset, end=' ')
                            if (w['url_status'] == 'offline'):
                                print(mycolors.foreground.red + mycolors.reverse + w['url_status'] + mycolors.reset, end=' ')
                            if (w['url_status'] == ''):
                                print(mycolors.foreground.blue + mycolors.reverse + "unknown" + mycolors.reset, end=' ')
                            if w['file_type']:
                                print(mycolors.foreground.purple + ' ' * 2 + "%-6s" % w['file_type'] + mycolors.reset, end=' ')
                            else:
                                print(mycolors.foreground.purple + ' ' * 2 + "%-6s" % "data" + mycolors.reset, end=' ')
                            if w['sha256_hash']:
                                print(mycolors.foreground.red + w['sha256_hash'] + mycolors.reset, end=' ')
                            if w['virustotal']:
                                print(mycolors.foreground.cyan + ' ' * 2 + "%-9s" % w['virustotal'].get('result') + mycolors.reset, end=' ')
                            else:
                                print(mycolors.foreground.cyan + ' ' * 2 + "%-9s" % "Not Found" + mycolors.reset, end=' ')
                            if (w['url']):
                                print(mycolors.foreground.green + (("\n" + " ".ljust(98)).join(textwrap.wrap(w['url'], width=35))), end="\n")
                            else:
                                print(mycolors.foreground.green + ' ' * 2 + "URL not provided".center(20) + mycolors.reset)

            printr()

        except (BrokenPipeError, IOError, TypeError):
            print(mycolors.reset, file=sys.stderr)
            exit(1)

        except ValueError as e:
            print(e)
            if (cv.bkg == 1):
                print((mycolors.foreground.lightred + "Error while connecting to URLhaus!\n"))
            else:
                print((mycolors.foreground.lightred + "Error while connecting to URLhaus!\n"))
            printr()

    def haustagsearchroutine(self, haustag):
        hausurltag = URLHausExtractor.haust
        haustext = ''
        hausresponse = ''
        params = ''

        try:

            print("\n")
            print((mycolors.reset + "URLHaus Report".center(126)), end='')
            print((mycolors.reset + "".center(28)), end='')
            print("\n" + (130 * '-').center(59))

            params = {"tag": haustag}
            requestsession = requests.Session()
            requestsession.headers.update({'accept': 'application/json'})
            hausresponse = requestsession.post(hausurltag, data=params)
            haustext = json.loads(hausresponse.text)

            if 'query_status' in haustext:
                if (cv.bkg == 1):
                    print(mycolors.foreground.lightcyan + "Is available?: \t" + haustext.get('query_status').upper())
                else:
                    print(mycolors.foreground.green + "Is available?: \t" + haustext.get('query_status').upper())
            else:
                if (cv.bkg == 1):
                    print(mycolors.foreground.lightcyan + 'Is availble?: Not available')
                else:
                    print(mycolors.foreground.green + 'Is available?: Not available')

            if 'firstseen' in haustext:
                if haustext.get('firstseen') is not None:
                    if (cv.bkg == 1):
                        print(mycolors.foreground.lightcyan + "First Seen: \t" + haustext.get('firstseen'))
                    else:
                        print(mycolors.foreground.cyan + "First Seen: \t" + haustext.get('firstseen'))
                else:
                    if (cv.bkg == 1):
                        print(mycolors.foreground.lightcyan + 'First Seen: ')
                    else:
                        print(mycolors.foreground.cyan + 'First Seen: ')

            if 'lastseen' in haustext:
                if haustext.get('lastseen') is not None:
                    if (cv.bkg == 1):
                        print(mycolors.foreground.lightcyan + "Last Seen: \t" + haustext.get('lastseen'))
                    else:
                        print(mycolors.foreground.cyan + "Last Seen: \t" + haustext.get('lastseen'))
                else:
                    if (cv.bkg == 1):
                        print(mycolors.foreground.lightcyan + 'Last Seen: ')
                    else:
                        print(mycolors.foreground.cyan + 'Last Seen: ')

            if 'url_count' in haustext:
                if haustext.get('url_count') is not None:
                    if (cv.bkg == 1):
                        print(mycolors.foreground.lightred + "URL count: \t" + haustext.get('url_count'))
                    else:
                        print(mycolors.foreground.red + "URL count: \t" + haustext.get('url_count'))
                else:
                    if (cv.bkg == 1):
                        print(mycolors.foreground.lightred + 'URL count: \tNot Found')
                    else:
                        print(mycolors.foreground.red + 'URL count: \tNot Found')

            if (cv.bkg == 1):
                print(mycolors.foreground.yellow + "Tag:\t\t%s" % haustag)
            else:
                print(mycolors.foreground.pink + "Tag:\t\t%s" % haustag)

            if 'urls' in haustext:
                if ('url_id' in haustext['urls']) is not None:
                    print(mycolors.reset + "\nStatus".center(9) + " " * 6 + " " * 2 + "Date Added".ljust(22) + " Threat".ljust(17) + " " * 28 + "Associated URL".ljust(80))
                    print("-" * 130 + "\n")

                    for w in haustext['urls']:
                        if (cv.bkg == 1):
                            if (w['url_status'] == 'online'):
                                print(mycolors.foreground.lightcyan + mycolors.reverse + w['url_status'] + " " + mycolors.reset, end=' ')
                            if (w['url_status'] == 'offline'):
                                print(mycolors.foreground.lightred + mycolors.reverse + w['url_status'] + mycolors.reset, end=' ')
                            if (w['url_status'] == ''):
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
                                    print(mycolors.foreground.yellow + ("\n" + "".ljust(51)).join(textwrap.wrap(w['url'], width=80)).ljust(80), end="\n")
                                else:
                                    print(mycolors.foreground.yellow + " " * 2 + "URL not provided".center(80) + mycolors.reset)

                        else:
                            if (w['url_status'] == 'online'):
                                print(mycolors.foreground.green + mycolors.reverse + w['url_status'] + " " + mycolors.reset, end=' ')
                            if (w['url_status'] == 'offline'):
                                print(mycolors.foreground.red + mycolors.reverse + w['url_status'] + mycolors.reset, end=' ')
                            if (w['url_status'] == ''):
                                print(mycolors.foreground.cyan + mycolors.reverse + "unknown" + mycolors.reset, end=' ')
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
                                    print(mycolors.foreground.red + ("\n" + "".ljust(51)).join(textwrap.wrap(w['url'], width=80)).ljust(80), end="\n")
                                else:
                                    print(mycolors.foreground.red + " " * 2 + "URL not provided".center(80) + mycolors.reset, end=' ')

            printr()

        except (BrokenPipeError, IOError, TypeError):
            print(mycolors.reset, file=sys.stderr)
            exit(1)

        except ValueError as e:
            print(e)
            if (cv.bkg == 1):
                print((mycolors.foreground.lightred + "Error while connecting to URLhaus!\n"))
            else:
                print((mycolors.foreground.lightred + "Error while connecting to URLhaus!\n"))
            printr()

    def haussample(self, hashx):
        haus = URLHausExtractor.hausd
        if len(hashx) != 64:
            return False

        hatext = ''
        response = ''
        finalurl = ''

        try:
            resource = hashx
            requestsession = requests.Session()
            requestsession.headers.update({'accept': 'application/gzip'})
            finalurl = ''.join([haus, resource])
            response = requestsession.get(url=finalurl, allow_redirects=True)
            hatext = response.text

            rc = str(hatext)
            if 'not_found' in rc:
                final = 'Malware sample is not available to download.'
                if (cv.bkg == 1):
                    print((mycolors.foreground.lightred + "\n" + final + "\n" + mycolors.reset))
                else:
                    print((mycolors.foreground.red + "\n" + final + "\n" + mycolors.reset))
                exit(1)
            if 'copy_error' in rc:
                final = 'It has occured an error while downloading.'
                if (cv.bkg == 1):
                    print((mycolors.foreground.lightred + "\n" + final + "\n" + mycolors.reset))
                else:
                    print((mycolors.foreground.red + "\n" + final + "\n" + mycolors.reset))
                exit(1)

            open(resource + '.zip', 'wb').write(response.content)
            final = '\nSAMPLE SAVED!'

            if (cv.bkg == 1):
                print((mycolors.foreground.yellow + final + "\n"))
            else:
                print((mycolors.foreground.green + final + "\n"))
        except (BrokenPipeError, IOError, TypeError):
            print(mycolors.reset, file=sys.stderr)
            exit(1)

        except ValueError as e:
            print(e)
            if (cv.bkg == 1):
                print((mycolors.foreground.lightred + "Error while connecting to URLhaus!\n"))
            else:
                print((mycolors.foreground.red + "Error while connecting to URLhaus!\n"))
            printr()

        printr()
        exit(0)

    def hausgetbatch(self):
        haus = URLHausExtractor.hausb
        haustext = ''
        hausresponse = ''
        nurl = 0
        alltags = ''
        c = 0

        try:
            print("\n")
            print((mycolors.reset + "URLhaus Recent Malicious URLs".center(104)), end='')
            print((mycolors.reset + "".center(28)), end='')
            print("\n" + (126 * '-').center(59))

            requestsession7 = requests.Session()
            requestsession7.headers.update({'accept': 'application/json'})
            hausresponse = requestsession7.get(haus)
            haustext = json.loads(hausresponse.text)
            nurl = len(haustext['urls'])

            if (nurl > 0):
                try:
                    for i in range(0, nurl):
                        if 'url' in haustext['urls'][i]:
                            if (cv.bkg == 1):
                                if (haustext['urls'][i].get('url_status') == 'online'):
                                    print(mycolors.foreground.lightcyan + haustext['urls'][i].get('url_status') + " " + mycolors.reset, end=' ')
                                if (haustext['urls'][i].get('url_status') == 'offline'):
                                    print(mycolors.foreground.lightred + haustext['urls'][i].get('url_status') + mycolors.reset, end=' ')
                                if (haustext['urls'][i].get('url_status') == ''):
                                    print(mycolors.foreground.yellow + "unknown" + mycolors.reset, end=' ')
                                if 'tags' in haustext['urls'][i]:
                                    print(mycolors.foreground.yellow, end='')
                                    if haustext['urls'][i].get('tags') is not None:
                                        alltags = haustext['urls'][i].get('tags')
                                        for t in alltags:
                                            print("%s" % t, end=' ')
                                            c += len(t)
                                        print(" " * ((45 - c) - len(alltags)), end=' ')
                                    else:
                                        print(" " * 45, end=' ')
                                print(mycolors.reset + ("\n".ljust(55)).join(textwrap.wrap((haustext['urls'][i].get('url')).ljust(14), width=75)), end='\n')
                                c = 0
                            else:
                                if (haustext['urls'][i].get('url_status') == 'online'):
                                    print(mycolors.foreground.green + haustext['urls'][i].get('url_status') + " " + mycolors.reset, end=' ')
                                if (haustext['urls'][i].get('url_status') == 'offline'):
                                    print(mycolors.foreground.red + haustext['urls'][i].get('url_status') + mycolors.reset, end=' ')
                                if (haustext['urls'][i].get('url_status') == ''):
                                    print(mycolors.foreground.cyan + "unknown" + mycolors.reset, end=' ')
                                if 'tags' in haustext['urls'][i]:
                                    print(mycolors.foreground.blue, end='')
                                    if haustext['urls'][i].get('tags') is not None:
                                        alltags = haustext['urls'][i].get('tags')
                                        for t in alltags:
                                            print("%s" % t, end=' ')
                                            c += len(t)
                                        print(" " * ((45 - c) - len(alltags)), end=' ')
                                    else:
                                        print(" " * 45, end=' ')
                                print(mycolors.reset + ("\n".ljust(55)).join(textwrap.wrap((haustext['urls'][i].get('url')).ljust(14), width=75)), end='\n')
                                c = 0

                    print(mycolors.reset, file=sys.stderr)

                except KeyError:
                    pass

                except (BrokenPipeError, IOError, TypeError):
                    print(mycolors.reset, file=sys.stderr)

            printr()
        except KeyError:
            pass
        except (BrokenPipeError, IOError, TypeError):
            printr()
            exit(1)
        except ValueError as e:
            print(e)
            if (cv.bkg == 1):
                print((mycolors.foreground.lightred + "Error while connecting to URLhaus!\n"))
            else:
                print((mycolors.foreground.red + "Error while connecting to URLhaus!\n"))
            printr()

    def hauspayloadslist(self):
        haus = URLHausExtractor.hausp
        haustext = ''
        hausresponse = ''
        npayloads = 0

        try:
            print("\n")
            print((mycolors.reset + "Haus Downloadable Links to Recent Payloads".center(146)), end='')
            print((mycolors.reset + "".center(28)), end='')
            print("\n" + (146 * '-').center(59))

            requestsession8 = requests.Session()
            requestsession8.headers.update({'accept': 'application/json'})
            hausresponse = requestsession8.get(haus)
            haustext = json.loads(hausresponse.text)
            npayloads = len(haustext['payloads'])

            if (npayloads > 0):
                try:
                    for i in range(0, npayloads):
                        if 'sha256_hash' in haustext['payloads'][i]:
                            if (cv.bkg == 1):
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

                    print(mycolors.reset, file=sys.stderr)

                except KeyError:
                    pass

                except (BrokenPipeError, IOError, TypeError):
                    print(mycolors.reset, file=sys.stderr)

            print(mycolors.reset, file=sys.stderr)

        except KeyError:
            pass

        except (BrokenPipeError, IOError, TypeError):
            print(mycolors.reset, file=sys.stderr)
            exit(1)

        except ValueError as e:
            print(e)
            if (cv.bkg == 1):
                print((mycolors.foreground.lightred + "Error while connecting to URLhaus!\n"))
            else:
                print((mycolors.foreground.red + "Error while connecting to URLhaus!\n"))
            printr()

    def urlhauscheck(self, urlx):
        haus = URLHausExtractor.hausq

        if (not urlx or not validators.url(urlx)):
            if (cv.bkg == 0):
                print(mycolors.foreground.red + "\nYou didn't provide a valid URL.\n")
                printr()
                exit(1)
            else:
                print(mycolors.foreground.yellow + "\nYou didn't provide a valid URL.\n")
                printr()
                exit(1)

        haustext = ''
        hausresponse = ''

        try:
            print("\n")
            print((mycolors.reset + "URLhaus Report".center(100)), end='')
            print((mycolors.reset + "".center(28)), end='')
            print("\n" + (126 * '-').center(59))

            requestsession = requests.Session()
            requestsession.headers.update({'accept': 'application/json'})
            params = {"url": urlx}
            hausresponse = requestsession.post(haus, data=params)
            haustext = json.loads(hausresponse.text)

            if (haustext.get('id') is None):
                if (cv.bkg == 1):
                    print(mycolors.foreground.lightred + "URL not found!\n" + mycolors.reset)
                else:
                    print(mycolors.foreground.red + "URL not found!\n" + mycolors.reset)
                exit(1)

            if 'query_status' in haustext:
                if (cv.bkg == 1):
                    print(mycolors.foreground.lightcyan + "Is available?: \t" + haustext.get('query_status').upper())
                else:
                    print(mycolors.foreground.purple + "Is available?: \t" + haustext.get('query_status').upper())
            else:
                if (cv.bkg == 1):
                    print(mycolors.foreground.lightcyan + 'Is availble?: ')
                else:
                    print(mycolors.foreground.purple + 'Is available: ')

            if 'url' in haustext:
                if (validators.url(haustext.get('url'))):
                    urlcity = urltoip(haustext.get('url'))
                    if (urlcity is None):
                        urlcity = 'Not found'
                else:
                    urlcity = 'Not found'
                if (cv.bkg == 1):
                    print(mycolors.foreground.lightcyan + "URL: \t\t" + haustext.get('url') + "  (city: " + urlcity + ")")
                else:
                    print(mycolors.foreground.purple + "URL: \t\t" + haustext.get('url') + "  (city: " + urlcity + ")")
            else:
                if (cv.bkg == 1):
                    print(mycolors.foreground.lightcyan + 'URL: ')
                else:
                    print(mycolors.foreground.purple + 'URL: ')

            if 'url_status' in haustext:
                if (cv.bkg == 1):
                    if (haustext.get('url_status') == 'online'):
                        print(mycolors.foreground.lightcyan + "Status: \t" + mycolors.reverse + haustext.get('url_status') + mycolors.reset)
                    if (haustext.get('url_status') == 'offline'):
                        print(mycolors.foreground.lightred + "Status: \t" + mycolors.reverse + haustext.get('url_status') + mycolors.reset)
                    if (haustext.get('url_status') == ''):
                        print(mycolors.foreground.yellow + "Status: \t" + mycolors.reverse + "unknown" + mycolors.reset)
                else:
                    if (haustext.get('url_status') == 'online'):
                        print(mycolors.foreground.green + "Status: \t" + mycolors.reverse + haustext.get('url_status') + mycolors.reset)
                    if (haustext.get('url_status') == 'offline'):
                        print(mycolors.foreground.red + "Status: \t" + mycolors.reverse + haustext.get('url_status') + mycolors.reset)
                    if (haustext.get('url_status') == ''):
                        print(mycolors.foreground.cyan + "Status: \t" + mycolors.reverse + "unknown" + mycolors.reset)
            else:
                if (cv.bkg == 1):
                    print(mycolors.foreground.lightred + 'Status: ')
                else:
                    print(mycolors.foreground.red + 'Status: ')

            if 'host' in haustext:
                if haustext.get('host') is not None:
                    if (cv.bkg == 1):
                        print(mycolors.foreground.yellow + "Host: \t\t" + haustext.get('host'))
                    else:
                        print(mycolors.foreground.blue + "Host: \t\t" + haustext.get('host'))
                else:
                    if (cv.bkg == 1):
                        print(mycolors.foreground.yellow + 'Host: ')
                    else:
                        print(mycolors.foreground.blue + 'Host: ')

            if 'date_added' in haustext:
                if haustext.get('date_added') is not None:
                    if (cv.bkg == 1):
                        print(mycolors.foreground.pink + "Date Added: \t" + haustext.get('date_added'))
                    else:
                        print(mycolors.foreground.green + "Date Added: \t" + haustext.get('date_added'))
                else:
                    if (cv.bkg == 1):
                        print(mycolors.foreground.pink + 'Date Added: ')
                    else:
                        print(mycolors.foreground.green + 'Date Added: ')

            if 'threat' in haustext:
                if haustext.get('threat') is not None:
                    if (cv.bkg == 1):
                        print(mycolors.foreground.pink + "Threat: \t" + haustext.get('threat'))
                    else:
                        print(mycolors.foreground.green + "Threat: \t" + haustext.get('threat'))
                else:
                    if (cv.bkg == 1):
                        print(mycolors.foreground.pink + 'Threat: ')
                    else:
                        print(mycolors.foreground.green + 'Threat: ')

            if 'blacklists' in haustext:
                blacks = haustext.get('blacklists')
                if (cv.bkg == 1):
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
                if (cv.bkg == 1):
                    print(mycolors.foreground.lightred + "Google(gsb): \t")
                    print(mycolors.foreground.lightred + "Surbl: \t\t")
                    print(mycolors.foreground.lightred + "Spamhaus DBL:   ")
                else:
                    print(mycolors.foreground.red + "Google(gsb): \t")
                    print(mycolors.foreground.red + "Surbl: \t\t")
                    print(mycolors.foreground.red + "Spamhaus DBL:   ")

            if 'reporter' in haustext:
                if haustext.get('reporter') is not None:
                    if (cv.bkg == 1):
                        print(mycolors.foreground.lightcyan + "Reporter: \t" + haustext.get('reporter'))
                    else:
                        print(mycolors.foreground.blue + "Reporter: \t" + haustext.get('reporter'))
                else:
                    if (cv.bkg == 1):
                        print(mycolors.foreground.lightcyan + 'Reporter: ')
                    else:
                        print(mycolors.foreground.blue + 'Reporter: ')

            if 'larted' in haustext:
                if haustext.get('larted') is not None:
                    if (cv.bkg == 1):
                        print(mycolors.foreground.lightcyan + "Larted: \t" + haustext.get('larted'))
                    else:
                        print(mycolors.foreground.blue + "Larted: \t" + haustext.get('larted'))

                else:
                    if (cv.bkg == 1):
                        print(mycolors.foreground.lightcyan + "Larted: ")
                    else:
                        print(mycolors.foreground.blue + "Larted: ")

            if 'tags' in haustext:
                if (haustext.get('tags') is not None):
                    alltags = haustext.get('tags')
                    if (cv.bkg == 1):
                        print(mycolors.foreground.yellow + "Tags:\t\t", end='')
                    else:
                        print(mycolors.foreground.red + "Tags:\t\t", end='')
                    for i in alltags:
                        print(i, end=' ')
                else:
                    if (cv.bkg == 1):
                        print(mycolors.foreground.yellow + "Tags: ")
                    else:
                        print(mycolors.foreground.red + "Tags: ")
            else:
                if (cv.bkg == 1):
                    print(mycolors.foreground.yellow + "Tags: ")
                else:
                    print(mycolors.foreground.red + "Tags: ")

            if 'payloads' in haustext:
                if haustext.get('payloads') is not None:
                    allpayloads = haustext.get('payloads')
                    x = 0
                    z = 0
                    results = {}

                    if (cv.bkg == 1):
                        print(Fore.WHITE + "\n")
                    else:
                        print(Fore.BLACK + "\n")

                    for i in allpayloads:
                        x = x + 1
                        if (cv.bkg == 1):
                            print(mycolors.reset + "Payload_%d:\t" % x, end='')
                            print(mycolors.foreground.pink + "firstseen:%12s" % i['firstseen'], end='     ')
                            print(mycolors.foreground.yellow + "filename: %-30s" % i['filename'].ljust(40), end=' ' + "")
                            print(mycolors.foreground.lightred + "filetype: %s" % i['file_type'].ljust(10) + Fore.WHITE, end=' ' + "")
                            results = i['virustotal']
                            if (results) is not None:
                                print(mycolors.foreground.lightcyan + "VirusTotal: %s" % results['result'] + Fore.WHITE)
                            else:
                                print(mycolors.foreground.lightcyan + "VirusTotal: Not Found" + Fore.WHITE)
                        else:
                            print(mycolors.reset + "Payload_%d:\t" % x, end='')
                            print(mycolors.foreground.purple + "firstseen:%12s" % i['firstseen'], end='     ')
                            print(mycolors.foreground.green + "filename: %-30s" % i['filename'].ljust(40), end=' ' + "")
                            print(mycolors.foreground.red + "filetype: %s" % i['file_type'].ljust(10) + Fore.BLACK, end='' + "")
                            results = i['virustotal']
                            if (results) is not None:
                                print(mycolors.foreground.blue + "VirusTotal: %s" % results['result'] + Fore.BLACK)
                            else:
                                print(mycolors.foreground.blue + "VirusTotal: Not Found" + Fore.BLACK)

                    print(mycolors.reset + "\nSample Hashes")
                    print(13 * '-' + "\n")

                    for j in allpayloads:
                        z = z + 1
                        if (cv.bkg == 1):
                            print(mycolors.reset + "Payload_%d:\t" % z, end='')
                            print(mycolors.foreground.lightcyan + j['response_sha256'])
                        else:
                            print(mycolors.reset + "Payload_%d:\t" % z, end='')
                            print(mycolors.foreground.blue + j['response_sha256'])

            printr()

        except (BrokenPipeError, IOError, TypeError):
            print(mycolors.reset, file=sys.stderr)
            exit(1)
        except ValueError as e:
            print(e)
            if (cv.bkg == 1):
                print((mycolors.foreground.lightred + "Error while connecting to URLhaus!\n"))
            else:
                print((mycolors.foreground.red + "Error while connecting to URLhaus!\n"))
            printr()

    def haushashsearch(self, hashx):
        haus = URLHausExtractor.hausph

        if len(hashx) not in [32, 64]:
            return False

        haustext = ''
        hausresponse = ''
        params = ''

        try:
            print("\n")
            print((mycolors.reset + "URLHaus Report".center(126)), end='')
            print((mycolors.reset + "".center(28)), end='')
            print("\n" + (126 * '-').center(59))

            requestsession = requests.Session()
            requestsession.headers.update({'accept': 'application/json'})
            if ((len(hashx) == 32)):
                params = {"md5_hash": hashx}
            hausresponse = requestsession.post(haus, data=params)
            haustext = json.loads(hausresponse.text)

            if ((len(hashx) == 64)):
                params = {"sha256_hash": hashx}
            hausresponse = requests.post(haus, data=params)
            haustext = json.loads(hausresponse.text)

            if ((haustext.get('md5_hash') is None) and (haustext.get('sha256_hash') is None)):
                if (cv.bkg == 1):
                    print(mycolors.foreground.lightred + "Hash not found!\n" + mycolors.reset)
                else:
                    print(mycolors.foreground.red + "Hash not found!\n" + mycolors.reset)
                exit(1)

            if 'query_status' in haustext:
                if (cv.bkg == 1):
                    print(mycolors.foreground.lightcyan + "Is available?: \t" + haustext.get('query_status').upper())
                else:
                    print(mycolors.foreground.green + "Is available?: \t" + haustext.get('query_status').upper())
            else:
                if (cv.bkg == 1):
                    print(mycolors.foreground.lightcyan + 'Is availble?: Not available')
                else:
                    print(mycolors.foreground.green + 'Is available?: Not available')

            if 'md5_hash' in haustext:
                if haustext.get('md5_hash') is not None:
                    if (cv.bkg == 1):
                        print(mycolors.foreground.yellow + "MD5: \t\t" + haustext.get('md5_hash'))
                    else:
                        print(mycolors.foreground.blue + "MD5: \t\t" + haustext.get('md5_hash'))
                else:
                    if (cv.bkg == 1):
                        print(mycolors.foreground.yellow + 'MD5: ')
                    else:
                        print(mycolors.foreground.blue + 'MD5: ')

            if 'sha256_hash' in haustext:
                if haustext.get('md5_hash') is not None:
                    if (cv.bkg == 1):
                        print(mycolors.foreground.yellow + "SHA256:\t\t" + haustext.get('sha256_hash'))
                    else:
                        print(mycolors.foreground.blue + "SHA256:\t\t" + haustext.get('sha256_hash'))
                else:
                    if (cv.bkg == 1):
                        print(mycolors.foreground.yellow + 'SHA256: ')
                    else:
                        print(mycolors.foreground.blue + 'SHA256: ')

            if 'file_type' in haustext:
                if haustext.get('file_type') is not None:
                    if (cv.bkg == 1):
                        print(mycolors.foreground.pink + "File Type: \t" + haustext.get('file_type'))
                    else:
                        print(mycolors.foreground.purple + "File Type: \t" + haustext.get('file_type'))
                else:
                    if (cv.bkg == 1):
                        print(mycolors.foreground.pink + 'File Type: ')
                    else:
                        print(mycolors.foreground.purple + 'File Type: ')

            if 'file_size' in haustext:
                if haustext.get('file_size') is not None:
                    if (cv.bkg == 1):
                        print(mycolors.foreground.pink + "File Size: \t" + haustext.get('file_size') + " bytes")
                    else:
                        print(mycolors.foreground.purple + "File Size: \t" + haustext.get('file_size') + " bytes")
                else:
                    if (cv.bkg == 1):
                        print(mycolors.foreground.pink + 'File Size: ')
                    else:
                        print(mycolors.foreground.purple + 'File Size: ')

            if 'firstseen' in haustext:
                if haustext.get('firstseen') is not None:
                    if (cv.bkg == 1):
                        print(mycolors.foreground.lightcyan + "First Seen: \t" + haustext.get('firstseen'))
                    else:
                        print(mycolors.foreground.cyan + "First Seen: \t" + haustext.get('firstseen'))
                else:
                    if (cv.bkg == 1):
                        print(mycolors.foreground.lightcyan + 'First Seen: ')
                    else:
                        print(mycolors.foreground.cyan + 'First Seen: ')

            if 'lastseen' in haustext:
                if haustext.get('lastseen') is not None:
                    if (cv.bkg == 1):
                        print(mycolors.foreground.lightcyan + "Last Seen: \t" + haustext.get('lastseen'))
                    else:
                        print(mycolors.foreground.cyan + "Last Seen: \t" + haustext.get('lastseen'))
                else:
                    if (cv.bkg == 1):
                        print(mycolors.foreground.lightcyan + 'Last Seen: ')
                    else:
                        print(mycolors.foreground.cyan + 'Last Seen: ')

            if 'urlhaus_download' in haustext:
                if haustext.get('urlhaus_download') is not None:
                    if (cv.bkg == 1):
                        print(mycolors.foreground.lightred + "URL Download: \t" + haustext.get('urlhaus_download'))
                    else:
                        print(mycolors.foreground.red + "URL Download: \t" + haustext.get('urlhaus_download'))
                else:
                    if (cv.bkg == 1):
                        print(mycolors.foreground.lightred + 'URL Download: ')
                    else:
                        print(mycolors.foreground.red + 'URL Download: ')

            if 'virustotal' in haustext:
                if haustext.get('virustotal') is not None:
                    if (cv.bkg == 1):
                        print(mycolors.foreground.lightred + "Virus Total: \t" + haustext['virustotal'].get('result'))
                    else:
                        print(mycolors.foreground.red + "Virus Total: \t" + haustext['virustotal'].get('result'))
                else:
                    if (cv.bkg == 1):
                        print(mycolors.foreground.lightred + 'Virus Total: \tNot Found')
                    else:
                        print(mycolors.foreground.red + 'Virus Total: \tNot Found')

            if 'urls' in haustext:
                if (haustext.get('urls')) is not None:
                    if (cv.bkg == 1):
                        print(mycolors.reset + "\nStatus".center(9) + " Filename".ljust(36) + "  Location".ljust(23) + "Associated URL".ljust(20))
                        print("-" * 126 + "\n")
                    else:
                        print(mycolors.reset + "\nStatus".center(9) + " Filename".ljust(36) + "  Location".ljust(23) + "Associated URL".ljust(20))
                        print("-" * 126 + "\n")
                    allurls = haustext.get('urls')
                    for w in allurls:
                        if (cv.bkg == 1):
                            if (w['url_status'] == 'online'):
                                print(mycolors.foreground.lightcyan + mycolors.reverse + w['url_status'] + " " + mycolors.reset, end=' ')
                            if (w['url_status'] == 'offline'):
                                print(mycolors.foreground.lightred + mycolors.reverse + w['url_status'] + mycolors.reset, end=' ')
                            if (w['url_status'] == ''):
                                print(mycolors.foreground.yellow + mycolors.reverse + "unknown" + mycolors.reset, end=' ')
                            if w['filename'] is not None:
                                print(mycolors.foreground.pink + "%-36s" % w['filename'] + mycolors.reset, end=' ')
                            else:
                                print(mycolors.foreground.pink + "%-36s" % "Filename not reported!" + mycolors.reset, end=' ')
                            if (w['url'] is not None):
                                if (validators.url(w['url'])):
                                    print(mycolors.foreground.lightcyan + urltoip((w['url'])).ljust(20) + mycolors.reset, end=' ')
                                else:
                                    print(mycolors.foreground.lightcyan + "Not located".center(20) + mycolors.reset, end=' ')
                                print(mycolors.foreground.yellow + w['url'] + mycolors.reset)
                            else:
                                print(mycolors.foreground.lightcyan + "Not located".center(20) + mycolors.reset, end=' ')
                                print(mycolors.foreground.lightcyan + "URL not provided".center(20) + mycolors.reset, end=' ')

                        else:
                            if (w['url_status'] == 'online'):
                                print(mycolors.foreground.green + mycolors.reverse + w['url_status'] + " " + mycolors.reset, end=' ')
                            if (w['url_status'] == 'offline'):
                                print(mycolors.foreground.red + mycolors.reverse + w['url_status'] + mycolors.reset, end=' ')
                            if (w['url_status'] == ''):
                                print(mycolors.foreground.cyan + mycolors.reverse + "unknown" + mycolors.reset, end=' ')
                            if w['filename'] is not None:
                                print(mycolors.foreground.pink + "%-36s" % w['filename'] + mycolors.reset, end=' ')
                            else:
                                print(mycolors.foreground.pink + "%-36s" % "Filename not reported!" + mycolors.reset, end=' ')
                            if (w['url']):
                                if (validators.url(w['url'])):
                                    print(mycolors.foreground.green + (urltoip(w['url'])).ljust(20) + mycolors.reset, end=' ')
                                else:
                                    print(mycolors.foreground.green + "Not located".center(20) + mycolors.reset, end=' ')
                                print(mycolors.foreground.blue + w['url'] + mycolors.reset)
                            else:
                                print(mycolors.foreground.lightcyan + "Not located".center(20) + mycolors.reset, end=' ')
                                print(mycolors.foreground.lightcyan + "URL not provided".center(20) + mycolors.reset, end=' ')

            printr()

        except (BrokenPipeError, IOError, TypeError):
            print(mycolors.reset, file=sys.stderr)
            exit(1)

        except ValueError as e:
            print(e)
            if (cv.bkg == 1):
                print((mycolors.foreground.lightred + "Error while connecting to URLhaus!\n"))
            else:
                print((mycolors.foreground.lightred + "Error while connecting to URLhaus!\n"))
            printr()
